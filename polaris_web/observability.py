"""polaris_web/observability.py: what a running Polaris tells its operator.

Two surfaces, one purpose: an operator watching a deployment should be able to
see throughput, failures, and above all a duress signal, without attaching a
debugger and without a metrics backend this project does not ship.

**The log stream.** `structured_log(event, **fields)` writes one JSON object
per line to stdout. Every line carries `ts`, `pid`, `event`, `request_id`, and,
while an OpenTelemetry span is recording, `trace_id` and `span_id`, so a log
line and a trace join on the same request. Point stdout wherever the deployment
keeps logs; nothing here writes to disk or to the database.

Event names are namespaced by subject, so an operator can select a family:

    auth.failure            a password, WebAuthn or recovery-code attempt failed
                            (fields: kind, username)
    duress.signal           a holder's duress code matched during verification
                            (fields: individual_id, agency_id)
    quota.refused           an agency's issuance, revocation or verification
                            quota refused a write (fields: kind, agency_id)
    db.error                the database refused a statement; the message is
                            truncated and never echoed to the caller
                            (fields: detail)
    boot.session_policy     the per-role session and WebAuthn policy this
                            process started with
    boot.tracing_enabled    OpenTelemetry tracing is on (fields: service, endpoint)
    boot.tracing_unavailable  tracing was asked for and the packages are absent

The `boot.*` events are state announcements, emitted once at start; the others
are events, emitted as they happen.

**The counters.** Four in-process counters, thread-safe, no external
dependency, served as JSON at `/api/metrics` and, in Prometheus text format
with the per-route HTTP series, at `/metrics`:

    request_rate_per_minute     trailing five-minute average throughput
    error_rate_per_minute       trailing five-minute 5xx and uncaught exceptions
    auth_failures_per_minute    trailing five-minute failed authentications
    duress_events_total         monotonic count since this process started

`duress_events_total` is the load-bearing one. A duress code that raises a row
nobody reads makes the whole duress mechanism decorative, so this counter is
what the shipped `PolarisDuressEvent` alert fires on, immediately, at severity
one.

**One operational instruction.** Both metrics surfaces are unauthenticated, and
both carry the duress signal, so whoever can scrape them can observe that, and
roughly when, a duress alarm fired. Restrict `/metrics` and `/api/metrics` at
the edge to the monitoring network. The control is access to the surface, not
suppression of the metric: the operator's own monitoring is exactly the
audience that needs it in order to page. The access rule, and the Caddy matcher
that enforces it, are in `deploy/observability/README.md`.

Nothing here is auto-instrumented at import: every counter has an explicit call
site, because instrumentation an operator cannot see is instrumentation an
operator cannot switch off.
"""

from __future__ import annotations

import contextvars
import json
import os
import re
import sys
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Request-correlation id (v9.122).
#
# A single ephemeral id per HTTP request so an operator can match a structured
# log line to the response a caller saw. This is deliberately NOT a tracing
# system (no spans, no cross-service propagation, no backend) — it is one field
# stamped into the existing stdout JSON stream, consistent with the
# anti-architect constraints above. (v9.187 / P1.6: tracing.py adds the
# OPT-IN tracing layer on top; this id becomes the join key between the log
# stream and the trace — its own semantics are unchanged.)
#
# Vocation (anti-coercion): the id is per-request and ephemeral. It lives only
# in the contextvar below and the X-Request-ID response header. It is NEVER
# derived from identity and is NEVER written to a DB row — in particular not the
# append-only audit-of-record, where the C1 trigger would make it a permanent,
# reconstructable cross-request linkage key. That asymmetry (useful for live
# debugging in the moment, inert as a retention/aggregation vector) is the point.
#
# Accepted inbound ids are bounded to a safe charset and length so a hostile
# X-Request-ID cannot inject newlines/control bytes into logs or grow unbounded
# (the v9.83 "bound unbounded resources" posture). \A and \Z (not ^ / $) anchor
# the whole string, so a trailing-newline payload cannot slip through.
_REQUEST_ID_RE = re.compile(r"\A[A-Za-z0-9-]{8,64}\Z")
_request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "polaris_request_id", default="-"
)


def validate_or_new_request_id(raw) -> str:
    """Return ``raw`` only if it is a well-formed inbound id, else mint a fresh one.

    This is the ONLY function that is allowed to trust inbound bytes. A value is
    accepted only when it is a ``str`` matching ``\\A[A-Za-z0-9-]{8,64}\\Z``;
    anything else (None, wrong type, bad charset, too short/long, embedded
    control char) is dropped in favour of ``uuid4().hex`` (32 hex chars, a strict
    subset of the accepted charset).
    """
    if isinstance(raw, str) and _REQUEST_ID_RE.fullmatch(raw):
        return raw
    return uuid.uuid4().hex


def set_request_id(value: str) -> contextvars.Token:
    """Bind ``value`` as the current request id; returns the reset token."""
    return _request_id_var.set(value)


def get_request_id() -> str:
    """The current request id, or the sentinel ``'-'`` outside any request."""
    return _request_id_var.get()


def reset_request_id(token: contextvars.Token) -> None:
    """Clear the request id back to its prior value.

    Tolerates a token created in a different context or already spent (Flask can
    pop a shared-``g`` request context more than once, and a ``Token`` may only
    reset once): this must never crash teardown. As a backstop, drop the var
    back to the sentinel so a reset that could not be honoured still cannot leak
    the id into the next request a worker serves.
    """
    try:
        _request_id_var.reset(token)
    except (ValueError, LookupError, RuntimeError):
        _request_id_var.set("-")


# ---------------------------------------------------------------------------
# Trace-context hook (v9.187 / roadmap P1.6). tracing.py registers a callable
# returning {'trace_id': ..., 'span_id': ...} while a span is recording, or
# None. This module never imports opentelemetry (backend-free by charter);
# the hook is how structured_log joins the log stream to traces without a
# dependency. Default None = tracing off = logs exactly as before.
_trace_context_provider = None


def set_trace_context_provider(fn) -> None:
    """Install (or clear, with None) the trace-context callable."""
    global _trace_context_provider
    _trace_context_provider = fn


class Counter:
    """Thread-safe monotonically-increasing counter."""

    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()

    def inc(self, n: int = 1) -> None:
        with self._lock:
            self._value += n

    def value(self) -> int:
        with self._lock:
            return self._value


class RateWindow:
    """Per-minute rolling counter. Keeps the last `window_minutes`
    minutes of per-minute samples + returns the trailing rate.

    Cheap: O(window_minutes) per .rate() call. Default window = 5 min.
    """

    def __init__(self, window_minutes: int = 5):
        self._window_minutes = window_minutes
        self._samples = deque(maxlen=window_minutes)
        self._current_minute = self._minute_now()
        self._current_count = 0
        self._lock = threading.Lock()

    def inc(self, n: int = 1) -> None:
        with self._lock:
            now_min = self._minute_now()
            if now_min != self._current_minute:
                self._samples.append(self._current_count)
                gap = now_min - self._current_minute - 1
                for _ in range(min(gap, self._window_minutes)):
                    self._samples.append(0)
                self._current_minute = now_min
                self._current_count = n
            else:
                self._current_count += n

    def rate_per_minute(self) -> float:
        with self._lock:
            now_min = self._minute_now()
            sample_total = sum(self._samples)
            if now_min == self._current_minute:
                sample_total += self._current_count
            total_minutes = len(self._samples) + 1
            if total_minutes == 0:
                return 0.0
            return round(sample_total / total_minutes, 2)

    @staticmethod
    def _minute_now() -> int:
        return int(time.time() // 60)


@dataclass
class _Registry:
    requests: RateWindow = field(default_factory=lambda: RateWindow(5))
    errors: RateWindow = field(default_factory=lambda: RateWindow(5))
    auth_failures: RateWindow = field(default_factory=lambda: RateWindow(5))
    duress_events: Counter = field(default_factory=Counter)
    process_started_at: float = field(default_factory=time.time)
    process_id: int = field(default_factory=os.getpid)


_REGISTRY = _Registry()


def record_request() -> None:
    """Call from a Flask after_request hook. One inc per request."""
    _REGISTRY.requests.inc()


def record_error() -> None:
    """Call from a Flask errorhandler. One inc per 5xx / uncaught."""
    _REGISTRY.errors.inc()


def record_auth_failure(*, kind: str = "password", username: str = "") -> None:
    """Call from security.py:authenticate on a bad-credential path,
    AND from webauthn_auth on a failed assertion.

    `kind` is one of: 'password', 'webauthn', 'recovery_code'.
    """
    _REGISTRY.auth_failures.inc()
    structured_log("auth.failure", kind=kind, username=username)


def record_duress_event(*, individual_id: int = 0, agency_id: int = 0) -> None:
    """Call from app.py:duress handler. Increments the headline
    duress counter + emits a structured log line. The OPERATOR is
    expected to alert on this.

    Per the v9.27 Sanctum: this is the load-bearing anti-coercion
    observability primitive. If this never fires when it should,
    the duress-code mechanism (R11-5) is decorative.
    """
    _REGISTRY.duress_events.inc()
    structured_log("duress.signal",
                   individual_id=individual_id,
                   agency_id=agency_id)


def record_witness_disagreement(*, token_id: int = 0, single_ok: bool = False,
                                both_ok: bool = False) -> None:
    """Call from app.py:api_token_verify when continuous second-witness sampling
    (P1.18 item 5) finds the two-witness reference disagreeing with the single-
    witness result. It means the fast verify-at-use path can no longer be trusted
    to stand in for the reference, so it is a paging SEV: the Prometheus counter
    polaris_verify_witness_disagreements_total is the alerting surface, and this
    structured log at critical grain is the audit record."""
    structured_log("verify.witness_disagreement",
                   token_id=token_id,
                   single_ok=single_ok,
                   both_ok=both_ok,
                   severity="critical")


def structured_log(event: str, **fields) -> None:
    """Emit one JSON object per line to stdout.

    Format: `{"ts": "ISO8601", "pid": NNNN, "event": "...", ...fields}`.
    """
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "pid": _REGISTRY.process_id,
        "event": event,
        "request_id": get_request_id(),
    }
    # v9.187 (P1.6) — the log half of the correlation join: while a span is
    # recording, every log line carries the trace/span ids. The hook must
    # never break logging (tracing is an accessory, the log stream is not).
    if _trace_context_provider is not None:
        try:
            _ids = _trace_context_provider()
            if _ids:
                record.update(_ids)
        except Exception:
            pass
    record.update(fields)
    try:
        sys.stdout.write(json.dumps(record, default=str) + "\n")
        sys.stdout.flush()
    except (OSError, ValueError):
        # Refuse to crash the request path on logging failure.
        pass


@dataclass(frozen=True)
class MetricsSnapshot:
    """The structure returned by /api/metrics."""
    request_rate_per_minute: float
    error_rate_per_minute: float
    auth_failures_per_minute: float
    duress_events_total: int
    uptime_seconds: int
    process_id: int

    @classmethod
    def collect(cls) -> "MetricsSnapshot":
        return cls(
            request_rate_per_minute=_REGISTRY.requests.rate_per_minute(),
            error_rate_per_minute=_REGISTRY.errors.rate_per_minute(),
            auth_failures_per_minute=_REGISTRY.auth_failures.rate_per_minute(),
            duress_events_total=_REGISTRY.duress_events.value(),
            uptime_seconds=int(time.time() - _REGISTRY.process_started_at),
            process_id=_REGISTRY.process_id,
        )

    def to_dict(self) -> dict:
        return {
            "request_rate_per_minute": self.request_rate_per_minute,
            "error_rate_per_minute": self.error_rate_per_minute,
            "auth_failures_per_minute": self.auth_failures_per_minute,
            "duress_events_total": self.duress_events_total,
            "uptime_seconds": self.uptime_seconds,
            "process_id": self.process_id,
        }

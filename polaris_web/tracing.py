# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_web/tracing.py — opt-in OpenTelemetry distributed tracing (v9.187 / roadmap P1.6).

The v9.27 anti-architect constraint ("no tracing system") held while Polaris
had no operators; P1.6 supersedes it for deployments that need cross-request
latency attribution, WITHOUT surrendering the constraints that made the
original refusal right:

1. **Opt-in and visible.** Tracing is OFF unless `POLARIS_OTEL` is truthy.
   When it turns on, a `tracing_enabled` structured-log line says so at
   startup — hidden instrumentation is itself a coercion risk (a coerced
   operator cannot disable what they cannot see), so the switch is one
   documented env var, not an import-time side effect. The request hooks
   below are registered at import (Flask 3 forbids adding them later) but
   are inert no-ops until the operator's switch activates a provider.

2. **Nothing identity-derived, nothing persisted.** The server span is
   HAND-ROLLED in this module (no Flask auto-instrumentation), so what it
   carries is exactly what is written here: the route TEMPLATE as the span
   name (an unmatched path collapses to `UNMATCHED`, mirroring the v9.130
   metrics-cardinality rule), the query-stripped path in `http.target`
   (filters and cursors do not belong in telemetry), and the ephemeral
   per-request correlation id (`polaris.request_id`, v9.122 semantics:
   minted per request, never written to a DB row). DB spans come from the
   psycopg2 instrumentation, which records the parameterized statement
   TEMPLATE only (`%s` placeholders, never values). Exceptions mark the span
   status ERROR by exception CLASS name only — no message, no stack (a
   psycopg2 error message embeds host/db details; a ValueError can embed
   user input). Trace ids live in the operator's tracing backend under the
   operator's retention, exactly like the stdout logs they join.

3. **The correlation id is the join key.** The request span carries
   `polaris.request_id`, and `observability.structured_log` lines carry
   `trace_id`/`span_id` while a span is recording (via the provider hook
   this module registers). So: a log line finds its trace, a trace finds its
   log lines, and the X-Request-ID a caller quotes finds both. An inbound
   `traceparent` header is honoured only behind a trusted proxy
   (`POLARIS_TRUST_PROXY`), symmetric with X-Request-ID: an untrusted client
   does not get to choose how its requests correlate.

Dependencies are optional at runtime exactly like prometheus_client in
app.py: if the opentelemetry packages are missing, the app serves normally
and `POLARIS_OTEL=1` logs `tracing_unavailable` instead of crashing.

Configuration (all env):
    POLARIS_OTEL=1                  turn tracing on (default: off)
    OTEL_EXPORTER_OTLP_ENDPOINT     collector base URL (default
                                    http://localhost:4318; the exporter POSTs
                                    OTLP/HTTP to <base>/v1/traces)
    OTEL_TRACES_SAMPLER[_ARG]       standard OTel sampling knobs (the SDK
                                    reads them itself; default: always on,
                                    parent-based)
    OTEL_SERVICE_NAME               override the `polaris-web` service name
    POLARIS_OTEL_EXCLUDE            comma list of path prefixes NOT to trace
                                    (default: the 5s health probes
                                    /api/health/live,/api/health/ready)

gunicorn note: workers import the app AFTER fork (no preload), so each worker
builds its own TracerProvider + BatchSpanProcessor; there is no
fork-inherits-a-dead-exporter-thread hazard here.
"""

from __future__ import annotations

import os

from flask import g, request

import observability
from __version__ import POLARIS_VERSION

try:
    from opentelemetry import context as _otel_context
    from opentelemetry import trace as _otel_trace
    from opentelemetry.propagate import extract as _otel_extract
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
    from opentelemetry.trace import SpanKind, StatusCode
    _OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover — exercised via the disabled-path tests
    _OTEL_AVAILABLE = False

_TRUTHY = ('1', 'true', 'yes')

# The live tracing state: None while tracing is off. Holds the provider and
# tracer so shutdown() can undo activate() (the suites cycle this; production
# activates once per worker at import and never looks back).
_ACTIVE: dict | None = None


def is_enabled() -> bool:
    """The operator's switch: POLARIS_OTEL truthy. One knob, documented."""
    return os.environ.get('POLARIS_OTEL', '').strip().lower() in _TRUTHY


def _excluded_prefixes() -> tuple:
    raw = os.environ.get('POLARIS_OTEL_EXCLUDE',
                         '/api/health/live,/api/health/ready')
    return tuple(p.strip() for p in raw.split(',') if p.strip())


def current_trace_ids():
    """The active span's ids as hex, or None when no span is recording.

    Registered into observability.set_trace_context_provider at activation so
    every structured_log line emitted inside a traced request carries
    trace_id/span_id — the log half of the P1.6 correlation join.
    """
    if _ACTIVE is None:
        return None
    span = _otel_trace.get_current_span()
    ctx = span.get_span_context()
    if not span.is_recording() or not ctx.is_valid:
        return None
    return {
        'trace_id': format(ctx.trace_id, '032x'),
        'span_id': format(ctx.span_id, '016x'),
    }


# ---------------------------------------------------------------------------
# The request hooks. Registered at import via init_app (inert while _ACTIVE
# is None); ordering matters and is guaranteed by registration order in
# app.py: the v9.122 correlation hook registers first, so the request id is
# bound before the span opens and can be stamped immediately.
# ---------------------------------------------------------------------------

def _trace_before_request():
    if _ACTIVE is None:
        return
    path = request.path
    if any(path.startswith(p) for p in _ACTIVE['exclude']):
        return
    # Span name: the route TEMPLATE, never the raw path — same bounded-
    # cardinality rule the /metrics labels follow (an unmatched path is one
    # bucket, not one name per probe string).
    rule = request.url_rule.rule if request.url_rule else 'UNMATCHED'
    # Inbound trace context (traceparent) only from a trusted proxy —
    # symmetric with X-Request-ID / X-Forwarded-For.
    parent = None
    if os.environ.get('POLARIS_TRUST_PROXY', '').lower() in _TRUTHY:
        # Werkzeug title-cases header keys; the W3C propagator looks up
        # lowercase 'traceparent' — normalize or the extract silently misses.
        parent = _otel_extract({k.lower(): v for k, v in request.headers.items()})
    span = _ACTIVE['tracer'].start_span(
        f'{request.method} {rule}',
        context=parent,
        kind=SpanKind.SERVER,
        attributes={
            'http.method': request.method,
            'http.route': rule,
            'http.target': path,  # path only — the query string never leaves
            'http.host': request.host,
            'polaris.request_id': observability.get_request_id(),
        },
    )
    token = _otel_context.attach(_otel_trace.set_span_in_context(span))
    g._otel_span = span
    g._otel_token = token


def _trace_after_request(response):
    span = getattr(g, '_otel_span', None)
    if span is not None and span.is_recording():
        span.set_attribute('http.status_code', response.status_code)
        if response.status_code >= 500:
            span.set_status(StatusCode.ERROR)
    return response


def _trace_teardown_request(exc):
    # Always runs, even on exceptions — the span must end and the context
    # token must detach, or the trace context leaks into the next request
    # this worker serves (same discipline as the correlation teardown).
    span = getattr(g, '_otel_span', None)
    token = getattr(g, '_otel_token', None)
    if span is None:
        return
    g._otel_span = None
    g._otel_token = None
    try:
        if exc is not None and span.is_recording():
            # Class name only: exception MESSAGES can carry user input or
            # connection details, and stacks belong in the operator's logs.
            span.set_status(StatusCode.ERROR, type(exc).__name__)
            span.set_attribute('polaris.exception_type', type(exc).__name__)
        span.end()
    finally:
        if token is not None:
            try:
                _otel_context.detach(token)
            except Exception:
                pass


def init_app(app) -> bool:
    """Register the (inert) request hooks and activate tracing if opted in.

    Called once from app.py at import time — BEFORE the first request, which
    is the only moment Flask 3 accepts new hooks. Returns True when tracing
    is live.
    """
    if not app.config.get('POLARIS_TRACING_HOOKS_REGISTERED'):
        app.before_request(_trace_before_request)
        app.after_request(_trace_after_request)
        app.teardown_request(_trace_teardown_request)
        app.config['POLARIS_TRACING_HOOKS_REGISTERED'] = True
    if not is_enabled():
        return False
    return activate()


def activate(span_processor=None) -> bool:
    """Build the provider and turn the hooks live. Returns True when on.

    `span_processor` is a test seam (an in-memory or simple processor); the
    suites call this directly to exercise the wiring without touching process
    env. Production reaches here only through init_app's POLARIS_OTEL gate.
    """
    global _ACTIVE
    if _ACTIVE is not None:
        return True
    if not _OTEL_AVAILABLE:
        # The operator asked for tracing and cannot have it: SAY SO (a silent
        # no-op here would be the invisible-telemetry failure mode inverted —
        # the operator believes they have traces and they do not).
        observability.structured_log(
            'boot.tracing_unavailable',
            reason='opentelemetry packages not installed (see requirements.txt)',
        )
        return False

    resource = Resource.create({
        'service.name': os.environ.get('OTEL_SERVICE_NAME', 'polaris-web'),
        'service.version': POLARIS_VERSION,
    })
    provider = TracerProvider(resource=resource)
    if span_processor is None:
        # OTLPSpanExporter reads OTEL_EXPORTER_OTLP_ENDPOINT itself and POSTs
        # protobuf to <endpoint>/v1/traces. Batch, not simple: export must
        # never sit on the request path.
        span_processor = BatchSpanProcessor(OTLPSpanExporter())
    provider.add_span_processor(span_processor)

    # DB spans: the psycopg2 instrumentation wraps connect() and records the
    # parameterized statement template only (never values). Explicit
    # provider, no global mutation — a test provider cannot leak elsewhere.
    Psycopg2Instrumentor().instrument(tracer_provider=provider,
                                      skip_dep_check=True)  # psycopg2-binary

    observability.set_trace_context_provider(current_trace_ids)
    _ACTIVE = {
        'provider': provider,
        'tracer': provider.get_tracer('polaris_web.tracing', POLARIS_VERSION),
        'exclude': _excluded_prefixes(),
    }
    observability.structured_log(
        'boot.tracing_enabled',
        service=resource.attributes.get('service.name', 'polaris-web'),
        endpoint=os.environ.get('OTEL_EXPORTER_OTLP_ENDPOINT',
                                'http://localhost:4318'),
    )
    return True


def force_flush(timeout_millis: int = 10000) -> None:
    """Flush pending spans (the drill and the suites call this; prod relies on
    the batch processor's own schedule + atexit shutdown)."""
    if _ACTIVE is not None:
        _ACTIVE['provider'].force_flush(timeout_millis)


def shutdown() -> None:
    """Undo activate: uninstrument the DB, drop the log join, stop the provider.
    The request hooks stay registered (Flask cannot unregister them) and fall
    back to their inert no-op path."""
    global _ACTIVE
    if _ACTIVE is None:
        return
    provider = _ACTIVE['provider']
    _ACTIVE = None
    observability.set_trace_context_provider(None)
    try:
        Psycopg2Instrumentor().uninstrument()
    except Exception:
        pass
    provider.shutdown()

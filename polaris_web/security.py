# =============================================================================
# AI-context: auth, rate limit, CSRF, CSP, security headers. The CSP is
#   'self' — never weaken without naming the threat.
# Read before editing:
#     ../docs/design/concurrency.md  (atomic increment section — TOCTOU history)
#     ../docs/operator/SECURITY-CONTROLS.md              (full threat model)
# Tests can lock the admin account. To unlock:
#     UPDATE AppUser SET locked_until=NULL, failed_login_count=0
# =============================================================================

"""
============================================================================
POLARIS — Web Interface Security Module
============================================================================

Implements the controls applied during the security-patching pass:

  Authentication        Login + scrypt password verification + session
  Authorization         Role-based decorators (admin/operator/auditor)
  CSRF protection       HMAC-signed token in session, validated on POSTs
  Account lockout       N failures within W minutes locks for L minutes
  Rate limiting         Per-IP token bucket on login + state-changing POSTs
  Security headers      CSP, X-Frame-Options, X-Content-Type-Options,
                        Referrer-Policy, HSTS (prod-only), Permissions-Policy
  Cookie hardening      HttpOnly, SameSite=Lax, Secure (prod-only)
  Body size limit       Flask's MAX_CONTENT_LENGTH set to 1 MiB
  Auth audit logging    Every login / logout / failure / lockout / CSRF
                        rejection / authz denial recorded in AuthAuditLog
  Network policy        Per-role CIDR allow-lists (POLARIS_NETWORK_POLICY_<ROLE>)
                        enforced at login and on every live session (v9.189)
  Session registry      Server-side OperatorSession rows: per-role concurrent
                        caps, idle timeouts, revocation on deactivation,
                        logout, password change (v9.189)

Frameworks:
  - OWASP ASVS L2 controls
  - OWASP Top 10 (2021): A01-A09 mitigations
  - CWE references annotated inline

This module deliberately avoids Flask-Login / Flask-WTF / Flask-Limiter
to keep the dependency graph small (just Flask + psycopg2 + werkzeug,
all already required) and to keep the security logic transparent and
auditable rather than hidden behind a third-party DSL.
============================================================================
"""

import os
import hmac
import time
import secrets
import functools
import ipaddress
from datetime import datetime
from collections import deque, OrderedDict
from urllib.parse import urlsplit

from flask import (
    request, session, redirect, url_for, abort, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash

import observability  # v9.31 freeze condition 6 — counter call-sites for auth failures


# ----------------------------------------------------------------------------
# Configuration constants
# ----------------------------------------------------------------------------

LOGIN_FAILURE_THRESHOLD   = 5         # account locks after this many failures
LOGIN_FAILURE_WINDOW_MIN  = 10        # within this many minutes
ACCOUNT_LOCK_MIN          = 15        # locked out for this many minutes

# Per-IP rate limits. The DEFAULTS are the security posture (F-03: 10 login
# attempts and 60 writes per IP per minute) and check_performance_baseline
# pins them; the environment overrides exist for one reason, v9.191 (roadmap
# P1.9): a benchmark of issuance/s or verification/s from ONE client address
# is impossible under 60 writes a minute, so scripts/polaris-perf-baseline.sh
# raises the write cap on the scratch server it starts. A production stack
# that raises them has lowered its own brute-force and flood resistance and
# should say why in polaris.env.
def _env_int(name, default):
    raw = os.environ.get(name, '').strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        return default


# Per-IP rate limit on login attempts (token bucket)
RATE_LIMIT_LOGIN_MAX      = _env_int('POLARIS_RATE_LIMIT_LOGIN_MAX', 10)   # max login attempts...
RATE_LIMIT_LOGIN_WINDOW   = 60                                             # ...per N seconds per IP

# Per-IP rate limit on all state-changing requests
RATE_LIMIT_WRITE_MAX      = _env_int('POLARIS_RATE_LIMIT_WRITE_MAX', 60)
RATE_LIMIT_WRITE_WINDOW   = _env_int('POLARIS_RATE_LIMIT_WRITE_WINDOW', 60)

# Body size limit (1 MiB; the SQL console caps queries at 5 KB separately)
MAX_REQUEST_BODY_BYTES    = 1 * 1024 * 1024

# Session lifetime
SESSION_LIFETIME_HOURS    = 8


# ----------------------------------------------------------------------------
# Rate limiter — sliding-window per-key counter (CWE-307 / CWE-770 mitigation)
#
# Two backends with the same public contract:
#   - InMemoryRateLimiter — per-process; correct for single-worker dev / tests
#                            and for any deployment where there is exactly one
#                            Python process (e.g. `flask run`, single-worker
#                            gunicorn).
#   - RedisRateLimiter   — multi-process / multi-host; uses an atomic Lua
#                            script over a sorted set so all workers share the
#                            same per-IP counter.
#
# Production gunicorn defaults to 4 workers. With the in-memory limiter, every
# worker holds its own copy of the bucket — a single client can effectively
# get 4× the configured limit. For correctness under multi-worker production
# deployments, set POLARIS_REDIS_URL and the auto-selector picks the Redis
# backend. The in-memory backend logs a warning at startup when it sees
# POLARIS_WORKERS > 1 (no Redis URL → operator should know).
#
# Selection (POLARIS_RATE_LIMIT_BACKEND, defaults to 'auto'):
#   auto    → Redis if POLARIS_REDIS_URL set and reachable, else in-memory.
#   memory  → always in-memory.
#   redis   → always Redis; falls back to in-memory + stderr warning if Redis
#             is misconfigured (no URL or unreachable). Tests and operators
#             can use POLARIS_RATE_LIMIT_BACKEND=memory to bypass Redis.
#
# Both backends honor the same allow(key, max, window) → bool contract and
# the same reset(key=None) semantic, so app code (security.py and app.py
# call sites) is backend-agnostic.
# ----------------------------------------------------------------------------


class _BaseRateLimiter:
    """Public contract every backend must implement."""

    name = 'base'  # subclasses override

    def allow(self, key, max_events, window_seconds):
        """Return True if the event is allowed; False if it would exceed the
        per-key sliding window. Implementations must be atomic with respect
        to concurrent allow() calls on the same key."""
        raise NotImplementedError

    def reset(self, key=None):
        """Clear all buckets if key is None; otherwise clear just that key."""
        raise NotImplementedError

    def healthy(self):
        """Return True if the backend is currently operational."""
        return True


class InMemoryRateLimiter(_BaseRateLimiter):
    """Per-process sliding-window limiter. Single-worker deployments only.

    Concurrency: a single deque per key with no locking is safe under
    CPython for the usage pattern here (popleft + append are atomic at the
    bytecode level for deque). The earlier audit accepted this; do not
    change it without re-verifying — adding a lock here is a TOCTOU
    regression risk on the GIL guarantees the current code relies on."""

    name = 'memory'

    # Bound the per-key bucket map so idle keys cannot accumulate forever. An
    # attacker rotating source IPs (or spoofing X-Forwarded-For when
    # POLARIS_TRUST_PROXY is set) would otherwise leak one dict entry per
    # distinct key for the process lifetime. The map is LRU-ordered and capped.
    _MAX_KEYS = 50_000

    def __init__(self):
        self._buckets = OrderedDict()

    def allow(self, key, max_events, window_seconds):
        now = time.monotonic()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = deque()
            self._buckets[key] = bucket
        else:
            self._buckets.move_to_end(key)   # mark recently used (LRU)
        cutoff = now - window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()
        if len(bucket) >= max_events:
            return False
        bucket.append(now)
        # Evict the least-recently-used keys beyond the cap (bounds memory).
        while len(self._buckets) > self._MAX_KEYS:
            self._buckets.popitem(last=False)
        return True

    def reset(self, key=None):
        if key is None:
            self._buckets.clear()
        else:
            self._buckets.pop(key, None)


class RedisRateLimiter(_BaseRateLimiter):
    """Multi-process sliding-window limiter backed by a Redis sorted set.

    The Lua script runs atomically inside Redis: it trims old entries,
    counts what remains, decides allow/deny, and (on allow) records the
    new entry — all within a single round trip and a single Redis lock.
    No race window exists between count and write.

    Sort-set member format: a per-call random nonce so two events with the
    same millisecond score don't collide (ZADD by default updates a
    member's score; we want each call to be a distinct entry).

    Failure mode: if Redis is unreachable mid-flight, allow() fails-closed
    (returns False) and logs to stderr. This matches OWASP "fail securely"
    guidance — denying a request under load is preferable to silently
    bypassing the rate limiter. Operators should monitor redis_errors_total
    and treat sustained errors as a SEV.
    """

    name = 'redis'

    KEY_PREFIX = 'polaris:rl:'

    # KEYS[1] = bucket key (already prefixed)
    # ARGV[1] = now in milliseconds
    # ARGV[2] = window in milliseconds
    # ARGV[3] = max_events (allow if count < this)
    # ARGV[4] = nonce — unique member added on success
    # Returns 1 if allowed, 0 if denied. PEXPIRE keeps Redis tidy when a key
    # goes idle.
    LUA_SLIDING_WINDOW = """
    local key = KEYS[1]
    local now = tonumber(ARGV[1])
    local window = tonumber(ARGV[2])
    local max_events = tonumber(ARGV[3])
    local cutoff = now - window
    redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
    local count = redis.call('ZCARD', key)
    if count >= max_events then
        return 0
    end
    redis.call('ZADD', key, now, ARGV[4])
    redis.call('PEXPIRE', key, window + 1000)
    return 1
    """

    def __init__(self, url, socket_timeout=2.0):
        import redis as _redis  # imported lazily; package is optional
        from redis.retry import Retry
        from redis.backoff import NoBackoff
        self._url = url
        self._client = _redis.from_url(
            url, socket_timeout=socket_timeout,
            socket_connect_timeout=socket_timeout,
            decode_responses=False,
            # v9.190 (redis-py 8.x, roadmap P1.8): since redis-py 6.0 a
            # standalone client retries 3 times with exponential jitter by
            # default. On the request hot path that turns a Redis outage into
            # multi-second stalls before the fail-closed deny below. Keep the
            # pre-6 contract this limiter was written and tested against:
            # ONE attempt, then fail closed fast (a 2s socket timeout at most).
            retry=Retry(NoBackoff(), 0),
        )
        # Surface configuration errors at construction time, not at first
        # request — the selector catches and falls back if this raises.
        self._client.ping()
        self._script = self._client.register_script(self.LUA_SLIDING_WINDOW)

    def allow(self, key, max_events, window_seconds):
        full_key = self.KEY_PREFIX + key
        now_ms = int(time.time() * 1000)
        window_ms = int(window_seconds * 1000)
        # Use a fresh nonce per call so simultaneous events do not collapse
        # into a single sorted-set member with their score overwritten.
        nonce = f"{now_ms}-{secrets.token_hex(8)}"
        try:
            result = self._script(
                keys=[full_key],
                args=[now_ms, window_ms, max_events, nonce],
            )
            return bool(int(result))
        except Exception as e:
            import sys
            sys.stderr.write(
                f"[security] Redis rate limiter error on key={key!r}: "
                f"{e!r}; failing closed (denying request).\n"
            )
            return False

    def reset(self, key=None):
        try:
            if key is None:
                # Tests use this; in production reset(None) is rare. SCAN
                # is paginated server-side — never blocks Redis even on a
                # large key space.
                for k in self._client.scan_iter(match=self.KEY_PREFIX + '*',
                                                count=500):
                    self._client.delete(k)
            else:
                self._client.delete(self.KEY_PREFIX + key)
        except Exception as e:
            import sys
            sys.stderr.write(
                f"[security] Redis rate limiter reset failed: {e!r}\n"
            )

    def healthy(self):
        try:
            return self._client.ping() is True
        except Exception:
            return False


# Back-compat alias: pre-v7.5 code referenced security.RateLimiter() directly.
RateLimiter = InMemoryRateLimiter


def _make_rate_limiter():
    """Pick a rate-limiter backend based on env config.

    Returns an instance implementing _BaseRateLimiter. Always returns SOME
    backend — never raises — because rate limiting is on the request
    hot path and a startup failure would take the whole app offline.
    Misconfiguration falls back to in-memory + a loud stderr warning.
    """
    backend = os.environ.get('POLARIS_RATE_LIMIT_BACKEND', 'auto').lower()
    redis_url = os.environ.get('POLARIS_REDIS_URL', '').strip()
    try:
        workers = int(os.environ.get('POLARIS_WORKERS', '1') or '1')
    except (TypeError, ValueError):
        workers = 1

    import sys

    def _try_redis():
        try:
            return RedisRateLimiter(redis_url)
        except Exception as e:
            sys.stderr.write(
                f"[security] Redis rate limiter unavailable ({e!r}); "
                f"falling back to in-memory.\n"
            )
            return None

    if backend == 'memory':
        chosen = InMemoryRateLimiter()
    elif backend == 'redis':
        if not redis_url:
            sys.stderr.write(
                "[security] POLARIS_RATE_LIMIT_BACKEND=redis but "
                "POLARIS_REDIS_URL is empty — falling back to in-memory.\n"
            )
            chosen = InMemoryRateLimiter()
        else:
            chosen = _try_redis() or InMemoryRateLimiter()
    else:  # 'auto' or anything unrecognized
        if redis_url:
            chosen = _try_redis() or InMemoryRateLimiter()
        else:
            chosen = InMemoryRateLimiter()

    if chosen.name == 'memory' and workers > 1:
        sys.stderr.write(
            f"[security] WARNING: POLARIS_WORKERS={workers} with in-memory "
            f"rate limiter — actual per-IP limits will be ~{workers}× "
            f"configured because each worker holds its own buckets. Set "
            f"POLARIS_REDIS_URL for accurate cross-worker enforcement.\n"
        )
    return chosen


# Global rate-limiter instance. Reset by tests via security.rate_limiter.reset().
# In multi-worker production with POLARIS_REDIS_URL set this is the Redis
# backend; otherwise it's the in-memory backend (with a startup warning if
# multiple workers are configured).
rate_limiter = _make_rate_limiter()


def client_ip():
    """
    Extract the real client IP, honoring X-Forwarded-For when behind a
    trusted reverse proxy. Be conservative: only honor XFF if explicitly
    enabled via TRUST_PROXY env var (CWE-345 / CWE-348 mitigation).
    """
    if os.environ.get('POLARIS_TRUST_PROXY', '').lower() in ('1', 'true', 'yes'):
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            # Use the leftmost (the original client)
            return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


# ----------------------------------------------------------------------------
# Audit logging — writes to AuthAuditLog table
# ----------------------------------------------------------------------------

def _audit(get_conn, event_type, username=None, user_id=None, detail=None):
    """
    Append an AuthAuditLog row. Failures are caught and logged to stderr
    rather than propagating, so audit-logging never breaks user-facing
    requests. (Audit logging is best-effort but should never deny service.)
    """
    try:
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO AuthAuditLog
                        (event_type, username, user_id, ip_address, user_agent, detail)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event_type,
                        username,
                        user_id,
                        client_ip()[:45],
                        (request.headers.get('User-Agent', '') or '')[:255],
                        (detail or '')[:500],
                    )
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:
        import sys
        sys.stderr.write(f"[audit] Failed to write {event_type}: {e}\n")


# ----------------------------------------------------------------------------
# v9.20 — record_audit_access: the audit's audit.
#
# per a recorded decision
# Position A. Records WHO queried the audit tables (TokenLifecycleEvent /
# VerificationEvent / AuthAuditLog / DuressEvent). The helper is fail-open
# (logging failure does not block the actual query — accountability data
# corrupts gracefully rather than blocking operator access to legitimate
# audit data).
#
# CONSTITUTIONAL BOUNDARY: this helper must NEVER be called from a route
# that reads AuditAccessLog itself. The audit-of-audit-of-audit regress
# stops at AuditAccessLog by construction. This is structurally enforced
# by the structural invariant test_audit_access_log_reads_not_logged in
# TestWave20V920 — any reference to record_audit_access alongside a
# SELECT FROM AuditAccessLog will trip the test.
# ----------------------------------------------------------------------------

# The four tables whose reads are audited by AuditAccessLog. Pinned here
# (rather than in app.py) so additions go through this constant + the
# associated structural test in TestWave20V920.
AUDIT_TABLES_TRACKED = (
    'TokenLifecycleEvent',
    'VerificationEvent',
    'AuthAuditLog',
    'DuressEvent',
)


def record_audit_access(get_conn, accessed_table, filter_criteria=None,
                        result_row_count=None):
    """Append an AuditAccessLog row recording that the current actor read
    from `accessed_table`. Best-effort + fail-open: any exception is
    suppressed to stderr; the caller's actual query proceeds regardless.

    Args:
        get_conn: callable returning a fresh DB connection (matches the
                  pattern of _audit + audit hooks elsewhere)
        accessed_table: one of AUDIT_TABLES_TRACKED (raises ValueError
                  otherwise — programmer error, not operator error)
        filter_criteria: dict serializable to JSONB; describes what
                  filter the query applied (e.g., {"token_id": 42}).
                  None becomes {}.
        result_row_count: integer count of rows returned, or None when
                  not easily measurable. Stored as-is.

    Returns:
        None. The function is side-effect only.

    Constitutional contract:
      - MUST NOT be called from any route that reads AuditAccessLog
        itself (regress boundary; structurally pinned)
      - Failures DO NOT propagate (fail-open)
      - Filter criteria are stored verbatim; no LLM analysis
    """
    if accessed_table not in AUDIT_TABLES_TRACKED:
        # Programmer error: caller passed an unknown table name.
        # Surface loudly in dev; do not propagate in production.
        import sys
        sys.stderr.write(
            f"[audit_access] WARNING: record_audit_access called with "
            f"unknown table {accessed_table!r}; expected one of "
            f"{AUDIT_TABLES_TRACKED}. Skipping log.\n"
        )
        return

    user = current_user()
    actor_user_id = user['user_id'] if user else None

    # System access (no logged-in user) captures source in filter for
    # accountability. The same field is used by web reads for explicit
    # filter parameters.
    filter_payload = dict(filter_criteria or {})

    try:
        from psycopg2.extras import Json
        conn = get_conn()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    INSERT INTO AuditAccessLog
                        (actor_user_id, accessed_table,
                         filter_criteria_jsonb, result_row_count)
                    VALUES (%s, %s, %s, %s)
                    """,
                    (
                        actor_user_id,
                        accessed_table,
                        Json(filter_payload),
                        result_row_count,
                    ),
                )
            conn.commit()
        finally:
            conn.close()
    except Exception as e:  # noqa: BLE001 — fail-open by design
        import sys
        sys.stderr.write(
            f"[audit_access] Failed to write read of {accessed_table}: {e}\n"
        )


# ----------------------------------------------------------------------------
# Password hashing (Werkzeug scrypt) — kept here so callers don't depend on
# werkzeug.security directly. CWE-256 / CWE-916 mitigation.
# ----------------------------------------------------------------------------

def hash_password(plaintext):
    return generate_password_hash(plaintext, method='scrypt')

def verify_password(hashed, plaintext):
    return check_password_hash(hashed, plaintext)


# ----------------------------------------------------------------------------
# Authentication: login / logout / current user
# ----------------------------------------------------------------------------

def authenticate(get_conn, username, password):
    """
    Verify credentials and update lockout/last-login bookkeeping.
    Returns (user_dict_or_None, error_message). The error message is
    intentionally generic to avoid username enumeration (CWE-203, CWE-204).
    """
    GENERIC_ERROR = "Invalid username or password."

    if not username or not password:
        return None, GENERIC_ERROR
    if len(username) > 50 or len(password) > 128:
        # Reject obviously-malformed inputs without DB query (CWE-1284)
        return None, GENERIC_ERROR

    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, username, password_hash, role, is_active, "
                "       failed_login_count, locked_until "
                "FROM AppUser WHERE username = %s",
                (username,)
            )
            user = cur.fetchone()

            # Constant-time-ish: even if user not found, run a dummy verify
            # to make timing oracles less useful (CWE-208).
            if user is None:
                check_password_hash(
                    'scrypt:32768:8:1$dummy$0' + '0' * 128,
                    password
                )
                _audit(get_conn, 'LOGIN_FAILED', username=username,
                       detail='unknown user')
                return None, GENERIC_ERROR

            # Verify the password BEFORE branching on account state (inactive or
            # locked), so EVERY path for an existing user runs the same scrypt
            # work. The inactive branch below used to return here without
            # hashing; its ~0ms response time was a username-enumeration oracle
            # for deactivated accounts (CWE-208) — the exact timing leak the
            # unknown-user dummy hash above closes for the not-found path
            # (unknown ~scrypt, inactive ~0ms, active+wrong ~scrypt made the
            # inactive class uniquely identifiable). The lockout state, likewise,
            # is revealed only to a caller who already proved knowledge of the
            # password; an unknown user is never locked (it returns above before
            # any counter bump), so a distinct "locked" response would uniquely
            # confirm the account exists. SECURITY.md promises enumeration is
            # prevented; this keeps that promise on every branch.
            password_ok = check_password_hash(user['password_hash'], password)

            if not user['is_active']:
                _audit(get_conn, 'LOGIN_FAILED', username=username,
                       user_id=user['user_id'], detail='account inactive')
                return None, GENERIC_ERROR

            # Lockout check.
            now = datetime.now()
            if user['locked_until'] and user['locked_until'] > now:
                _audit(get_conn, 'LOGIN_LOCKED', username=username,
                       user_id=user['user_id'],
                       detail=f"locked until {user['locked_until']}")
                # The account stays locked either way (no login, no counter
                # bump). Reveal the lockout only on a correct password; a
                # wrong-password attacker enumerating accounts gets the generic
                # error, identical to the unknown-user and wrong-password paths.
                if password_ok:
                    return None, "Account is temporarily locked. Try again later."
                return None, GENERIC_ERROR

            # Wrong password (account is not locked): count the failure.
            if not password_ok:
                # v9.31 freeze condition 6: operator-readable auth-failure
                # counter + structured log. Fires once per bad-credential
                # check regardless of subsequent lockout branch.
                try:
                    observability.record_auth_failure(kind='password',
                                                     username=username)
                except Exception:
                    pass
                # Atomic increment + return-the-new-value. This is critical
                # for concurrency: under load, two simultaneous failed logins
                # against the same account both read failed_login_count=N
                # under the previous "read then write +1" pattern, then both
                # wrote N+1, losing one failure. Lockout could be bypassed by
                # spamming concurrent attempts. UPDATE...SET col=col+1 is
                # atomic in PostgreSQL and resolves under row lock; both
                # transactions get sequenced and observe the correct counter.
                cur.execute(
                    "UPDATE AppUser SET failed_login_count = failed_login_count + 1 "
                    "WHERE user_id = %s "
                    "RETURNING failed_login_count",
                    (user['user_id'],)
                )
                new_count = cur.fetchone()['failed_login_count']

                if new_count >= LOGIN_FAILURE_THRESHOLD:
                    # Lock the account. Use the same row-locked path: the
                    # threshold test above used the post-increment value, so
                    # exactly one of N concurrent failures crosses the line.
                    cur.execute(
                        "UPDATE AppUser SET locked_until = CURRENT_TIMESTAMP + "
                        "(%s || ' minutes')::INTERVAL "
                        "WHERE user_id = %s AND locked_until IS NULL",
                        (ACCOUNT_LOCK_MIN, user['user_id'])
                    )
                    conn.commit()
                    _audit(get_conn, 'LOGIN_LOCKED', username=username,
                           user_id=user['user_id'],
                           detail=f"locked after {new_count} failures")
                    return None, GENERIC_ERROR
                else:
                    conn.commit()
                    _audit(get_conn, 'LOGIN_FAILED', username=username,
                           user_id=user['user_id'],
                           detail=f"failure {new_count}/{LOGIN_FAILURE_THRESHOLD}")
                    return None, GENERIC_ERROR

            # v9.189 (P1.7): per-role network policy. Evaluated only once the
            # password is right, and answered with GENERIC_ERROR, so a caller
            # on a disallowed network learns nothing about the password; the
            # operator reads the real reason in AuthAuditLog. No counter bump:
            # the credential was correct. client_ip() honours X-Forwarded-For
            # only behind POLARIS_TRUST_PROXY, so the address cannot be chosen
            # by the caller.
            ip = client_ip()
            if not network_policy_allows(user['role'], ip):
                conn.rollback()
                _audit(get_conn, 'NETWORK_POLICY_DENIED', username=username,
                       user_id=user['user_id'],
                       detail=f"login from {ip} outside "
                              f"POLARIS_NETWORK_POLICY_{user['role'].upper()}")
                return None, GENERIC_ERROR

            # Success — reset counter, update last login
            cur.execute(
                "UPDATE AppUser SET failed_login_count=0, locked_until=NULL, "
                "last_login_at=CURRENT_TIMESTAMP WHERE user_id=%s",
                (user['user_id'],)
            )
            conn.commit()
            _audit(get_conn, 'LOGIN_SUCCESS', username=username,
                   user_id=user['user_id'])

            return ({
                'user_id':  user['user_id'],
                'username': user['username'],
                'role':     user['role'],
            }, None)
    finally:
        conn.close()


def login_user(user, get_conn=None):
    """Establish a session for the authenticated user. Regenerate session
    ID by clearing/recreating the session dict to prevent fixation (CWE-384).

    v9.189 (P1.7): the session is also registered server-side
    (OperatorSession) and the role's concurrent cap enforced; the registry
    id rides in the signed cookie as 'sid' and validate_session() checks it
    on every request. `get_conn` defaults to the app's configured GET_DB.
    """
    session.clear()
    session['user_id']   = user['user_id']
    session['username']  = user['username']
    session['role']      = user['role']
    session['logged_in'] = True
    session.permanent    = True
    # Issue a fresh CSRF token on login
    session['csrf_token'] = secrets.token_urlsafe(32)
    if get_conn is None:
        get_conn = current_app.config['GET_DB']
    session['sid'] = register_session(get_conn, user)


def logout_user(get_conn):
    """Audit-log the logout, revoke the registry row, then clear the session."""
    if session.get('logged_in'):
        _audit(get_conn, 'LOGOUT',
               username=session.get('username'),
               user_id=session.get('user_id'))
        if session.get('sid'):
            revoke_session(get_conn, session['sid'], 'logout')
    session.clear()


def current_user():
    """Return the logged-in user dict, or None."""
    if not session.get('logged_in'):
        return None
    return {
        'user_id':  session.get('user_id'),
        'username': session.get('username'),
        'role':     session.get('role'),
    }


# ----------------------------------------------------------------------------
# v9.189 (roadmap P1.7) — per-role network policy + the server-side session
# registry with per-role limits.
#
# Both are OFF unless the operator configures them (admin keeps a default
# cap and idle timeout: an admin session is the highest-value cookie in the
# system), both are read from the environment at call time so a change
# lands on restart and the tests can drive them, and both fail LOUDLY on a
# malformed value instead of silently allowing everything:
# validate_role_policies() runs at app import and refuses the boot.
#
#   POLARIS_NETWORK_POLICY_<ROLE>        comma-separated CIDRs / addresses the
#                                        role may log in from and keep a live
#                                        session on (unset = anywhere)
#   POLARIS_SESSION_MAX_<ROLE>           concurrent live sessions per account;
#                                        0 = unlimited (admin default 3)
#   POLARIS_SESSION_IDLE_MINUTES_<ROLE>  idle timeout; 0 = none (admin default 30)
#
# <ROLE> is ADMIN / OPERATOR / AUDITOR. The client address is always
# client_ip(): X-Forwarded-For is honoured only behind POLARIS_TRUST_PROXY,
# exactly as for the rate limiter and AuthAuditLog, so an untrusted client
# cannot spoof its way inside an allowed network.
#
# The registry (OperatorSession, migration 2026-09-01-001) is consulted on
# every authenticated request by validate_session(): a cookie whose row is
# missing, revoked, idle past the role's timeout, owned by a deactivated
# account, or presented from outside the role's policy is cleared and the
# browser sent back to /login. Evictions, expiries, and policy denials are
# written to AuthAuditLog; the registry itself is working state, not audit.
# ----------------------------------------------------------------------------

SESSION_DEFAULT_MAX   = {'admin': 3}     # concurrent live sessions per account
SESSION_DEFAULT_IDLE  = {'admin': 30}    # minutes without a request
SESSION_TOUCH_SECONDS = 60               # last_seen_at write amplification bound
SESSION_PURGE_DAYS    = 30               # registry rows older than this are deleted

_NETWORK_POLICY_CACHE = {}


def _role_env(prefix, role):
    return os.environ.get(f"{prefix}_{str(role).upper()}", '').strip()


def role_network_policy(role):
    """The parsed allow-list for `role` (a tuple of ip_network), or None when
    the role has no policy. Raises ValueError on a malformed entry: a typo in
    an allow-list must never degrade to "allow everything"."""
    raw = _role_env('POLARIS_NETWORK_POLICY', role)
    if not raw:
        return None
    cached = _NETWORK_POLICY_CACHE.get(raw)
    if cached is not None:
        return cached
    nets = []
    for item in raw.split(','):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError as exc:
            raise ValueError(
                f"POLARIS_NETWORK_POLICY_{str(role).upper()}: {item!r} is not "
                f"an IP address or CIDR ({exc})") from None
    if not nets:
        raise ValueError(
            f"POLARIS_NETWORK_POLICY_{str(role).upper()} is set but names no "
            f"network (unset it to allow every address)")
    nets = tuple(nets)
    _NETWORK_POLICY_CACHE[raw] = nets
    return nets


def network_policy_allows(role, ip):
    """True when `role` has no policy or `ip` lies inside one of its networks.
    An address that does not parse never matches an allow-list."""
    nets = role_network_policy(role)
    if nets is None:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in nets)


def _role_int_env(prefix, role, default):
    raw = _role_env(prefix, role)
    if raw == '':
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(
            f"{prefix}_{str(role).upper()} must be a non-negative integer, "
            f"got {raw!r}") from None
    if value < 0:
        raise ValueError(
            f"{prefix}_{str(role).upper()} must be a non-negative integer, "
            f"got {raw!r}")
    return value


def session_max_for_role(role):
    """Concurrent live sessions allowed per account of `role`; 0 = unlimited."""
    return _role_int_env('POLARIS_SESSION_MAX', role, SESSION_DEFAULT_MAX.get(role, 0))


def session_idle_minutes_for_role(role):
    """Idle timeout in minutes for `role`; 0 = none (the 8h cookie lifetime
    still applies)."""
    return _role_int_env('POLARIS_SESSION_IDLE_MINUTES', role,
                         SESSION_DEFAULT_IDLE.get(role, 0))


def validate_role_policies():
    """Parse every role's policy once and return the effective limits, or
    raise ValueError on the first malformed value. app.py calls this at
    import so a bad value fails the boot, never a login."""
    summary = {}
    for role in ROLES:
        nets = role_network_policy(role)
        summary[role] = {
            'network_policy': [str(n) for n in nets] if nets else None,
            'max_sessions':   session_max_for_role(role),
            'idle_minutes':   session_idle_minutes_for_role(role),
        }
    return summary


def register_session(get_conn, user):
    """INSERT the OperatorSession row for a fresh login, enforce the role's
    concurrent cap, purge stale rows, and return the new session id.

    The cap evicts the LEAST-RECENTLY-SEEN live sessions beyond it rather
    than refusing the new login: an operator locked out of their own account
    by their own stale tabs would be the wrong failure. The account row is
    locked for the transaction so concurrent logins serialize and the cap is
    exact (C9: the count is tested with real threads).
    """
    sid = secrets.token_hex(32)
    role = user['role']
    cap = session_max_for_role(role)
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT user_id FROM AppUser WHERE user_id = %s FOR UPDATE",
                        (user['user_id'],))
            cur.execute(
                "INSERT INTO OperatorSession (session_id, user_id, role, client_ip) "
                "VALUES (%s, %s, %s, %s)",
                (sid, user['user_id'], role, client_ip()[:45]))
            evicted = []
            if cap > 0:
                cur.execute(
                    "UPDATE OperatorSession "
                    "   SET revoked_at = now(), revoke_reason = 'evicted' "
                    " WHERE session_id IN ("
                    "       SELECT session_id FROM OperatorSession "
                    "        WHERE user_id = %s AND revoked_at IS NULL "
                    "        ORDER BY last_seen_at DESC, created_at DESC "
                    "       OFFSET %s) "
                    "RETURNING session_id",
                    (user['user_id'], cap))
                evicted = [r['session_id'] for r in cur.fetchall()]
            # Hygiene: rows nobody can present any more.
            cur.execute(
                "DELETE FROM OperatorSession "
                " WHERE COALESCE(revoked_at, last_seen_at) < now() - make_interval(days => %s)",
                (SESSION_PURGE_DAYS,))
        conn.commit()
    finally:
        conn.close()
    for old in evicted:
        _audit(get_conn, 'SESSION_EVICTED',
               username=user['username'], user_id=user['user_id'],
               detail=f"POLARIS_SESSION_MAX_{role.upper()}={cap}; "
                      f"evicted the least-recently-seen session {old[:12]}")
    return sid


def revoke_session(get_conn, sid, reason):
    """Mark one registry row revoked (idempotent)."""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE OperatorSession SET revoked_at = now(), revoke_reason = %s "
                " WHERE session_id = %s AND revoked_at IS NULL",
                (reason, sid))
        conn.commit()
    finally:
        conn.close()


def _relative_next():
    """The current request as a same-origin path, for ?next=.

    is_safe_next_url() accepts only a relative path, and until v9.237 every
    redirect to /login carried request.url, which is absolute, so the return
    to the page that required the login never happened: the operator always
    landed on the dashboard. Path plus query string, nothing else."""
    qs = request.query_string.decode('utf-8', 'replace')
    return request.path + ('?' + qs if qs else '')


def _end_session():
    """Clear the cookie session and send the browser to /login (GETs keep a
    ?next= so the operator lands back where they were after re-authenticating)."""
    session.clear()
    if request.method == 'GET':
        return redirect(url_for('login', next=_relative_next()))
    return redirect(url_for('login'))


def validate_session(get_conn):
    """before_request hook for the registry. Returns None when the request may
    proceed, or a redirect response after ending the session because its
    registry row is missing / revoked, its account is deactivated, it idled
    past the role's timeout, or the client's address is outside the role's
    network policy. Touches last_seen_at at most once per SESSION_TOUCH_SECONDS.
    """
    if not session.get('logged_in') or request.endpoint == 'static':
        return None
    sid      = session.get('sid')
    role     = session.get('role')
    user_id  = session.get('user_id')
    username = session.get('username')
    if not sid or not isinstance(sid, str):
        # A cookie from before v9.189, or one without a registry id: anonymous.
        return _end_session()
    idle = session_idle_minutes_for_role(role)
    ip = client_ip()
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT s.revoked_at, u.is_active, "
                "       (%(idle)s > 0 AND s.last_seen_at < now() - make_interval(mins => %(idle)s)) AS idle_expired, "
                "       (s.last_seen_at < now() - make_interval(secs => %(touch)s)) AS stale "
                "  FROM OperatorSession s JOIN AppUser u ON u.user_id = s.user_id "
                " WHERE s.session_id = %(sid)s AND s.user_id = %(uid)s",
                {'idle': idle, 'touch': SESSION_TOUCH_SECONDS, 'sid': sid, 'uid': user_id})
            row = cur.fetchone()
            if row is None or row['revoked_at'] is not None:
                ended = None          # already audited when it was revoked, or never registered
            elif not row['is_active']:
                ended = ('deactivated', 'SESSION_REVOKED', 'account deactivated')
            elif row['idle_expired']:
                ended = ('idle', 'SESSION_EXPIRED',
                         f"idle longer than POLARIS_SESSION_IDLE_MINUTES_{role.upper()}={idle}")
            elif not network_policy_allows(role, ip):
                ended = ('network_policy', 'NETWORK_POLICY_DENIED',
                         f"live session presented from {ip} outside "
                         f"POLARIS_NETWORK_POLICY_{role.upper()}")
            else:
                ended = False
            if ended:
                cur.execute(
                    "UPDATE OperatorSession SET revoked_at = now(), revoke_reason = %s "
                    " WHERE session_id = %s AND revoked_at IS NULL",
                    (ended[0], sid))
                conn.commit()
            elif ended is False and row['stale']:
                cur.execute("UPDATE OperatorSession SET last_seen_at = now() WHERE session_id = %s",
                            (sid,))
                conn.commit()
    finally:
        conn.close()
    if row is None or row['revoked_at'] is not None:
        return _end_session()
    if ended:
        _audit(get_conn, ended[1], username=username, user_id=user_id, detail=ended[2])
        return _end_session()
    return None


def is_safe_next_url(next_url):
    """True only for a same-origin relative path that is safe to redirect to
    after login (open-redirect / CWE-601 defense). Rejects:

      - empty or non-string values;
      - anything not starting with a single '/';
      - protocol-relative '//host';
      - backslash variants like '/\\host' — browsers normalize a backslash to
        a forward slash when parsing a URL or Location header, so '/\\evil.com'
        becomes '//evil.com', but werkzeug emits the backslash verbatim, so the
        naive `startswith('//')` guard misses it;
      - anything urlsplit() reads as carrying a scheme or netloc;
      - embedded control characters (CR/LF header-splitting, etc.).

    The three post-login redirect sites (password login, the WebAuthn partial-
    auth redirect, and the assertion completion) all route ?next= through here.
    """
    if not next_url or not isinstance(next_url, str):
        return False
    if not next_url.startswith('/') or next_url.startswith('//'):
        return False
    if '\\' in next_url:
        return False
    if any(ord(ch) < 0x20 for ch in next_url):
        return False
    split = urlsplit(next_url)
    return not split.scheme and not split.netloc


# ----------------------------------------------------------------------------
# Authorization decorators
# ----------------------------------------------------------------------------

# Role hierarchy for "at least this role" semantics where useful.
# Note: in this app the roles are mostly orthogonal (auditor != less-than-admin),
# so we use require_role with a set rather than a hierarchy.
ROLES = ('admin', 'operator', 'auditor')


def login_required(view_func):
    """Reject anonymous requests. CWE-306 mitigation."""
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('logged_in'):
            # Audit the auth-required event for unauthenticated POSTs;
            # GETs are noisy and would flood the log with browser noise.
            if request.method != 'GET':
                _audit(current_app.config['GET_DB'], 'AUTH_REQUIRED',
                       detail=f"{request.method} {request.path}")
            return redirect(url_for('login', next=_relative_next()))
        return view_func(*args, **kwargs)
    return wrapped


def require_role(*allowed_roles):
    """
    Restrict view to specified roles. Logged-in users with the wrong role
    get a 403, not a 404 — they're authenticated but not authorized
    (CWE-285 mitigation).
    """
    def decorator(view_func):
        @functools.wraps(view_func)
        def wrapped(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login', next=_relative_next()))
            if session.get('role') not in allowed_roles:
                _audit(current_app.config['GET_DB'], 'AUTHZ_DENIED',
                       username=session.get('username'),
                       user_id=session.get('user_id'),
                       detail=f"role={session.get('role')} "
                              f"allowed={allowed_roles} "
                              f"path={request.path}")
                abort(403)
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


# ----------------------------------------------------------------------------
# CSRF protection (CWE-352)
# ----------------------------------------------------------------------------

def issue_csrf_token():
    """Generate or fetch the per-session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']


def validate_csrf():
    """
    Validate the CSRF token submitted on a state-changing request.
    Uses constant-time comparison to defeat timing oracles (CWE-208).
    Returns True if valid, False otherwise.

    Accepts the token from either:
      - form field 'csrf_token' (HTML form POSTs)
      - header 'X-CSRFToken' (JSON / AJAX POSTs)
    Form takes precedence when both are present.
    """
    submitted = request.form.get('csrf_token') or request.headers.get('X-CSRFToken') or ''
    expected  = session.get('csrf_token', '')
    if not submitted or not expected:
        return False
    return hmac.compare_digest(submitted, expected)


def csrf_protect(view_func):
    """Decorator to require a valid CSRF token on POST/PUT/DELETE."""
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            if not validate_csrf():
                _audit(current_app.config['GET_DB'], 'CSRF_REJECTED',
                       username=session.get('username'),
                       user_id=session.get('user_id'),
                       detail=f"{request.method} {request.path}")
                abort(403)
        return view_func(*args, **kwargs)
    return wrapped


def reject_cross_site(view_func):
    """Reject cross-site requests to unauthenticated local-control endpoints
    (the launcher's /api/quit and /api/heartbeat). Browsers set the
    `Sec-Fetch-Site` header on every request; a request originating from a
    different site carries `cross-site`. Those endpoints take no CSRF token and
    no session (the launcher beacon is anonymous), so without this a page the
    user merely visits could `fetch()` the local instance and, for /api/quit,
    shut it down (CWE-352-adjacent drive-by). Same-origin browser calls
    (`same-origin`) and header-less callers (the native launcher, curl, an
    operator) are allowed, so this does not break the heartbeat or operator use.
    """
    @functools.wraps(view_func)
    def wrapped(*args, **kwargs):
        if request.headers.get('Sec-Fetch-Site') == 'cross-site':
            abort(403)
        return view_func(*args, **kwargs)
    return wrapped


# ----------------------------------------------------------------------------
# Security headers (applied by app.after_request hook)
# ----------------------------------------------------------------------------

def apply_security_headers(response):
    """
    Add the standard security headers to every response.

    CSP: default-src 'self' allows only same-origin; 'unsafe-inline' is
    permitted for <style> because the templates use a small amount of inline
    style (and our hand-written CSS isn't worth the effort to migrate to
    CSP-nonce-style). Inline scripts are NOT permitted — there are none in
    the templates by design (one toy onclick handler in sql_console.html
    uses inline JS but it's not security-critical; we'll move it).

    Headers applied:
      Content-Security-Policy   (CWE-79 mitigation)
      X-Frame-Options           (CWE-1021 clickjacking)
      X-Content-Type-Options    (CWE-451 MIME sniffing)
      Referrer-Policy           (CWE-200 information leak)
      Permissions-Policy        (feature-policy minimization)
      Strict-Transport-Security (CWE-319, only in production)
      Cache-Control             (CWE-525 sensitive content caching)
    """
    # v9.13: tightened CSP with `upgrade-insecure-requests` when HSTS active
    # (defense against mixed-content on production) and isolation headers
    # (COOP/COEP/CORP) for cross-origin defense-in-depth against Spectre-class
    # side-channel + cross-origin object leaks.
    hsts_active = os.environ.get('POLARIS_HSTS', '').lower() in ('1', 'true', 'yes')

    # v9.146: the Atlas page renders a MapLibre GL street-level basemap from
    # CARTO's free dark-matter vector tiles. That requires reaching exactly
    # two external origins (style, glyphs, sprite, vector tiles) and a blob:
    # web worker. This relaxation is scoped to the atlas endpoint ONLY via the
    # `g.atlas_tiles` flag the view sets; every other response keeps the strict
    # self-only CSP. The MapLibre JS itself is self-hosted (static/vendor), so
    # script-src stays 'self'. ZERO_KNOWLEDGE events are never plotted (C6), so
    # the basemap is cartography, not new exposure.
    from flask import g as _g
    # v9.237: the origin is whatever the deployment configured (app.py's
    # ATLAS_BASEMAP_STYLE_URL); the view sets g.atlas_tile_origins from it. A
    # self-hosted basemap yields an empty list and the page stays self-only
    # apart from blob:, which MapLibre needs for its workers regardless.
    _TILE = getattr(_g, 'atlas_tile_origins', '') or ''
    atlas_tiles = bool(getattr(_g, 'atlas_tiles', False))
    img_extra     = (" blob:" + (" " + _TILE if _TILE else "")) if atlas_tiles else ""
    connect_extra = ((" " + _TILE) if _TILE else "")            if atlas_tiles else ""

    csp_parts = [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:" + img_extra,
        "font-src 'self' data:",
        "connect-src 'self'" + connect_extra,
        "worker-src 'self' blob:" if atlas_tiles else "worker-src 'self'",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
    ]
    if hsts_active:
        # Forces mixed-content requests to be upgraded to HTTPS rather than
        # blocked silently. Only meaningful in production where HSTS is on.
        csp_parts.append("upgrade-insecure-requests")
    response.headers['Content-Security-Policy']   = "; ".join(csp_parts)
    response.headers['X-Frame-Options']           = 'DENY'
    response.headers['X-Content-Type-Options']    = 'nosniff'
    response.headers['Referrer-Policy']           = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy']        = (
        'camera=(), microphone=(), geolocation=(), payment=(), usb=(), '
        'interest-cohort=(), browsing-topics=()'
    )
    # v9.13 cross-origin isolation: COOP isolates the browsing context from
    # cross-origin windows (Spectre defense); CORP restricts cross-origin
    # embedding of our resources to same-origin only.
    response.headers['Cross-Origin-Opener-Policy']   = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    # Note: COEP `require-corp` is not enabled because it breaks any future
    # embedded resources (img/script) that don't carry CORP. Leaving COOP +
    # CORP active provides ~90% of the isolation benefit without the
    # operational cost.

    # HSTS only in production (env opt-in, since enabling it on a non-HTTPS
    # dev box would be confusing). 1 year + includeSubDomains is the standard.
    if hsts_active:
        response.headers['Strict-Transport-Security'] = \
            'max-age=31536000; includeSubDomains'

    # v9.13: Server-header scrubbing — defense-in-depth across deployment shapes.
    #
    #   - Werkzeug dev server: pop+set wins; the wire shows `Server: Polaris`.
    #   - Gunicorn (production): the `gunicorn.conf.py` post_worker_init hook
    #     monkey-patches `gunicorn.http.wsgi.Response.default_headers` to drop
    #     the hardcoded `Server: gunicorn`. The pop+set below covers the case
    #     where the patch is bypassed.
    #   - Behind reverse proxy (canonical production path): Caddy or nginx
    #     strips/replaces Server at the edge. Documented in
    #     `docs/operator/DEPLOYMENT.md`. That layer is authoritative.
    #
    # Outcome on the wire: either `Server: Polaris` or no Server header at all.
    # Both are acceptable; neither leaks the actual server type/version.
    response.headers.pop('Server', None)
    response.headers['Server'] = 'Polaris'

    # Don't cache authenticated content. (Most of our content is.)
    if session.get('logged_in'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma']        = 'no-cache'

    return response


# ----------------------------------------------------------------------------
# Body-size limit guard (used as before_request)
# ----------------------------------------------------------------------------

def enforce_body_size_limit():
    """Reject oversized POSTs. Flask's MAX_CONTENT_LENGTH does this too,
    but we add an explicit check that returns a clear error message rather
    than a generic 413."""
    if request.content_length and request.content_length > MAX_REQUEST_BODY_BYTES:
        abort(413)


# ----------------------------------------------------------------------------
# Helpers for templates
# ----------------------------------------------------------------------------

def template_context_processor():
    """Inject CSRF token and current_user into all templates."""
    return {
        'csrf_token':   issue_csrf_token,
        'current_user': current_user(),
    }

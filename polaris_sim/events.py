"""The national life-event stream: a realistic flow of verifications and token
lifecycle events over a time window, written through the REAL paths.

- Verifications are written by the same direct `INSERT INTO VerificationEvent`
  the application's verification route uses (there is no stored procedure for a
  verification). The database's `chk_disclosure_token_consistency` is the
  boundary: a ZERO_KNOWLEDGE event carries no token_id and no location (C6), a
  FULL event carries a token, a located event is placed near its holder's state.
- Lifecycle transitions (revocations) go through the real procedure
  `uc8_revoke_token`, which writes the REVOKED lifecycle row itself. The stream
  never inserts a TokenLifecycleEvent or an IdentityToken directly.

Generation is a pure function of (seed, pools, now); the writer is separate, so
the distribution can be tested without a database.
"""

from __future__ import annotations

import datetime
import hashlib
import io
import random
import time
from dataclasses import dataclass, field
from typing import Iterable, Iterator

from . import reference


# Weighted mixes. Zero-knowledge is the privacy default and dominates; SUCCESS
# dominates outcomes; everyday contexts (banking, motor vehicle, employment)
# out-number rare ones (voting).
@dataclass(frozen=True)
class EventProfile:
    disclosure: tuple[tuple[str, float], ...] = (
        ("ZERO_KNOWLEDGE", 0.55), ("SELECTIVE", 0.35), ("FULL", 0.10))
    outcome: tuple[tuple[str, float], ...] = (
        ("SUCCESS", 0.90), ("FAILURE", 0.06), ("EXPIRED", 0.02), ("UNAUTHORIZED", 0.02))
    # context_id (1..7 as seeded: BANKING, EMPLOYMENT, HEALTHCARE, TRAVEL,
    # VOTING, MOTOR_VEHICLE, GOVERNMENT_BENEFITS) with everyday weighting.
    context: tuple[tuple[int, float], ...] = (
        (1, 0.26), (2, 0.16), (3, 0.14), (4, 0.12), (5, 0.03), (6, 0.20), (7, 0.09))


DEFAULT_PROFILE = EventProfile()

_PURPOSES = (
    "account access", "identity confirmation", "age verification",
    "benefit eligibility", "boarding check", "license renewal", "records request",
)


def _weighted(rng: random.Random, choices: tuple[tuple[object, float], ...]):
    r = rng.random() * sum(w for _, w in choices)
    upto = 0.0
    for value, w in choices:
        upto += w
        if r <= upto:
            return value
    return choices[-1][0]


@dataclass(frozen=True)
class TokenRef:
    token_id: int
    jurisdiction: str


# One generated verification, matching the VerificationEvent columns the writer
# emits. token_id / latitude / longitude / requestor_location are None for a
# zero-knowledge event (C6).
@dataclass(frozen=True)
class Verification:
    token_id: int | None
    requesting_agency_id: int
    context_id: int
    event_timestamp: datetime.datetime
    outcome: str
    disclosure_level: str
    proof_commitment: str | None
    requestor_location: str | None
    latitude: float | None
    longitude: float | None
    requesting_purpose_text: str


def iter_verifications(pool: list[TokenRef], agency_ids: list[int], count: int,
                       window_hours: float, seed: int, now: datetime.datetime,
                       profile: EventProfile = DEFAULT_PROFILE) -> Iterator[Verification]:
    """Yield `count` synthetic verifications spread over the window ending at
    `now`. Pure: no database, no global RNG. A zero-knowledge event is anonymous
    and unplaceable; a disclosing event names a token from the pool and is placed
    near that holder's state (C6 by construction)."""
    if not agency_ids:
        raise ValueError("no agencies to act as verifiers")
    rng = random.Random(_derive(seed, "verifications", count, window_hours))
    window_s = max(0.0, window_hours) * 3600.0
    for i in range(count):
        disclosure = str(_weighted(rng, profile.disclosure))
        agency = agency_ids[rng.randrange(len(agency_ids))]
        context = int(_weighted(rng, profile.context))
        outcome = str(_weighted(rng, profile.outcome))
        ts = now - datetime.timedelta(seconds=rng.random() * window_s)
        if disclosure == "ZERO_KNOWLEDGE" or not pool:
            # Anonymous: no token, no place. A synthetic proof commitment stands
            # in for the ZK proof hash.
            commit = hashlib.sha256(f"{seed}:{i}".encode()).hexdigest()[:64]
            yield Verification(None, agency, context, ts, outcome, "ZERO_KNOWLEDGE",
                               commit, None, None, None, _PURPOSES[i % len(_PURPOSES)])
        else:
            ref = pool[rng.randrange(len(pool))]
            lat0, lon0 = reference.STATE_CENTROIDS.get(ref.jurisdiction, (39.0, -98.0))
            lat = round(lat0 + rng.uniform(-1.4, 1.4), 5)
            lon = round(lon0 + rng.uniform(-1.4, 1.4), 5)
            yield Verification(ref.token_id, agency, context, ts, outcome, disclosure,
                               None, reference.STATE_NAMES.get(ref.jurisdiction, "United States"),
                               lat, lon, _PURPOSES[i % len(_PURPOSES)])


def _derive(*parts: object) -> int:
    h = hashlib.sha256("|".join(str(p) for p in parts).encode()).digest()
    return int.from_bytes(h[:8], "big")


_COPY_COLS = ("token_id", "requesting_agency_id", "context_id", "event_timestamp",
              "outcome", "disclosure_level", "proof_commitment", "requestor_location",
              "latitude", "longitude", "requesting_purpose_text")


def _cell(v: object) -> str:
    # COPY text format: \N is NULL; our data has no tabs/newlines/backslashes.
    if v is None:
        return r"\N"
    if isinstance(v, datetime.datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return str(v)


def write_verifications(conn, events: Iterable[Verification], batch_size: int = 10000) -> int:
    """Stream verifications into VerificationEvent with COPY. Returns the count
    written. The partitioned table routes each row by event_timestamp.

    COPY FROM is refused on a table whose row-level security applies to the
    caller, and VerificationEvent's does apply to the application role. The
    bulk simulator runs as the owner and keeps COPY; the web application's
    simulation tick (/api/sim/tick) runs as polaris_app and failed on every
    tick in any real deployment, while the suite, connected as the owner,
    passed (found 2026-09-25 by running the suite as the application role).
    Where the policy applies, the same rows go in as batched INSERTs."""
    written = 0
    buf = io.StringIO()
    rows: list[tuple] = []
    n = 0
    with conn.cursor() as cur:
        cur.execute("SELECT row_security_active('verificationevent') AS rls")
        r = cur.fetchone()
        use_copy = not (r["rls"] if isinstance(r, dict) else r[0])

    def flush():
        nonlocal n
        if n == 0:
            return
        with conn.cursor() as cur:
            if use_copy:
                buf.seek(0)
                cur.copy_expert(
                    f"COPY VerificationEvent ({', '.join(_COPY_COLS)}) FROM STDIN", buf)
                buf.seek(0)
                buf.truncate(0)
            else:
                from psycopg2.extras import execute_values
                execute_values(cur, f"INSERT INTO VerificationEvent ({', '.join(_COPY_COLS)}) "
                                    f"VALUES %s", rows, page_size=1000)
                rows.clear()
        n = 0

    for e in events:
        if use_copy:
            buf.write("\t".join((
                _cell(e.token_id), _cell(e.requesting_agency_id), _cell(e.context_id),
                _cell(e.event_timestamp), _cell(e.outcome), _cell(e.disclosure_level),
                _cell(e.proof_commitment), _cell(e.requestor_location),
                _cell(e.latitude), _cell(e.longitude), _cell(e.requesting_purpose_text))) + "\n")
        else:
            rows.append((e.token_id, e.requesting_agency_id, e.context_id, e.event_timestamp,
                         e.outcome, e.disclosure_level, e.proof_commitment,
                         e.requestor_location, e.latitude, e.longitude,
                         e.requesting_purpose_text))
        written += 1
        n += 1
        if n >= batch_size:
            flush()
    flush()
    return written


def load_pools(conn, sample: int = 5000) -> tuple[list[TokenRef], list[int], list[int]]:
    """Sample active tokens (with their holder's jurisdiction) plus the agency
    and context id lists. A random sample of tokens is population-weighted for
    free, since the substrate enrolled people in proportion to population."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT it.token_id, ind.jurisdiction
            FROM IdentityToken it JOIN Individual ind ON it.individual_id = ind.individual_id
            WHERE it.status = 'ACTIVE'
            ORDER BY random() LIMIT %s""", (sample,))
        pool = [TokenRef(r["token_id"], r["jurisdiction"]) for r in cur.fetchall()]
        cur.execute("SELECT agency_id FROM Agency ORDER BY agency_id")
        agencies = [r["agency_id"] for r in cur.fetchall()]
        cur.execute("SELECT context_id FROM VerificationContext ORDER BY context_id")
        contexts = [r["context_id"] for r in cur.fetchall()]
    return pool, agencies, contexts


# Real revocation reason codes (RevocationList CHECK), weighted toward the
# everyday ones. DEATH is the rare erasure trigger.
_REVOKE_REASONS = (("LOST", 0.40), ("STOLEN", 0.25), ("COMPROMISED", 0.15),
                   ("SUPERSEDED", 0.10), ("ADMINISTRATIVE", 0.05), ("DEATH", 0.05))


def revoke_tokens(conn, count: int, seed: int, algorithm_id: int = 1) -> int:
    """Revoke `count` tokens through the REAL uc8_revoke_token procedure, which
    writes the REVOKED lifecycle row itself. Revocation is a co-signed action
    above a rate bound (an anti-abuse control), so this picks two agencies both
    authorized on the algorithm as actor and co-signer. Each call is wrapped in
    a savepoint, so one that trips a control (e.g. the rate bound) is skipped
    without losing the others. Returns how many were revoked."""
    if count <= 0:
        return 0
    rng = random.Random(_derive(seed, "revocations"))
    with conn.cursor() as cur:
        cur.execute(
            "SELECT agency_id FROM AgencyAlgorithmAuth "
            "WHERE algorithm_id = %s AND authorization_type = 'BOTH' "
            "ORDER BY agency_id LIMIT 2", (algorithm_id,))
        auth = [r["agency_id"] for r in cur.fetchall()]
        if len(auth) < 2:
            return 0
        actor, cosigner = auth[0], auth[1]
        cur.execute(
            "SELECT token_id FROM IdentityToken "
            "WHERE status = 'ACTIVE' AND algorithm_id = %s "
            "ORDER BY random() LIMIT %s", (algorithm_id, count))
        token_ids = [r["token_id"] for r in cur.fetchall()]

    done = 0
    with conn.cursor() as cur:
        for tid in token_ids:
            reason = str(_weighted(rng, _REVOKE_REASONS))
            try:
                cur.execute("SAVEPOINT sp_rev")
                cur.execute("CALL uc8_revoke_token(%s, %s, %s, %s, %s)",
                            (tid, actor, reason, "https://crl.polaris.example/sim", cosigner))
                cur.execute("RELEASE SAVEPOINT sp_rev")
                done += 1
            except Exception:
                cur.execute("ROLLBACK TO SAVEPOINT sp_rev")
    return done


@dataclass
class StreamStats:
    verifications: int = 0
    revocations: int = 0
    seconds: float = 0.0
    by_disclosure: dict = field(default_factory=dict)

    @property
    def rows_per_sec(self) -> float:
        return self.verifications / self.seconds if self.seconds > 0 else 0.0


def run_stream(conn, *, verifications: int, lifecycle: int = 0, window_hours: float = 24.0,
               seed: int = 42, sample: int = 5000, batch_size: int = 10000,
               commit: bool = True, now: datetime.datetime | None = None) -> StreamStats:
    """Generate and write a life-event stream against the enrolled nation."""
    from . import assert_expendable
    assert_expendable()
    if now is None:
        now = datetime.datetime.now()
    pool, agencies, _contexts = load_pools(conn, sample)
    if not pool:
        raise RuntimeError("no active tokens: build the substrate first (polaris_sim build)")

    t0 = time.perf_counter()
    stats = StreamStats()
    events = list(iter_verifications(pool, agencies, verifications, window_hours, seed, now))
    for e in events:
        stats.by_disclosure[e.disclosure_level] = stats.by_disclosure.get(e.disclosure_level, 0) + 1
    stats.verifications = write_verifications(conn, events, batch_size)
    if commit:
        conn.commit()
    stats.revocations = revoke_tokens(conn, lifecycle, seed)
    if commit:
        conn.commit()
    stats.seconds = time.perf_counter() - t0
    return stats

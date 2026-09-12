"""Load a synthetic-nation plan into a Polaris database through the REAL
enrollment path: agencies inserted as configuration, then every person issued a
token set-based through the bulk pipeline (uc_bulk_issue), so each synthetic
enrollee passes exactly the constraint set a real one does.

The loader is deliberately dumb about the DB connection: the caller passes a
psycopg2 connection (RealDictCursor), which keeps it testable and lets the
benchmark point it at an expendable database.
"""

from __future__ import annotations

import io
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from . import nation as _nation

# The simulation issues tokens through the real bulk pipeline, so it signs each
# token_value through the same signing module single issuance uses. Real
# ML-DSA-65 when POLARIS_USE_REAL_PQC=1 (+ liboqs), a deterministic verifiable
# sha3-256 placeholder otherwise; never a fabricated placeholder literal.
from polaris_web import pqc_signing as _pqc

# Every synthetic token is permitted in all seven verification contexts (ids
# 1..7 as seeded), so the enrolled population is usable everywhere the later
# event-stream ship will exercise.
_ALL_CONTEXTS = "{1,2,3,4,5,6,7}"

# Real biometric bindings only (a national credential is biometrically bound);
# cycled deterministically.
_BIO_TYPES = ("FINGERPRINT", "FACE", "IRIS")

_DEFAULT_ALGORITHM_ID = 1        # ML-DSA-65, the operational default (not deprecated)
_DEFAULT_BATCH_SIZE = 5000       # rows per uc_bulk_issue call


@dataclass(frozen=True)
class LoadStats:
    scale_divisor: int
    seed: int
    agencies: int
    people: int
    tokens_issued: int
    seconds: float

    @property
    def rows_per_sec(self) -> float:
        return self.people / self.seconds if self.seconds > 0 else 0.0


#: Why the simulation is allowed to create authorities. Since v9.440 the database
#: refuses an INSERT into Agency without a stated reason of at least 20 characters,
#: and the simulation is a caller like any other: a loader that could bypass the rule
#: would be simulating a system that does not have it.
_SIM_REASON = ("synthetic bureau for the national simulation, notional data only")


def _insert_agencies(cur, plan: _nation.NationPlan) -> dict[str, int]:
    """Insert every bureau as an Agency (configuration data, like the seed) and
    return name -> agency_id. Bureau names are unique by construction."""
    ids: dict[str, int] = {}
    # Transaction-local, so it cannot leak into whatever runs on this connection next.
    cur.execute("SELECT set_config('polaris.actor', 'national-simulation', true), "
                "       set_config('polaris.justification', %s, true)", (_SIM_REASON,))
    for b in plan.bureaus:
        cur.execute(
            "INSERT INTO Agency (name, agency_type, jurisdiction, authorization_level) "
            "VALUES (%s, %s, %s, %s) RETURNING agency_id",
            (b.name, b.agency_type, b.jurisdiction, b.authorization_level))
        ids[b.name] = cur.fetchone()["agency_id"]
    return ids


def _grant_auth(cur, agency_ids: Iterable[int], algorithm_id: int) -> None:
    """Grant every simulated bureau BOTH (issue+verify) on the algorithm, the
    same AgencyAlgorithmAuth gate uc_bulk_issue checks once per batch. Without
    this a brand-new agency cannot issue and the batch is refused."""
    for aid in agency_ids:
        cur.execute(
            "INSERT INTO AgencyAlgorithmAuth (agency_id, algorithm_id, authorization_type) "
            "VALUES (%s, %s, 'BOTH') ON CONFLICT (agency_id, algorithm_id) DO NOTHING",
            (aid, algorithm_id))


def _issue_batch(cur, agency_id: int, algorithm_id: int,
                 people: list[_nation.Person], seq: int) -> int:
    """Stage one batch with COPY and issue it through uc_bulk_issue. `seq` is a
    global monotonic counter that makes token_value / physical_serial unique
    across the whole build. Returns the advanced counter."""
    cur.execute(
        "INSERT INTO BulkEnrollmentBatch (issuing_agency_id, algorithm_id, note) "
        "VALUES (%s, %s, 'polaris_sim substrate') RETURNING batch_id",
        (agency_id, algorithm_id))
    batch_id = cur.fetchone()["batch_id"]

    buf = io.StringIO()
    for p in people:
        seq += 1
        bio = _BIO_TYPES[seq % len(_BIO_TYPES)]
        token_value = f"SIMTOK-{seq:012d}"
        serial = f"SIMSER-{seq:012d}"
        # Sign the token_value the same way single issuance does; stage the real
        # signature + public key so uc_bulk_issue stores them (it refuses NULL).
        sig, _label, pubkey = _pqc.signature_with_key_for_token(token_value)
        sig_field = "\\x" + sig.hex()          # CSV bytea hex input
        pk_field = pubkey if pubkey else ""    # empty -> NULL (placeholder has no key)
        # batch_id | legal_name | dob | jurisdiction | biometric | token | serial | contexts | sig | pubkey
        buf.write("|".join((
            str(batch_id), p.legal_name, p.date_of_birth.isoformat(), p.jurisdiction,
            bio, token_value, serial, _ALL_CONTEXTS, sig_field, pk_field)) + "\n")
    buf.seek(0)
    cur.copy_expert(
        "COPY BulkEnrollmentStaging "
        "(batch_id, legal_name, date_of_birth, jurisdiction, biometric_binding_type, "
        " token_value, physical_serial, permitted_contexts, signature_bytes, signing_public_key_hex) "
        "FROM STDIN WITH (FORMAT csv, DELIMITER '|')", buf)
    cur.execute("CALL uc_bulk_issue(%s)", (batch_id,))
    return seq


def build_nation(conn, plan: _nation.NationPlan, *,
                 algorithm_id: int = _DEFAULT_ALGORITHM_ID,
                 batch_size: int = _DEFAULT_BATCH_SIZE,
                 commit: bool = True,
                 progress: Callable[[str, int, int], None] | None = None) -> LoadStats:
    """Load the whole plan. Agencies + grants go in first (setup), then each
    bureau's people are issued in batches through uc_bulk_issue.

    With `commit=True` (the default) the loader commits the setup and then each
    bureau, so progress is durable and no single transaction holds the whole
    nation. With `commit=False` it never commits, leaving the caller's
    transaction open (a test loads a small nation and rolls it back for
    isolation). `progress(jurisdiction, done_people, total_people)` fires after
    each bureau if supplied.
    """
    from . import assert_expendable
    assert_expendable()
    total_people = plan.total_people
    t0 = time.perf_counter()
    with conn.cursor() as cur:
        agency_ids = _insert_agencies(cur, plan)
        _grant_auth(cur, agency_ids.values(), algorithm_id)
    if commit:
        conn.commit()

    seq = 0
    done = 0
    tokens = 0
    with conn.cursor() as cur:
        for b in plan.bureaus:
            if b.enroll_count == 0:
                continue
            agency_id = agency_ids[b.name]
            chunk: list[_nation.Person] = []
            for person in _nation.generate_people(b, plan.seed):
                chunk.append(person)
                if len(chunk) >= batch_size:
                    seq = _issue_batch(cur, agency_id, algorithm_id, chunk, seq)
                    tokens += len(chunk)
                    chunk = []
            if chunk:
                seq = _issue_batch(cur, agency_id, algorithm_id, chunk, seq)
                tokens += len(chunk)
            if commit:
                conn.commit()
            done += b.enroll_count
            if progress is not None:
                progress(b.jurisdiction, done, total_people)

    return LoadStats(
        scale_divisor=plan.scale_divisor, seed=plan.seed,
        agencies=len(agency_ids), people=total_people, tokens_issued=tokens,
        seconds=time.perf_counter() - t0)

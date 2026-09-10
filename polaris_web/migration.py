"""polaris_web/migration.py — mass algorithm migration (roadmap P7.6, the quantum event).

UC-6 migrates ONE token. `uc6_migrate_algorithm` takes a per-token advisory lock, validates,
inserts a signature, and optionally deprecates the old one. That is the right shape for an
operator migrating a credential in front of them, and the wrong shape for the day an algorithm
falls: a round trip per token, times a population.

This module is the population path. It is deliberately built out of the same constraints the
per-token procedure relies on rather than around them, so nothing here is a fast path that
skips a check:

  THE UNIQUE CONSTRAINT IS THE SERIALIZATION POINT. `one_signature_per_algorithm_per_token`
  already makes a second migration of the same token to the same algorithm impossible. The
  advisory lock in UC-6 protects a read-then-write sequence this path does not perform, so the
  set-based INSERT ... ON CONFLICT DO NOTHING is not weaker; two workers racing the same token
  produce one row, and the loser learns it inserted nothing.

  THE TRIGGERS STILL FIRE. `enforce_token_has_active_signature` and the append-only
  TokenSignature triggers run per row exactly as they do for UC-6. A migration cannot leave a
  token without an active signature, because the database will not let it.

  RESUME IS THE DEFAULT, NOT A FEATURE. The work remaining is defined by the data
  ("ACTIVE tokens with no active signature under the target algorithm") rather than by a
  cursor or a progress file. Kill the runner at any point and re-running converges; run two
  copies and they cannot double-write. There is no state to corrupt because there is no state.

The ordering rule this module enforces is the one that actually protects holders:

  DEPRECATION IS A SECOND PASS, AND IT IS REFUSED WHILE ANY TOKEN IS UNMIGRATED. The old
  signature keeps verifying until its deprecation_date; that window IS the migration. Marking
  the old algorithm deprecated token-by-token as you go would leave a population where some
  credentials verify only under an algorithm that deployed verifiers may not have yet, which
  is the outage the window exists to prevent. So `deprecate_superseded` refuses to run while
  `pending_count` is non-zero.

See docs/operator/QUANTUM-EVENT.md for the runbook this module implements.
"""
from __future__ import annotations

import time

try:                                     # the app package and the flat layout both import it
    from polaris_web import pqc_signing  # type: ignore
except ImportError:                      # pragma: no cover - exercised by the flat layout
    import pqc_signing                   # type: ignore


class MigrationRefused(Exception):
    """A migration step was refused because running it would leave holders worse off."""


# The population a migration is responsible for: an ACTIVE credential whose holder expects it
# to verify. Nothing else is re-signed. A REVOKED or EXPIRED token keeps its historical
# signatures exactly as they were, because rewriting the signatures of a credential that is no
# longer valid would be editing the audit-of-record to say something that was never true.
_POPULATION = "IdentityToken t WHERE t.status = 'ACTIVE'"
_UNMIGRATED = (
    "NOT EXISTS (SELECT 1 FROM TokenSignature s WHERE s.token_id = t.token_id "
    "AND s.algorithm_id = %s AND (s.deprecation_date IS NULL "
    "OR s.deprecation_date > CURRENT_TIMESTAMP))")


def algorithm_row(conn, algorithm):
    """The CryptographicAlgorithm row for an id or a name, or None.

    Resolving by NAME matters for a migration: the operator is acting on "we are moving to
    ML-DSA-87", and an off-by-one in a numeric id would re-sign a population under the wrong
    parameter set with no error anywhere."""
    with conn.cursor() as cur:
        if isinstance(algorithm, int) or (isinstance(algorithm, str) and algorithm.isdigit()):
            cur.execute("SELECT algorithm_id, name, deprecation_date FROM CryptographicAlgorithm "
                        "WHERE algorithm_id = %s", (int(algorithm),))
        else:
            cur.execute("SELECT algorithm_id, name, deprecation_date FROM CryptographicAlgorithm "
                        "WHERE name = %s", (algorithm,))
        return cur.fetchone()


def resolve_target(conn, algorithm):
    """(algorithm_id, name) for a migration target, or a refusal explaining why not."""
    row = algorithm_row(conn, algorithm)
    if row is None:
        raise MigrationRefused(f"no such algorithm: {algorithm!r}")
    row_id, name = row["algorithm_id"], row["name"]
    if row["deprecation_date"] is not None:
        raise MigrationRefused(
            f"{name} is itself deprecated; migrating a population ONTO a deprecated algorithm "
            "would have to be undone immediately")
    return row_id, name


def pending_count(conn, target_algorithm_id) -> int:
    """ACTIVE credentials with no active signature under the target algorithm."""
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) AS n FROM {_POPULATION} AND {_UNMIGRATED}",
                    (target_algorithm_id,))
        return cur.fetchone()["n"]


def population_count(conn) -> int:
    with conn.cursor() as cur:
        cur.execute(f"SELECT count(*) AS n FROM {_POPULATION}")
        return cur.fetchone()["n"]


def migrate_batch(conn, target_algorithm_id, algorithm_name, batch_size=500):
    """Re-sign up to `batch_size` unmigrated credentials. Returns a timing/count dict.

    Timings are split into signing and database because they scale differently and an operator
    planning a national migration needs to know which one they are buying more of."""
    from psycopg2.extras import execute_values
    import psycopg2

    t0 = time.monotonic()
    with conn.cursor() as cur:
        # FOR UPDATE SKIP LOCKED so N runners divide the population without coordinating and
        # without two of them signing the same token: the wasted work of a duplicate signature
        # is small, but at population scale it is the difference between N workers and N/2.
        cur.execute(
            f"SELECT t.token_id, t.token_value FROM {_POPULATION} AND {_UNMIGRATED} "
            "ORDER BY t.token_id LIMIT %s FOR UPDATE OF t SKIP LOCKED",
            (target_algorithm_id, batch_size))
        rows = cur.fetchall()
    t_select = time.monotonic()
    if not rows:
        conn.rollback()
        return {"selected": 0, "signed": 0, "written": 0, "sign_seconds": 0.0,
                "db_seconds": 0.0, "seconds": time.monotonic() - t0}

    signed = []
    for row in rows:
        sig, label, pub = pqc_signing.signature_for_migration(row["token_value"], algorithm_name)
        signed.append((row["token_id"], target_algorithm_id, psycopg2.Binary(sig), pub))
    t_sign = time.monotonic()

    with conn.cursor() as cur:
        # ON CONFLICT DO NOTHING: another runner may have won this token between the select
        # and here. The unique constraint decides, and the loser simply wrote nothing.
        #
        # RETURNING with fetch=True rather than cur.rowcount. execute_values splits its
        # argument into pages (100 rows by default) and issues one statement per page, so
        # rowcount reports only the LAST page: a 250-row batch reported 100 written. An
        # operator running a national migration would have been reading a number that
        # undercounts by the page size, and the scale drill is what caught it.
        rows = execute_values(
            cur,
            "INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, "
            "signing_public_key_hex) VALUES %s "
            "ON CONFLICT (token_id, algorithm_id) DO NOTHING RETURNING signature_id",
            signed, fetch=True)
        written = len(rows)
    conn.commit()
    t_end = time.monotonic()
    return {
        "selected": len(rows),
        "signed": len(signed),
        "written": written,
        "sign_seconds": t_sign - t_select,
        "db_seconds": (t_select - t0) + (t_end - t_sign),
        "seconds": t_end - t0,
    }


def migrate_population(conn, target_algorithm_id, algorithm_name, batch_size=500,
                       limit=None, progress=None):
    """Re-sign every unmigrated ACTIVE credential. Resumable: re-running finishes the job.

    `limit` caps the number of credentials re-signed in this invocation, which is how a
    migration is run inside a maintenance window without holding a lock on the rest of the
    population. `progress` is called with the running totals after each batch."""
    totals = {"batches": 0, "written": 0, "signed": 0, "sign_seconds": 0.0,
              "db_seconds": 0.0, "seconds": 0.0}
    t0 = time.monotonic()
    while True:
        remaining = None if limit is None else limit - totals["signed"]
        if remaining is not None and remaining <= 0:
            break
        size = batch_size if remaining is None else min(batch_size, remaining)
        batch = migrate_batch(conn, target_algorithm_id, algorithm_name, size)
        if batch["selected"] == 0:
            break
        totals["batches"] += 1
        for key in ("written", "signed", "sign_seconds", "db_seconds"):
            totals[key] += batch[key]
        totals["seconds"] = time.monotonic() - t0
        if progress is not None:
            progress(totals, batch)
    totals["seconds"] = time.monotonic() - t0
    return totals


def deprecate_superseded(conn, target_algorithm_id, grace_seconds=0):
    """Close the migration window: deprecate every OTHER active signature on migrated tokens.

    Refused while any ACTIVE credential still lacks a signature under the target algorithm.
    That refusal is the whole safety property of this module. Deprecating as you go would
    produce a population where some credentials verify only under an algorithm that fielded
    verifiers may not support yet, and the holder finds out at a border, not the operator at a
    console. The old signature keeping its validity until every credential has a new one IS
    the migration window."""
    pending = pending_count(conn, target_algorithm_id)
    if pending:
        raise MigrationRefused(
            f"{pending} ACTIVE credential(s) still have no signature under the target "
            "algorithm. Deprecating the old one now would leave those holders with a "
            "credential that verifies under nothing. Finish the migration first")
    with conn.cursor() as cur:
        # +1 second at minimum: deprecation_after_signed refuses a signature deprecated at the
        # instant it was created, and a row migrated in this same second would hit that CHECK.
        cur.execute(
            "UPDATE TokenSignature s SET deprecation_date = "
            "CURRENT_TIMESTAMP + (%s || ' seconds')::INTERVAL "
            "FROM IdentityToken t "
            "WHERE s.token_id = t.token_id AND t.status = 'ACTIVE' "
            "AND s.algorithm_id <> %s AND s.deprecation_date IS NULL",
            (max(int(grace_seconds), 1), target_algorithm_id))
        deprecated = cur.rowcount
    conn.commit()
    return deprecated


def verifiability_report(conn):
    """Every ACTIVE credential, and whether it has at least one signature that verifies today.

    The number a migration is judged by. It must be zero unverifiable at every instant, before
    the migration, during it, and after the window closes."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT count(*) AS total, "
            "count(*) FILTER (WHERE NOT EXISTS ("
            "  SELECT 1 FROM TokenSignature s WHERE s.token_id = t.token_id "
            "  AND (s.deprecation_date IS NULL OR s.deprecation_date > CURRENT_TIMESTAMP))"
            ") AS unverifiable "
            f"FROM {_POPULATION}")
        row = cur.fetchone()
    return {"total": row["total"], "unverifiable": row["unverifiable"]}

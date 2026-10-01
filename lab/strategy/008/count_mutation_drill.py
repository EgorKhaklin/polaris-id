# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Mutate the population counts' triggers and fold one way at a time; each must fail a test.

    POLARIS_DB_NAME=<a loaded scratch database> python3 lab/strategy/008/count_mutation_drill.py

Lab evidence for record 008. Foreground only: the tree is mutated while a mutant runs and is
restored from a backup in a `finally`; the fold's mutants are applied to the database with psql
(the test reload does not re-run 05_procedures.sql) and the original re-applied after each.
"""
import os, pathlib, shutil, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[3]
TRIG = ROOT / "polaris_sql" / "06_triggers.sql"
PROC = ROOT / "polaris_sql" / "05_procedures.sql"
TMPD = pathlib.Path(tempfile.mkdtemp(prefix="polaris-count-drill-"))
DB = os.environ.get("POLARIS_DB_NAME") or sys.exit("set POLARIS_DB_NAME to a loaded scratch database")
TESTS = ["test_app.PopulationScaleTests.test_the_counts_equal_a_full_count_after_every_kind_of_change",
         "test_app.PopulationScaleTests.test_a_fresh_load_starts_with_exact_counts",
         "test_app.ConcurrencyTests.test_a_fold_skips_while_a_recount_holds_the_lock"]
MUTANTS = {
    "status update ignores the rows it removed":
        ("SELECT issuing_agency_id AS agency_id, status, -1 AS d FROM old_rows\n",
         "SELECT issuing_agency_id AS agency_id, status, 0 AS d FROM old_rows\n"),
    "a new signature on an active credential is not counted":
        ("""        SELECT 'live_signature', t.issuing_agency_id, n.algorithm_id::TEXT, count(*)
          FROM new_rows n JOIN IdentityToken t ON t.token_id = n.token_id
         WHERE n.deprecation_date IS NULL AND t.status = 'ACTIVE'
         GROUP BY t.issuing_agency_id, n.algorithm_id;""",
         """        SELECT 'live_signature', t.issuing_agency_id, n.algorithm_id::TEXT, count(*)
          FROM new_rows n JOIN IdentityToken t ON t.token_id = n.token_id
         WHERE false
         GROUP BY t.issuing_agency_id, n.algorithm_id;"""),
    "a deprecated signature stays counted":
        ("""                SELECT t.issuing_agency_id, n.algorithm_id, 1
                  FROM new_rows n JOIN IdentityToken t ON t.token_id = n.token_id
                 WHERE n.deprecation_date IS NULL AND t.status = 'ACTIVE') c""",
         """                SELECT t.issuing_agency_id, n.algorithm_id, 1
                  FROM new_rows n JOIN IdentityToken t ON t.token_id = n.token_id
                 WHERE t.status = 'ACTIVE') c"""),
    "deletes are not counted":
        ("""        SELECT 'credential_status', issuing_agency_id, status, -count(*)
          FROM old_rows GROUP BY issuing_agency_id, status;""",
         """        SELECT 'credential_status', issuing_agency_id, status, -count(*)
          FROM old_rows WHERE false GROUP BY issuing_agency_id, status;"""),
    "the load does not recount":
        ("SELECT uc_rebuild_population_counts();\n", "SELECT 1;\n"),
}
# Mutants of the fold live in 05_procedures.sql, which the test reload does not re-run: each is
# applied to the drill database with psql, and the original re-applied after it.
PROC_MUTANTS = {
    "a fold drops changes to an existing total":
        ("         WHERE c.facet = s.facet AND c.agency_id = s.agency_id AND c.item = s.item AND s.n <> 0\n        RETURNING 1\n    ), inserted AS (",
         "         WHERE false\n        RETURNING 1\n    ), inserted AS ("),
    "a fold drops new totals":
        ("         WHERE s.n <> 0\n           AND NOT EXISTS (SELECT 1 FROM PopulationCount c",
         "         WHERE false\n           AND NOT EXISTS (SELECT 1 FROM PopulationCount c"),
}
env = dict(os.environ, POLARIS_DB_HOST=os.environ.get("POLARIS_DB_HOST", "localhost"), POLARIS_DB_NAME=DB,
           POLARIS_TEST_RELOAD_VIA="direct", POLARIS_PQC_PROFILE="placeholder",
           POLARIS_SECRET_KEY="drill-secret-key-32-bytes-long-xxxxx", POLARIS_STATE_DIR="/tmp/polaris-state",
           POLARIS_TEST_REDIS_URL="redis://localhost:6399/0", PYTHONUNBUFFERED="1")
py = os.environ.get("POLARIS_TEST_PYTHON") or sys.executable

def apply_procs():
    subprocess.run(["psql", "-v", "ON_ERROR_STOP=1", "-q", "-h", env["POLARIS_DB_HOST"], "-d", DB,
                    "-f", str(PROC)], check=True, capture_output=True)


def run_test():
    r = subprocess.run([py, "-m", "unittest"] + TESTS, cwd=ROOT / "polaris_web", env=env, capture_output=True, text=True)
    return r.returncode, (r.stdout + r.stderr)[-600:]

results = []
backups = {TRIG: TMPD / "06_triggers.sql.drill-backup", PROC: TMPD / "05_procedures.sql.drill-backup"}
for src, bak in backups.items():
    shutil.copyfile(src, bak)
try:
    code, out = run_test()
    print("control (unmutated): %s" % ("PASS" if code == 0 else "FAIL\n" + out))
    if code != 0:
        sys.exit("the control must pass")
    for target, mutants in ((TRIG, MUTANTS), (PROC, PROC_MUTANTS)):
        for name, (old, new) in mutants.items():
            text = backups[target].read_text()
            assert text.count(old) == 1, "mutant site not unique: " + name
            target.write_text(text.replace(old, new))
            if target is PROC:
                apply_procs()
            code, out = run_test()
            results.append((name, code != 0))
            print("%-58s %s" % (name, "KILLED" if code != 0 else "SURVIVED"))
            shutil.copyfile(backups[target], target)
            if target is PROC:
                apply_procs()
finally:
    for src, bak in backups.items():
        shutil.copyfile(bak, src)
    apply_procs()
print("restored:", all(src.read_text() == bak.read_text() for src, bak in backups.items()))
print("%d of %d killed" % (sum(k for _, k in results), len(results)))

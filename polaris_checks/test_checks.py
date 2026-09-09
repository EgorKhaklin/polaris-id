"""
test_checks.py — tests for the flat check layer.

Two things matter: (1) every check runs against the real repo without crashing
and returns Findings; (2) each check actually discriminates — it FAILs on a
broken fixture and passes (OK) on the real tree. The discrimination tests are
what make these checks trustworthy (detection correctness, tested — the gap the
old apparatus never closed).

Run: python3 -m pytest polaris_checks/test_checks.py
"""

from __future__ import annotations

import pathlib

import pytest

from polaris_checks import checks
from polaris_checks.checks import Finding, run_all

REPO = pathlib.Path(__file__).resolve().parent.parent


def test_run_all_clean_on_real_repo():
    findings = run_all(REPO)
    assert findings, "run_all must produce findings"
    assert all(isinstance(f, Finding) for f in findings)
    fails = [f for f in findings if f.level == "FAIL"]
    assert fails == [], f"the real repo must pass every check; failures: {[str(f) for f in fails]}"


def test_every_check_returns_findings_and_does_not_crash():
    for check in checks.CHECKS:
        out = check(REPO)
        assert isinstance(out, list) and out, f"{check.__name__} returned no findings"
        assert all(isinstance(f, Finding) for f in out)


def test_csp_check_fails_on_unsafe_inline(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "security.py").write_text(
        "CSP = \"script-src 'self' 'unsafe-inline'\"\n")
    out = checks.check_csp_forbids_unsafe_inline(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when CSP enables 'unsafe-inline' for scripts"


def test_fk_cascade_check_scans_migrations(tmp_path):
    # A cascade smuggled into a migration (not just 01_schema.sql) must be caught.
    (tmp_path / "polaris_sql").mkdir()
    (tmp_path / "polaris_sql" / "migrations").mkdir()
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text("CREATE TABLE A (id SERIAL);\n")
    (tmp_path / "polaris_sql" / "migrations" / "y.up.sql").write_text(
        "ALTER TABLE B ADD CONSTRAINT fk FOREIGN KEY (a) REFERENCES A(id) ON DELETE CASCADE;\n")
    out = checks.check_no_fk_cascade(tmp_path)
    assert out[0].level == "FAIL", "must FAIL on a cascade in a migration, not only 01_schema.sql"


def test_fk_cascade_check_fails_on_cascade(tmp_path):
    (tmp_path / "polaris_sql").mkdir()
    (tmp_path / "polaris_sql" / "x.sql").write_text(
        "ALTER TABLE T ADD FOREIGN KEY (a) REFERENCES U(id) ON DELETE CASCADE;\n")
    out = checks.check_no_fk_cascade(tmp_path)
    assert out[0].level == "FAIL", "must FAIL on a destructive ON DELETE CASCADE"


def test_gitignore_trailing_comment_check_fails(tmp_path):
    (tmp_path / ".gitignore").write_text("polaris.env   # operator secrets\n")
    out = checks.check_gitignore_no_trailing_comments(tmp_path)
    assert out[0].level == "FAIL", "must FAIL on a trailing inline comment"
    # and the secrets check must catch the now-disabled pattern
    out2 = checks.check_secrets_file_ignored(tmp_path)
    assert out2[0].level == "FAIL", "trailing comment leaves polaris.env un-ignored"


def test_changelog_version_mismatch_fails(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "__version__.py").write_text('__version__ = "9.99"\n')
    (tmp_path / "CHANGELOG.md").write_text("## v1.00 — old\n")
    out = checks.check_changelog_matches_version(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when CHANGELOG top != __version__"


def test_debug_artifact_check_fails(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "x.py").write_text("def f():\n    breakpoint()\n")
    out = checks.check_no_debug_artifacts(tmp_path)
    assert out[0].level == "FAIL", "must FAIL on a breakpoint() in source"


def test_pqc_wired_check_fails_when_issuance_bypasses_signing_module(tmp_path):
    # Single issuance accepts the signature; bulk issuance stores a STAGED
    # signature and refuses an unsigned row (v9.257); the app routes through the
    # signing module.
    PROC = (
        "CREATE OR REPLACE FUNCTION uc1_issue_and_activate(p_token_value VARCHAR, "
        "p_signature_bytes BYTEA DEFAULT NULL) RETURNS INTEGER AS $$ SELECT 1 $$;\n"
        "CREATE OR REPLACE PROCEDURE uc_bulk_issue(p_batch_id INTEGER)\n"
        "LANGUAGE plpgsql AS $$\nBEGIN\n"
        "  IF EXISTS (SELECT 1 FROM BulkEnrollmentStaging WHERE batch_id=p_batch_id AND signature_bytes IS NULL) THEN\n"
        "    RAISE EXCEPTION 'unsigned' USING ERRCODE='invalid_parameter_value'; END IF;\n"
        "  INSERT INTO TokenSignature (token_id, algorithm_id, signature_bytes, signing_public_key_hex)\n"
        "    SELECT token_id, 1, signature_bytes, signing_public_key_hex FROM BulkEnrollmentStaging WHERE batch_id=p_batch_id;\n"
        "END $$;\n")
    APP = ("import pqc_signing\n"
           "sig = pqc_signing.signature_with_key_for_token(tv)\n"
           "@app.route('/api/tokens/<int:tok_id>/verify')\n"
           "def api_token_verify(tok_id):\n"
           "    ok = pqc_signing.verify_stored_signature(tv, sig, pk, witnesses='single')\n"
           "    row = query('SELECT status, now() AS as_of ...', (tok_id,), fetch='one', primary=True)\n"
           "    status = row['status']; as_of = row['as_of'].isoformat()\n"
           "    return jsonify(signature_valid=ok, signature_cacheable=True, status=status,\n"
           "                   status_source='primary', currently_authoritative=(status=='ACTIVE'),\n"
           "                   as_of=as_of, max_staleness_seconds=0, usable=(ok and status=='ACTIVE'))\n")
    SCHEMA = ("CREATE TABLE IF NOT EXISTS BulkEnrollmentStaging (\n"
              "  staging_id BIGSERIAL PRIMARY KEY, batch_id INTEGER, token_value VARCHAR(128) NOT NULL,\n"
              "  signature_bytes BYTEA, signing_public_key_hex TEXT\n);\n")
    # issuance two-witnesses before persisting, REQUIRING the witness; verify-at-use is single-witness.
    PQC = ("def signature_with_key_for_token(tv):\n"
           "    if not second_witness_available(): raise SigningError('need the second witness')\n"
           "    r = sign(tv)\n"
           "    if not verify_both(tv, r.sig, r.pk, require_witness=True): raise SigningError('two-witness self-verify failed')\n"
           "    return r.sig, r.label, r.pk\n")
    good = {"polaris_sql/05_procedures.sql": PROC, "polaris_web/app.py": APP,
            "polaris_sql/01_schema.sql": SCHEMA, "polaris_web/pqc_signing.py": PQC}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)

    write()
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # single issuance drops the signature param
    write({"polaris_sql/05_procedures.sql": PROC.replace("p_signature_bytes BYTEA DEFAULT NULL", "")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL without p_signature_bytes"
    # the app never routes issuance through the module
    write({"polaris_web/app.py": "import pqc_signing  # imported, never used\n"})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when the app never signs"
    # bulk FABRICATES a placeholder signature instead of storing the staged one
    write({"polaris_sql/05_procedures.sql": PROC.replace(
        "SELECT token_id, 1, signature_bytes, signing_public_key_hex FROM BulkEnrollmentStaging WHERE batch_id=p_batch_id;",
        "SELECT token_id, 1, ('BULK_ISSUE_' || token_id::TEXT)::BYTEA, NULL FROM BulkEnrollmentStaging;")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when bulk fabricates a placeholder signature"
    # bulk does not refuse an unsigned row
    write({"polaris_sql/05_procedures.sql": PROC.replace("AND signature_bytes IS NULL", "AND 1=0")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when bulk does not refuse unsigned rows"
    # the staging table has no signature column
    write({"polaris_sql/01_schema.sql": SCHEMA.replace("signature_bytes BYTEA,", "")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when staging cannot carry a signature"
    # v9.258: issuance weakened to a single witness (the strict self-check dropped)
    write({"polaris_web/pqc_signing.py": PQC.replace("verify_both", "verify")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when issuance stops two-witnessing"
    # the verify-at-use endpoint is missing
    write({"polaris_web/app.py": APP.replace("/api/tokens/<int:tok_id>/verify", "/api/tokens/<int:tok_id>/other")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL without the verify-at-use endpoint"
    # the verify endpoint uses the slow two-witness path (not the throughput single-witness)
    write({"polaris_web/app.py": APP.replace("witnesses='single'", "witnesses='both'")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when verify-at-use is not single-witness"
    # v9.264: issuance stops REQUIRING the second witness (silently degrades to one)
    write({"polaris_web/pqc_signing.py": PQC.replace(", require_witness=True", "")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when issuance does not require the witness"
    write({"polaris_web/pqc_signing.py": PQC.replace(
        "    if not second_witness_available(): raise SigningError('need the second witness')\n", "")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL without the up-front witness-availability refusal"
    # v9.264: the verify endpoint decides `usable` on a possibly-stale replica status
    write({"polaris_web/app.py": APP.replace(", fetch='one', primary=True", ", fetch='one'")})
    assert checks.check_pqc_signing_wired(tmp_path)[0].level == "FAIL", "must FAIL when usable is not decided on primary-fresh status"


def test_verification_load_certified_check_discriminates(tmp_path):
    # P2.9 (v9.259): the HA drills hold an authenticated verify-at-use load. The
    # good fixture has the load generator (strict accounting + --once), its test,
    # the coverage wiring, and both drills asserting on it (rolling = zero drops,
    # failover = recovery after each scenario + a served floor).
    GEN = ("def classify(status):\n"
           "    if status == 200: return \"served\", \"ok\"\n"
           "    if status == 429: return \"tolerated\", \"http_429\"\n"
           "    return \"drop\", \"transport\"\n"
           "# GET /api/tokens/<id>/verify after POST /login; supports --once\n")
    TEST = "def test_classify(): pass\n# also covers run_once\n"
    COV = 'run "$ROOT/scripts" unittest test_verify_load\n'
    ROLLING = ('python3 scripts/polaris-verify-load.py --out "$WORK/verify.json"\n'
               '# assert 0 verification requests dropped across the rollover\n')
    FAILOVER = ('python3 scripts/polaris-verify-load.py --out "$WORK/verify.json"\n'
                'verify_recovered || fail "1"\n'
                'verify_recovered || fail "2"\n'
                'verify_recovered || fail "3"\n'
                'verify_recovered || fail "4"\n'
                'python3 -c \'assert s["served"] >= 200\'\n')
    good = {"scripts/polaris-verify-load.py": GEN, "scripts/test_verify_load.py": TEST,
            "scripts/polaris-coverage.sh": COV, "scripts/polaris-rolling-drill.sh": ROLLING,
            "scripts/polaris-failover-drill.sh": FAILOVER}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)

    write()
    assert checks.check_verification_load_certified(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # the load generator loses its strict accounting (429 no longer tolerated-not-dropped)
    write({"scripts/polaris-verify-load.py": GEN.replace('    if status == 429: return "tolerated", "http_429"\n', "")})
    assert checks.check_verification_load_certified(tmp_path)[0].level == "FAIL", "must FAIL without strict accounting"
    # the recovery probe is gone
    write({"scripts/polaris-verify-load.py": GEN.replace("--once", "--never")})
    assert checks.check_verification_load_certified(tmp_path)[0].level == "FAIL", "must FAIL without a --once recovery probe"
    # the generator has no test
    write({"scripts/test_verify_load.py": "def test_nothing(): pass\n"})
    assert checks.check_verification_load_certified(tmp_path)[0].level == "FAIL", "must FAIL when run_once is untested"
    # coverage does not run the test
    write({"scripts/polaris-coverage.sh": "run other\n"})
    assert checks.check_verification_load_certified(tmp_path)[0].level == "FAIL", "must FAIL when the test is not under coverage"
    # the rolling drill drops its verification assertion
    write({"scripts/polaris-rolling-drill.sh": "python3 scripts/polaris-verify-load.py --out x\n"})
    assert checks.check_verification_load_certified(tmp_path)[0].level == "FAIL", "must FAIL when the rollover drops the verify assertion"
    # the failover drill probes recovery after only three of the four scenarios
    write({"scripts/polaris-failover-drill.sh": FAILOVER.replace('verify_recovered || fail "4"\n', "")})
    assert checks.check_verification_load_certified(tmp_path)[0].level == "FAIL", "must FAIL when a failover scenario has no recovery probe"
    # the failover drill drops the served floor
    write({"scripts/polaris-failover-drill.sh": FAILOVER.replace('assert s["served"] >= 200', "pass")})
    assert checks.check_verification_load_certified(tmp_path)[0].level == "FAIL", "must FAIL when the served floor is gone"


def test_atlas_rollups_prune_check_discriminates(tmp_path):
    # P2.14 S5 (v9.260): the roll-ups must window on COALESCE(p_since,'-infinity')
    # so a concrete since prunes partitions under the generic plan. The good
    # fixture uses the pruning-friendly predicate; each perturbation reintroduces
    # a shape that silently defeats pruning.
    GOOD = ("CREATE FUNCTION atlas_breakdown(p_since TIMESTAMP) RETURNS TABLE(n BIGINT) AS $$\n"
            "  SELECT count(*) FROM VerificationEvent ve\n"
            "  WHERE (ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))\n"
            "  GROUP BY 1;\n$$ LANGUAGE sql STABLE;\n")

    def write(body):
        f = tmp_path / "polaris_sql" / "11_atlas.sql"
        f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)

    write(GOOD)
    assert checks.check_atlas_rollups_prune(tmp_path)[0].level == "OK", "must PASS on the pruning-friendly fixture"
    # the OR-NULL guard is back (defeats generic-plan pruning)
    write(GOOD.replace("(ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))",
                       "(p_since IS NULL OR ve.event_timestamp >= p_since)"))
    assert checks.check_atlas_rollups_prune(tmp_path)[0].level == "FAIL", "must FAIL on the p_since IS NULL OR guard"
    # the window is reached through a CTE column, not the parameter
    write(GOOD.replace("(ve.event_timestamp >= COALESCE(p_since, '-infinity'::timestamp))",
                       "(ve.event_timestamp >= params.t_start)"))
    assert checks.check_atlas_rollups_prune(tmp_path)[0].level == "FAIL", "must FAIL on the params.t_start indirection"
    # no COALESCE window predicate present at all
    write("CREATE FUNCTION atlas_breakdown() RETURNS INTEGER AS $$ SELECT 1 $$ LANGUAGE sql;\n")
    assert checks.check_atlas_rollups_prune(tmp_path)[0].level == "FAIL", "must FAIL when the pruning-friendly predicate is absent"


def test_sim_mode_gated_check_discriminates(tmp_path):
    # P2.14 S4 (v9.261): the live-simulation mode must be triple-gated. The good
    # fixture has all three gates; each perturbation removes one.
    APP = ("SIM_MODE = _env_flag('POLARIS_SIM_MODE', False) and not _PRODUCTION\n"
           "@app.route('/api/sim/tick', methods=['POST'])\n"
           "def api_sim_tick():\n"
           "    if not SIM_MODE:\n"
           "        abort(404)\n"
           "    return jsonify(ok=True)\n")
    INIT = ("def assert_expendable():\n"
            "    if os.environ.get('POLARIS_ENV','').lower() == 'production':\n"
            "        raise SimulationRefused('refuses production')\n")
    EVENTS = "def run_stream(conn):\n    assert_expendable()\n    return 1\n"
    LOAD = "def build_nation(conn, plan):\n    assert_expendable()\n    return 1\n"
    good = {"polaris_web/app.py": APP, "polaris_sim/__init__.py": INIT,
            "polaris_sim/events.py": EVENTS, "polaris_sim/load.py": LOAD}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)

    write()
    assert checks.check_sim_mode_gated(tmp_path)[0].level == "OK", "must PASS on the triple-gated fixture"
    # SIM_MODE no longer force-off in production
    write({"polaris_web/app.py": APP.replace(" and not _PRODUCTION", "")})
    assert checks.check_sim_mode_gated(tmp_path)[0].level == "FAIL", "must FAIL when SIM_MODE is not force-off in production"
    # the tick route no longer 404s when the gate is off
    write({"polaris_web/app.py": APP.replace("        abort(404)\n", "        pass\n")})
    assert checks.check_sim_mode_gated(tmp_path)[0].level == "FAIL", "must FAIL when the route does not 404 off the gate"
    # the writer no longer refuses production
    write({"polaris_sim/__init__.py": INIT.replace("production", "prod-typo")})
    assert checks.check_sim_mode_gated(tmp_path)[0].level == "FAIL", "must FAIL when assert_expendable does not refuse production"
    # run_stream stops calling the gate
    write({"polaris_sim/events.py": "def run_stream(conn):\n    return 1\n"})
    assert checks.check_sim_mode_gated(tmp_path)[0].level == "FAIL", "must FAIL when run_stream skips assert_expendable()"


def test_ui_drill_check_discriminates(tmp_path):
    # P2.14 S4 (v9.262): the headless-browser harness must drive the sim and
    # ASSERT growth, and the live view must bypass the aggregate cache under
    # SIM_MODE. The good fixture has all of it; each perturbation removes one.
    PY = ("from playwright.sync_api import sync_playwright\n"
          "toggle = page.query_selector('[data-atlas-sim-toggle]')\n"
          "# read the sim counter (streamed) and the Overview aggregate\n"
          "n = page.query_selector('[data-ov-kpi=\"volume\"]')\n"
          "if not (last > first): fail('counter did not climb')\n"
          "if not (kpi_after > kpi_before): fail('aggregate did not grow')\n")
    SH = ('#!/usr/bin/env bash\n'
          'POLARIS_SIM_MODE=1 python -m flask run &\n'
          'python -m playwright install chromium\n')
    APP = ("def _atlas_cache_get(key):\n"
           "    if _ATLAS_CACHE_TTL_SECONDS <= 0:\n"
           "        return None\n"
           "    if SIM_MODE:\n"
           "        return None\n"
           "    return _atlas_cache.get(key)\n")
    CI = "jobs:\n  ui-drill:\n    steps:\n      - run: bash scripts/polaris-ui-drill.sh\n"
    good = {"scripts/polaris-ui-drill.py": PY, "scripts/polaris-ui-drill.sh": SH,
            "polaris_web/app.py": APP, ".github/workflows/ci.yml": CI}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)

    write()
    assert checks.check_ui_drill(tmp_path)[0].level == "OK", "must PASS on the full harness fixture"
    # CI does not run the drill
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    steps: []\n"})
    assert checks.check_ui_drill(tmp_path)[0].level == "FAIL", "must FAIL when ci.yml does not run the UI drill"
    # the harness no longer uses a real browser
    write({"scripts/polaris-ui-drill.py": PY.replace("playwright", "requests")})
    assert checks.check_ui_drill(tmp_path)[0].level == "FAIL", "must FAIL without a real browser (playwright)"
    # it screenshots but no longer asserts the counter climbs
    write({"scripts/polaris-ui-drill.py": PY.replace("if not (last > first): fail('counter did not climb')\n", "")})
    assert checks.check_ui_drill(tmp_path)[0].level == "FAIL", "must FAIL when it does not assert the counter climbs"
    # the wrapper does not boot SIM_MODE
    write({"scripts/polaris-ui-drill.sh": SH.replace("POLARIS_SIM_MODE=1 ", "")})
    assert checks.check_ui_drill(tmp_path)[0].level == "FAIL", "must FAIL when the wrapper does not boot SIM_MODE"
    # the live view no longer bypasses the aggregate cache under SIM_MODE
    write({"polaris_web/app.py": APP.replace("    if SIM_MODE:\n        return None\n", "")})
    assert checks.check_ui_drill(tmp_path)[0].level == "FAIL", "must FAIL when SIM_MODE does not bypass the aggregate cache"


def test_signing_key_generation_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    sh = scripts / "polaris-generate-secrets.sh"

    GOOD = (
        "write_signing_key_if_missing() {\n"
        "  if [[ -s \"${target}\" ]]; then return 0; fi\n"
        "  gen_py='import sys, io\\n_saved=sys.stdout\\nsys.stdout = io.StringIO()\\n"
        "import pqc_signing\\nsys.stdout=_saved\\nimport json\\nprint(json.dumps(pqc_signing.generate_keypair()))'\n"
        "  json=$(docker run --rm polaris-app:prod python -c \"${gen_py}\")\n"
        "  printf '%s' \"$json\" | python3 -c \"import sys,json; d=json.load(sys.stdin); "
        "assert d.get('algorithm')=='ML-DSA-65' and d.get('secret_key_hex') and d.get('public_key_hex')\"\n"
        "}\n")

    # 1. Naive capture (no stdout swallow, no validation) -> FAIL.
    sh.write_text("write() {\n  json=$(docker run polaris-app:prod python -c "
                  "\"import pqc_signing, json; print(json.dumps(pqc_signing.generate_keypair()))\")\n}\n")
    assert checks.check_signing_key_generation(tmp_path)[0].level == "FAIL", \
        "must FAIL when the generator does not swallow the import banner"

    # 2. Swallows stdout but does NOT validate the JSON -> FAIL.
    sh.write_text("g() {\n  sys.stdout = io.StringIO()\n"
                  "  json=$(docker run polaris-app:prod python -c \"import pqc_signing, json; "
                  "print(json.dumps(pqc_signing.generate_keypair()))\")\n}\n")
    assert checks.check_signing_key_generation(tmp_path)[0].level == "FAIL", \
        "must FAIL when the captured key JSON is not validated before writing"

    # 3. Uses -e existence guard (empty files silently block regeneration) -> FAIL.
    sh.write_text(GOOD.replace('[[ -s "${target}" ]]', '[[ -e "${target}" ]]'))
    assert checks.check_signing_key_generation(tmp_path)[0].level == "FAIL", \
        "must FAIL when an existence guard uses -e instead of -s"

    # 4. Swallows banner + validates + -s guard -> OK.
    sh.write_text(GOOD)
    assert checks.check_signing_key_generation(tmp_path)[0].level == "OK", \
        "must PASS when the generator swallows the banner, validates, and uses -s"


def test_c2_zk_null_check_fails_without_constraint(tmp_path):
    (tmp_path / "polaris_sql").mkdir()
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(
        "CREATE TABLE VerificationEvent (token_id INTEGER, disclosure_level VARCHAR);\n")
    out = checks.check_c2_zk_token_null(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when the ZK->token_id NULL CHECK is absent"


def test_c4_atomic_login_check_fails_on_read_then_write(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "security.py").write_text(
        "n = read_count()\nexecute('UPDATE AppUser SET failed_login_count = %s', n + 1)\n")
    out = checks.check_c4_atomic_failed_login(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when the increment is not a single atomic UPDATE"


def test_c8_atlas_caps_check_fails_without_constants(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "app.py").write_text("# no atlas caps here\n")
    out = checks.check_c8_atlas_caps(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when atlas hard-cap constants are missing"
    # v9.248: the analytical-console category cap is part of C8 too.
    (tmp_path / "polaris_web" / "app.py").write_text(
        "_ATLAS_MAX_CLUSTERS=5000\n_ATLAS_MAX_POINTS=2000\n_ATLAS_MAX_EVENTS=500\n")
    out = checks.check_c8_atlas_caps(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when the category cap is missing"
    # v9.253: the Map v2 Regions cap joins C8.
    (tmp_path / "polaris_web" / "app.py").write_text(
        "_ATLAS_MAX_CLUSTERS=5000\n_ATLAS_MAX_POINTS=2000\n"
        "_ATLAS_MAX_EVENTS=500\n_ATLAS_MAX_CATEGORIES=50\n")
    out = checks.check_c8_atlas_caps(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when the regions cap is missing"
    (tmp_path / "polaris_web" / "app.py").write_text(
        "_ATLAS_MAX_CLUSTERS=5000\n_ATLAS_MAX_POINTS=2000\n"
        "_ATLAS_MAX_EVENTS=500\n_ATLAS_MAX_CATEGORIES=50\n_ATLAS_MAX_REGIONS=500\n")
    out = checks.check_c8_atlas_caps(tmp_path)
    assert out[0].level == "OK", "must PASS with all five caps present"


def test_c9_concurrency_check_fails_without_threading_tests(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "test_app.py").write_text("class FooTests:\n    pass\n")
    out = checks.check_c9_concurrency_threading(tmp_path)
    assert out[0].level == "FAIL", "must FAIL without a ConcurrencyTests class using threading"


def test_c10_no_money_check_fails_on_money_table(tmp_path):
    (tmp_path / "polaris_sql").mkdir()
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(
        "CREATE TABLE MonetaryClaim (id SERIAL, balance NUMERIC);\n")
    out = checks.check_c10_no_money_tables(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when the schema defines a monetary table"


def test_open_redirect_guard_fails_on_naive_guard(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    # The helper exists, but app.py still uses the naive '//'-only guard it was
    # meant to replace — the one the backslash trick (/\\host) slips past.
    (tmp_path / "polaris_web" / "security.py").write_text(
        "def is_safe_next_url(u):\n    return bool(u)\n")
    (tmp_path / "polaris_web" / "app.py").write_text(
        "next_url = request.args.get('next', '')\n"
        "if next_url.startswith('/') and not next_url.startswith('//'):\n"
        "    return redirect(next_url)\n")
    out = checks.check_open_redirect_guard(tmp_path)
    assert out[0].level == "FAIL", "must FAIL while the naive startswith('//') guard survives"


def test_cookie_secure_check_fails_when_opt_in_only(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "app.py").write_text(
        "app.config['SESSION_COOKIE_SECURE'] = "
        "os.environ.get('POLARIS_COOKIE_SECURE', '').lower() in ('1', 'true')\n")
    out = checks.check_cookie_secure_in_production(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when SESSION_COOKIE_SECURE is opt-in only"


def test_table_count_check_fails_on_doc_drift(tmp_path):
    (tmp_path / "polaris_sql").mkdir()
    (tmp_path / "docs").mkdir()
    # Schema with 2 tables.
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(
        "CREATE TABLE A (id SERIAL);\nCREATE TABLE B (id SERIAL);\n")
    arch = tmp_path / "docs" / "ARCHITECTURE-OVERVIEW.md"
    readme = tmp_path / "README.md"
    (tmp_path / "docs" / "reference").mkdir()
    (tmp_path / "docs" / "reference" / "DATA-MODEL.md").write_text("The schema is 2 tables.\n")

    # 1. ARCHITECTURE-OVERVIEW drift -> FAIL.
    arch.write_text("PostgreSQL 16. 27 tables, stored procedures.\n")
    readme.write_text("a working reference implementation: 2 schema tables.\n")
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "FAIL", \
        "must FAIL when the architecture-doc table count contradicts the schema"

    # 2. Architecture doc correct, but the README count drifts -> FAIL (now guarded).
    arch.write_text("PostgreSQL 16. 2 tables, stored procedures.\n")
    readme.write_text("a working reference implementation: 26 schema tables.\n")
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "FAIL", \
        "must FAIL when the README schema-table count drifts from the schema"

    # 3. Both match the schema -> OK.
    readme.write_text("a working reference implementation: 2 schema tables.\n")
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "OK", \
        "must PASS when both docs match the schema"

    # 4. First README count right, a LATER instance drifted -> FAIL.
    #    (v9.141 shipped exactly this: line 42 said 28, three later mentions
    #    said 26, and the old re.search-based check validated only the first.)
    readme.write_text("implementation: 2 schema tables.\n"
                      "... the diagram shows 26 tables in the schema box.\n")
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "FAIL", \
        "must FAIL when any later table-count instance drifts, not just the first"


def test_local_clock_check_fails_on_utcnow(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    (tmp_path / "polaris_web" / "app.py").write_text(
        "if epoch['valid_until'] < datetime.utcnow():\n    pass\n")
    out = checks.check_local_clock_convention(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when app.py compares boundaries against utcnow()"


def test_operator_script_argv_check_fails_without_validation(tmp_path):
    (tmp_path / "scripts").mkdir()
    # A purge script that interpolates --actor-user-id with no numeric guard.
    (tmp_path / "scripts" / "polaris-purge.sh").write_text(
        '#!/usr/bin/env bash\nACTOR_USER_ID="$2"\n'
        'psql -c "CALL uc_archive_purge(p_actor_user_id := ${ACTOR_USER_ID})"\n')
    for name in ("polaris-recover-admin.sh", "polaris-migrate.sh", "polaris-archive.sh"):
        (tmp_path / "scripts" / name).write_text("#!/usr/bin/env bash\n# no validation\n")
    out = checks.check_operator_scripts_validate_argv(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when an operator script interpolates argv without regex validation"


def test_migration_drift_check_fails_on_column_missing_from_schema(tmp_path):
    (tmp_path / "polaris_sql").mkdir()
    (tmp_path / "polaris_sql" / "migrations").mkdir()
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(
        "CREATE TABLE AppUser (user_id SERIAL PRIMARY KEY);\n")
    (tmp_path / "polaris_sql" / "migrations" / "x.up.sql").write_text(
        "ALTER TABLE AppUser ADD COLUMN secret_drift_col TEXT;\n")
    out = checks.check_no_migration_column_drift(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when a migration adds a column missing from 01_schema.sql"


def test_c6_atlas_zk_check_fails_when_zk_location_not_redacted(tmp_path):
    (tmp_path / "polaris_sql").mkdir()
    (tmp_path / "polaris_web").mkdir()
    # Atlas function that plots ZK location with no exclusion/redaction.
    (tmp_path / "polaris_sql" / "11_atlas.sql").write_text(
        "SELECT ve.latitude, ve.longitude, ve.requestor_location "
        "FROM VerificationEvent ve WHERE ve.latitude IS NOT NULL;\n")
    (tmp_path / "polaris_web" / "app.py").write_text(
        "SELECT ve.*, ve.requestor_location FROM VerificationEvent ve;\n")
    out = checks.check_c6_atlas_redacts_zk_location(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when ZK location is not excluded/redacted at the atlas read paths"

    # v9.253: a passing fixture exercises the three spatial exclusions (clusters,
    # points, hexbin), the hexbin- and jurisdiction-specific assertions, and the
    # recent-events redaction.
    HEX = ("CREATE OR REPLACE FUNCTION atlas_hexbin(p_x DOUBLE PRECISION) RETURNS TABLE (lat DOUBLE PRECISION)\n"
           "AS $$ SELECT 1 WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE' $$;\n")
    GEO = ("CREATE OR REPLACE FUNCTION atlas_geo_jurisdictions(p_x TIMESTAMP) RETURNS TABLE (n_zk BIGINT)\n"
           "AS $$ SELECT avg(ve.latitude) FILTER (WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE'), count(*) AS n_zk $$;\n")
    good_atlas = (
        "SELECT 1 WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE';  -- clusters\n"
        "SELECT 1 WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE';  -- points\n"
        + HEX + GEO +
        "CASE WHEN zk THEN NULL ELSE tv.latitude END\n")
    good_app = "CASE WHEN zk THEN NULL ELSE ve.requestor_location END\n"
    (tmp_path / "polaris_sql" / "11_atlas.sql").write_text(good_atlas)
    (tmp_path / "polaris_web" / "app.py").write_text(good_app)
    assert checks.check_c6_atlas_redacts_zk_location(tmp_path)[0].level == "OK", \
        "must PASS when clusters/points/hexbin exclude ZK and the rollup counts-but-never-locates it"
    # the hexbin drops its ZK exclusion -> a hex could pin a ZK event (C6 fail)
    (tmp_path / "polaris_sql" / "11_atlas.sql").write_text(
        good_atlas.replace(HEX, HEX.replace("WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE'", "")))
    assert checks.check_c6_atlas_redacts_zk_location(tmp_path)[0].level == "FAIL", \
        "must FAIL when atlas_hexbin stops excluding ZERO_KNOWLEDGE"
    # the jurisdiction centroid stops excluding ZK -> ZK becomes locatable (C6 fail)
    (tmp_path / "polaris_sql" / "11_atlas.sql").write_text(
        good_atlas.replace("avg(ve.latitude) FILTER (WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE')", "avg(ve.latitude)"))
    assert checks.check_c6_atlas_redacts_zk_location(tmp_path)[0].level == "FAIL", \
        "must FAIL when atlas_geo_jurisdictions centroid includes ZERO_KNOWLEDGE events"


def test_aor_privilege_boundary_check_discriminates(tmp_path):
    sql = tmp_path / "polaris_sql"
    mig = sql / "migrations"
    mig.mkdir(parents=True)
    base_tables = ("tokenlifecycleevent verificationevent enrollmentstatusevent "
                   "anchorbatch tokenstateepochleaf duressevent authauditlog "
                   "individualerasureevent", "exchangereceiptlog", "exchangenonce", "authcodeconsumed")

    def write(grants, mig_revoke, proc_definer):
        (sql / "09_grants.sql").write_text(grants)
        (mig / "2026-05-15-003-audit-access-log.up.sql").write_text(
            "REVOKE UPDATE, DELETE ON AuditAccessLog FROM polaris_app;\n"
            if mig_revoke else "CREATE TABLE AuditAccessLog (id BIGSERIAL);\n")
        (sql / "05_procedures.sql").write_text(
            "CREATE OR REPLACE PROCEDURE uc_archive_purge(p_actor INTEGER)\n"
            "LANGUAGE plpgsql\n"
            + ("SECURITY DEFINER\n" if proc_definer else "")
            + "AS $$ BEGIN NULL; END; $$;\n")

    good_grants = (f"REVOKE UPDATE, DELETE ON ... -- tables: {base_tables}\n")

    # 1. No REVOKE at all -> FAIL.
    write("GRANT SELECT ON ALL TABLES TO polaris_app;\n", True, True)
    assert checks.check_aor_privilege_boundary(tmp_path)[0].level == "FAIL", \
        "must FAIL when 09_grants.sql never revokes UPDATE/DELETE"

    # 2. REVOKE present but omits a table -> FAIL.
    write("REVOKE UPDATE, DELETE ON tokenlifecycleevent FROM polaris_app;\n", True, True)
    assert checks.check_aor_privilege_boundary(tmp_path)[0].level == "FAIL", \
        "must FAIL when the REVOKE omits an append-only table"

    # 3. Grants/migration fine, but uc_archive_purge is not SECURITY DEFINER -> FAIL.
    write(good_grants, True, False)
    assert checks.check_aor_privilege_boundary(tmp_path)[0].level == "FAIL", \
        "must FAIL when the sole DELETE path is not SECURITY DEFINER"

    # 4. Migration forgets its own REVOKE for AuditAccessLog -> FAIL.
    write(good_grants, False, True)
    assert checks.check_aor_privilege_boundary(tmp_path)[0].level == "FAIL", \
        "must FAIL when the AuditAccessLog migration does not revoke UPDATE/DELETE"

    # 5. All three present -> OK.
    write(good_grants, True, True)
    assert checks.check_aor_privilege_boundary(tmp_path)[0].level == "OK", \
        "must PASS when revoke + migration revoke + SECURITY DEFINER are all present"


def test_prod_app_password_synced_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()

    GOOD_INIT = (
        'if [ -n "$POLARIS_APP_PASSWORD_FILE" ]; then\n'
        '  POLARIS_APP_PASSWORD="$(cat "$POLARIS_APP_PASSWORD_FILE")"\n'
        'fi\n'
        'psql -c "ALTER ROLE polaris_app WITH PASSWORD \'$POLARIS_APP_PASSWORD\'"\n')

    def write(compose, init=GOOD_INIT):
        (web / "docker-compose.prod.yml").write_text(compose)
        (web / "docker-init.sh").write_text(init)

    app_line = "      POLARIS_DB_PASSWORD_FILE: /run/secrets/polaris_db_password\n"
    role_line = "      POLARIS_APP_PASSWORD_FILE: /run/secrets/polaris_db_password\n"

    # 1. compose never wires the role password file -> FAIL.
    write(app_line)
    assert checks.check_prod_app_password_synced(tmp_path)[0].level == "FAIL", \
        "must FAIL when POLARIS_APP_PASSWORD_FILE is absent"

    # 2. role secret differs from the app's secret -> FAIL.
    write(app_line + "      POLARIS_APP_PASSWORD_FILE: /run/secrets/something_else\n")
    assert checks.check_prod_app_password_synced(tmp_path)[0].level == "FAIL", \
        "must FAIL when the role password secret differs from the app's"

    # 3. compose fine, but docker-init.sh never reads the file -> FAIL.
    write(app_line + role_line, init='echo "no rotation here"\n')
    assert checks.check_prod_app_password_synced(tmp_path)[0].level == "FAIL", \
        "must FAIL when docker-init.sh does not read POLARIS_APP_PASSWORD_FILE"

    # 4. compose fine, init reads the file but never ALTERs the role -> FAIL.
    write(app_line + role_line,
          init='POLARIS_APP_PASSWORD="$(cat "$POLARIS_APP_PASSWORD_FILE")"\n')
    assert checks.check_prod_app_password_synced(tmp_path)[0].level == "FAIL", \
        "must FAIL when docker-init.sh does not ALTER ROLE polaris_app"

    # 5. all wired and matching -> OK.
    write(app_line + role_line)
    assert checks.check_prod_app_password_synced(tmp_path)[0].level == "OK", \
        "must PASS when the role password is synced to the app's secret and rotated at init"


def test_coercion_evidence_retained_check_discriminates(tmp_path):
    sql = tmp_path / "polaris_sql"
    web = tmp_path / "polaris_web"
    sql.mkdir(); web.mkdir()

    GOOD_SCHEMA = (
        "-- requesting_purpose_text is the anti-coercion evidentiary trail,\n"
        "-- RETAINED on every disclosure level (unlike requestor_location).\n"
        "    requesting_purpose_text VARCHAR(280),\n")

    def write(schema, app="SELECT requesting_purpose_text FROM VerificationEvent;\n"):
        (sql / "01_schema.sql").write_text(schema)
        (sql / "11_atlas.sql").write_text("-- atlas\n")
        (sql / "05_procedures.sql").write_text("-- procs\n")
        (web / "app.py").write_text(app)

    # 1. Column missing entirely -> FAIL.
    write("CREATE TABLE VerificationEvent (id SERIAL);\n")
    assert checks.check_coercion_evidence_retained(tmp_path)[0].level == "FAIL", \
        "must FAIL when the coercion-evidence column is missing"

    # 2. Stale FALSE comment claiming ZK redaction, right before the column -> FAIL.
    write("-- Like requestor_location, it is redacted for ZERO_KNOWLEDGE rows at read.\n"
          "    requesting_purpose_text VARCHAR(280),\n")
    assert checks.check_coercion_evidence_retained(tmp_path)[0].level == "FAIL", \
        "must FAIL when the schema falsely documents the trail as ZK-redacted"

    # 3. A read path that NULLs the trail for ZK rows -> FAIL (destroys the feature).
    write(GOOD_SCHEMA,
          app=("SELECT CASE WHEN disclosure_level = 'ZERO_KNOWLEDGE' "
               "THEN NULL ELSE requesting_purpose_text END FROM VerificationEvent;\n"))
    assert checks.check_coercion_evidence_retained(tmp_path)[0].level == "FAIL", \
        "must FAIL when a read path redacts the evidence trail for ZERO_KNOWLEDGE"

    # 4. Retained + accurate comment -> OK.
    write(GOOD_SCHEMA)
    assert checks.check_coercion_evidence_retained(tmp_path)[0].level == "OK", \
        "must PASS when the evidence trail is retained and not falsely documented"


def test_zk_anti_replay_check_discriminates(tmp_path):
    sql = tmp_path / "polaris_sql"
    web = tmp_path / "polaris_web"
    sql.mkdir(); web.mkdir()

    TABLE = "CREATE TABLE ZkVerificationNonce (epoch_id INTEGER, nonce BIGINT);\n"
    CONSUME = ("INSERT INTO ZkVerificationNonce (epoch_id, context_id, nonce) "
               "VALUES (%s,%s,%s) ON CONFLICT DO NOTHING RETURNING consumed_at\n"
               "return jsonify(verified=False, reason='nonce already consumed (replay)')\n")

    def write(schema, app):
        (sql / "01_schema.sql").write_text(schema)
        (web / "app.py").write_text(app)

    # 1. No nonce store table -> FAIL.
    write("CREATE TABLE TokenStateEpoch (epoch_id SERIAL);\n", CONSUME)
    assert checks.check_zk_verify_anti_replay(tmp_path)[0].level == "FAIL", \
        "must FAIL when the single-use nonce store is missing"

    # 2. Table exists but the route never consumes the nonce -> FAIL (replay open).
    write(TABLE, "def api_zk_verify(): return jsonify(verified=True)\n")
    assert checks.check_zk_verify_anti_replay(tmp_path)[0].level == "FAIL", \
        "must FAIL when the verify route does not consume the nonce"

    # 3. Consumes but never rejects the replay case -> FAIL.
    write(TABLE, "INSERT INTO ZkVerificationNonce (epoch_id, context_id, nonce) VALUES (1,1,1)\n")
    assert checks.check_zk_verify_anti_replay(tmp_path)[0].level == "FAIL", \
        "must FAIL when the route consumes but does not reject replays"

    # 4. Table + consume + replay rejection -> OK.
    write(TABLE, CONSUME)
    assert checks.check_zk_verify_anti_replay(tmp_path)[0].level == "OK", \
        "must PASS when the nonce is consumed and replays are rejected"


def test_thesis_terminus_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    docs = tmp_path / "docs"
    web.mkdir(); docs.mkdir()

    RETIRED = ("**Status:** INCONCLUSIVE — retired.\nThe v9.40 terminus passed; "
               "the strong claim is retired permanently.\n")
    OPEN = "**Status:** HYPOTHESIS-NOT-VERIFIED.\nawaiting a cold read.\n"

    def write(version, thesis):
        (web / "__version__.py").write_text(f'__version__: str = "{version}"\n')
        (docs / "THESIS.md").write_text(thesis)

    # 1. Before the v9.40 terminus: an open THESIS is fine -> OK.
    write("9.39", OPEN)
    assert checks.check_thesis_terminus_honest(tmp_path)[0].level == "OK", \
        "before v9.40 the thesis may remain open"

    # 2. Past v9.40 but status still the open 'HYPOTHESIS-NOT-VERIFIED' -> FAIL.
    write("9.90", OPEN)
    assert checks.check_thesis_terminus_honest(tmp_path)[0].level == "FAIL", \
        "past v9.40 the open status must fail"

    # 3. Past v9.40, retired language but the 'until a real cold read happens' softener remains -> FAIL.
    write("9.90", RETIRED + "we keep the status honest until a real cold read happens.\n")
    assert checks.check_thesis_terminus_honest(tmp_path)[0].level == "FAIL", \
        "the open 'until a real cold read happens' softener must fail past v9.40"

    # 4. Past v9.40 but no terminus / retirement language at all -> FAIL.
    write("9.90", "**Status:** an experiment.\nstill thinking about it.\n")
    assert checks.check_thesis_terminus_honest(tmp_path)[0].level == "FAIL", \
        "past v9.40, missing the terminus + retirement language must fail"

    # 5. Past v9.40 with proper retired/inconclusive framing -> OK.
    write("9.90", RETIRED)
    assert checks.check_thesis_terminus_honest(tmp_path)[0].level == "OK", \
        "past v9.40 the retired/inconclusive framing must pass"


def test_launcher_current_check_discriminates(tmp_path):
    GOOD = (
        'req="$WEB_DIR/requirements.txt"\n'
        'pip install --quiet -r "$req"\n'
        'build_zk_binary() { cargo build --release --bin polaris-zk; export POLARIS_ZK_BINARY; }\n'
        'run_tests() { python -m polaris_checks.run; python -m unittest '
        'test_check_constraints test_invariants_property test_redaction_property test_app; }\n')

    def write(sh):
        (tmp_path / "polaris_mac_launch.sh").write_text(sh)

    # 1. Hardcoded pip list, no requirements.txt -> FAIL.
    write("pip install flask psycopg2-binary gunicorn werkzeug webauthn\n"
          "polaris_checks test_check_constraints test_invariants_property test_redaction_property polaris-zk\n")
    assert checks.check_launcher_current(tmp_path)[0].level == "FAIL", \
        "must FAIL on a hardcoded pip list"

    # 2. Installs from requirements.txt but the test command omits canonical suites -> FAIL.
    write('pip install -r requirements.txt\nrun_tests() { python test_app.py; }\npolaris-zk\n')
    assert checks.check_launcher_current(tmp_path)[0].level == "FAIL", \
        "must FAIL when the test command omits the canonical suites"

    # 3. Deps + suites fine but no ZK binary reference -> FAIL.
    write('pip install -r requirements.txt\n'
          'run_tests(){ polaris_checks.run test_check_constraints test_invariants_property test_redaction_property; }\n')
    assert checks.check_launcher_current(tmp_path)[0].level == "FAIL", \
        "must FAIL when the launcher never builds/references the ZK binary"

    # 4. All three present -> OK.
    write(GOOD)
    assert checks.check_launcher_current(tmp_path)[0].level == "OK", \
        "must PASS when deps come from requirements.txt, the suite is canonical, and ZK is built"


def test_launcher_refreshes_code_check_discriminates(tmp_path):
    sh = tmp_path / "polaris_mac_launch.sh"
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    mig = scripts / "polaris-migrate.sh"

    GOOD_SYNC = ('sync_db_docker() {\n'
                 '    polaris-migrate.sh --target=dev-stack --up\n'
                 '    polaris-migrate.sh --target=dev-stack --sync-objects\n'
                 '}\n')
    GOOD_NATIVE = 'launch_native() {\n    polaris-migrate.sh --sync-objects\n}\n'
    GOOD_MIG = 'OBJECT_FILES=(\n    05_procedures.sql\n    11_atlas.sql\n)\n'

    # The v9.159 regression: the string "11_atlas.sql" present (native path),
    # but launch_docker never syncs. The old presence-grep passed this for
    # months while the default path shipped stale functions.
    mig.write_text(GOOD_MIG)
    sh.write_text(GOOD_SYNC + GOOD_NATIVE +
                  'launch_docker() {\n    docker compose up -d\n}\n')
    assert checks.check_launcher_refreshes_code(tmp_path)[0].level == "FAIL", \
        "must FAIL when launch_docker never calls sync_db_docker"

    # Docker path syncs but only ONE half (objects without migrations).
    sh.write_text('sync_db_docker() {\n'
                  '    polaris-migrate.sh --target=dev-stack --sync-objects\n'
                  '}\n' + GOOD_NATIVE +
                  'launch_docker() {\n    sync_db_docker\n}\n')
    assert checks.check_launcher_refreshes_code(tmp_path)[0].level == "FAIL", \
        "must FAIL when sync_db_docker skips the migration half"

    # The migrate tool itself lost the atlas file from its object list.
    mig.write_text('OBJECT_FILES=(\n    05_procedures.sql\n)\n')
    sh.write_text(GOOD_SYNC + GOOD_NATIVE +
                  'launch_docker() {\n    sync_db_docker\n}\n')
    assert checks.check_launcher_refreshes_code(tmp_path)[0].level == "FAIL", \
        "must FAIL when --sync-objects no longer covers 11_atlas.sql"

    # Both paths sync through the one tool, and the tool covers the atlas -> OK.
    mig.write_text(GOOD_MIG)
    assert checks.check_launcher_refreshes_code(tmp_path)[0].level == "OK", \
        "must PASS when both launcher paths sync migrations + objects via the migrate tool"


def test_migrate_docker_stdin_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    mig = scripts / "polaris-migrate.sh"

    # The real defect: docker compose exec -T drains the caller's stdin, so a
    # while-read loop calling this sees its input swallowed and pending
    # migrations report as applied.
    mig.write_text('run_psql() {\n'
                   '    if [[ "${USE_DEV_STACK}" -eq 1 ]]; then\n'
                   '        docker compose -f "${DEV_COMPOSE_FILE}" exec -T db \\\n'
                   '            psql -U postgres -d polaris_test -tA "$@"\n'
                   '    else\n'
                   '        psql -h localhost -tA "$@"\n'
                   '    fi\n'
                   '}\n')
    assert checks.check_migrate_docker_stdin_safe(tmp_path)[0].level == "FAIL", \
        "must FAIL when a docker-exec psql leaves stdin attached"

    mig.write_text('run_psql() {\n'
                   '    if [[ "${USE_DEV_STACK}" -eq 1 ]]; then\n'
                   '        docker compose -f "${DEV_COMPOSE_FILE}" exec -T db \\\n'
                   '            psql -U postgres -d polaris_test -tA "$@" < /dev/null\n'
                   '    else\n'
                   '        psql -h localhost -tA "$@"\n'
                   '    fi\n'
                   '}\n')
    assert checks.check_migrate_docker_stdin_safe(tmp_path)[0].level == "OK", \
        "must PASS when every docker-exec psql redirects stdin from /dev/null"


def test_rust_toolchain_pin_check_discriminates(tmp_path):
    zk = tmp_path / "polaris_zk"
    zk.mkdir()
    tc = zk / "rust-toolchain.toml"
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    ci = wf / "ci.yml"
    ci.write_text("jobs:\n  test:\n    steps:\n"
                  "      - run: grep nightly polaris_zk/rust-toolchain.toml\n")

    # The real defect: a floating nightly re-resolves on every install.
    tc.write_text('[toolchain]\nchannel = "nightly"\n')
    assert checks.check_rust_toolchain_pinned(tmp_path)[0].level == "FAIL", \
        "must FAIL on a floating (undated) nightly channel"

    # A dated pin, but CI carries its own hardcoded copy instead of deriving.
    tc.write_text('[toolchain]\nchannel = "nightly-2026-05-10"\n')
    ci.write_text("jobs:\n  test:\n    steps:\n"
                  "      - uses: dtolnay/rust-toolchain@master\n"
                  "        with:\n          toolchain: nightly-2026-05-10\n")
    assert checks.check_rust_toolchain_pinned(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not derive the toolchain from the file"

    ci.write_text("jobs:\n  test:\n    steps:\n"
                  "      - run: chan=$(grep -oE 'nightly-[0-9-]+' "
                  "polaris_zk/rust-toolchain.toml)\n")
    assert checks.check_rust_toolchain_pinned(tmp_path)[0].level == "OK", \
        "must PASS on a dated pin that CI derives from the file"


def test_ci_atlas_e2e_check_discriminates(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    ci = wf / "ci.yml"
    web = tmp_path / "polaris_web"
    web.mkdir()
    suite = web / "test_e2e_atlas.py"
    suite.write_text('_REQUIRE = os.environ.get("POLARIS_E2E_REQUIRE") == "1"\n')

    # The real defect: the suite exists, no job runs it, it rots silently.
    ci.write_text("jobs:\n  docker-image:\n    steps:\n      - run: docker compose up -d\n")
    assert checks.check_ci_runs_atlas_e2e(tmp_path)[0].level == "FAIL", \
        "must FAIL when no CI job runs the e2e suite"

    # Runs it, but without the no-skip guard: unavailable browser = green.
    ci.write_text("jobs:\n  docker-image:\n    steps:\n"
                  "      - run: python3 -m pytest polaris_web/test_e2e_atlas.py\n")
    assert checks.check_ci_runs_atlas_e2e(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI runs the suite without POLARIS_E2E_REQUIRE=1"

    ci.write_text("jobs:\n  docker-image:\n    steps:\n"
                  "      - run: POLARIS_E2E_REQUIRE=1 python3 -m pytest "
                  "polaris_web/test_e2e_atlas.py\n")
    assert checks.check_ci_runs_atlas_e2e(tmp_path)[0].level == "OK", \
        "must PASS when CI forces the suite to run"

    # The guard is asserted in CI but the suite stopped honoring it.
    suite.write_text("import os\n")
    assert checks.check_ci_runs_atlas_e2e(tmp_path)[0].level == "FAIL", \
        "must FAIL when the suite no longer honors POLARIS_E2E_REQUIRE"


# ---------------------------------------------------------------------------
# Operator-tooling sweep tier 2 (P0.4 / v9.166). Each pins a defect found by
# RUNNING the tool: the load generator double-counted failures, the chaos
# probe never reached the verifier, ct-monitor was untestable offline, and
# rotate-secret regressed container-readable secret perms.
# ---------------------------------------------------------------------------

def test_load_gen_single_ledger_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    lg = scripts / "polaris_load_gen.py"

    lg.write_text("def run():\n    errors = 0\n    errors += 1\n"
                  "    statuses['err:x'] += 1\n")
    assert checks.check_load_gen_single_ledger(tmp_path)[0].level == "FAIL", \
        "must FAIL when an independent errors counter is incremented"

    lg.write_text("def _error_count(s):\n    return 1\n"
                  "def _5xx_count(s):\n    return 0\n"
                  "def run():\n    statuses[code] += 1\n")
    assert checks.check_load_gen_single_ledger(tmp_path)[0].level == "OK", \
        "must PASS with a single ledger and a 5xx gate"

    lg.write_text("def run():\n    statuses[code] += 1\n")
    assert checks.check_load_gen_single_ledger(tmp_path)[0].level == "FAIL", \
        "must FAIL when there is no 5xx exit gate"


def test_chaos_probe_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    ch = scripts / "polaris-chaos-test.sh"

    ch.write_text('PY_BIN=python3\nproc = subprocess.run(["python3", "-c", code])\n'
                  'if "WRAPPER_READY" in out: pass\n')
    assert checks.check_chaos_probe_reaches_wrapper(tmp_path)[0].level == "FAIL", \
        "must FAIL when the probe spawns bare python3"

    ch.write_text('proc = subprocess.run([sys.executable, "-c", code])\n'
                  'print("WRAPPER_READY")\n')
    assert checks.check_chaos_probe_reaches_wrapper(tmp_path)[0].level == "FAIL", \
        "must FAIL when the harness resolves no >=3.10 interpreter (no PY_BIN)"

    ch.write_text('PY_BIN="${POLARIS_TEST_PYTHON:-}"\n'
                  'proc = subprocess.run([sys.executable, "-c", code])\n'
                  'if "WRAPPER_READY" not in out: inconclusive()\n')
    assert checks.check_chaos_probe_reaches_wrapper(tmp_path)[0].level == "OK", \
        "must PASS with sys.executable, PY_BIN resolution, and the sentinel"


def test_ct_monitor_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    ct = scripts / "polaris-ct-monitor.sh"

    ct.write_text('ct_response=$(curl -fsS "$url")\n'
                  'in_window=$(echo "$ct_response" | jq ...)\n')
    assert checks.check_ct_monitor_testable_and_guarded(tmp_path)[0].level == "FAIL", \
        "must FAIL with no fixture seam"

    ct.write_text('if [[ -n "${POLARIS_CT_FIXTURE:-}" ]]; then cat "$f"; fi\n'
                  'ct_response=$(fetch)\n')
    assert checks.check_ct_monitor_testable_and_guarded(tmp_path)[0].level == "FAIL", \
        "must FAIL with a fixture seam but no array-type guard"

    ct.write_text('if [[ -n "${POLARIS_CT_FIXTURE:-}" ]]; then cat "$f"; fi\n'
                  'jq -e \'type == "array"\' || exit 4\n')
    assert checks.check_ct_monitor_testable_and_guarded(tmp_path)[0].level == "OK", \
        "must PASS with both the fixture seam and the array guard"


def test_rotate_secret_mode_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    rs = scripts / "polaris-rotate-secret.sh"

    rs.write_text('printf "%s" "$NEW" > "${TARGET}.new"\n'
                  'chmod 0600 "${TARGET}.new"\n'
                  'mv "${TARGET}.new" "${TARGET}"\n')
    assert checks.check_rotate_secret_preserves_mode(tmp_path)[0].level == "FAIL", \
        "must FAIL when rotation hardcodes chmod 0600 on the replacement"

    rs.write_text('CUR_MODE=$(stat -f "%Lp" "${TARGET}")\n'
                  'printf "%s" "$NEW" > "${TARGET}.new"\n'
                  'chmod "0${CUR_MODE#0}" "${TARGET}.new"\n'
                  'mv "${TARGET}.new" "${TARGET}"\n')
    assert checks.check_rotate_secret_preserves_mode(tmp_path)[0].level == "OK", \
        "must PASS when rotation captures and reapplies the existing mode"

    # The GNU trap (v9.181): `stat -f ... ||` never falls through on Linux (exit 0
    # with a file-system report), so the fallback chain must be refused; the same
    # text in a COMMENT must not trip it.
    rs.write_text("CUR_MODE=$(stat -f '%Lp' \"${TARGET}\" 2>/dev/null || stat -c '%a' \"${TARGET}\")\nchmod \"0${CUR_MODE#0}\" \"${TARGET}.new\"\n")
    f = checks.check_rotate_secret_preserves_mode(tmp_path)[0]
    assert f.level == "FAIL" and "GNU stat" in f.message, "must FAIL on the stat -f || fallback chain"
    rs.write_text("# never chain stat -f ... || stat -c\nCUR_MODE=$(stat --version >/dev/null 2>&1 && stat -c '%a' \"${TARGET}\" || stat -f '%Lp' \"${TARGET}\")\nchmod \"0${CUR_MODE#0}\" \"${TARGET}.new\"\n")
    assert checks.check_rotate_secret_preserves_mode(tmp_path)[0].level == "OK", "a comment naming the trap must not trip it"


def test_sbom_workflow_check_discriminates(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sbom = wf / "sbom.yml"

    # No workflow at all -> releases ship no SBOM.
    assert checks.check_sbom_workflow(tmp_path)[0].level == "FAIL", \
        "must FAIL when sbom.yml is absent"

    # Present but missing an image and the upload step.
    sbom.write_text("on:\n  release:\n    types: [published]\n"
                    "jobs:\n  sbom:\n    steps:\n"
                    "      - run: trivy fs --format spdx-json /src\n"
                    "      - run: docker build -t polaris-app:sbom .\n"
                    "      - run: echo sbom-python\n")
    assert checks.check_sbom_workflow(tmp_path)[0].level == "FAIL", \
        "must FAIL when not all five images are covered"

    sbom.write_text("on:\n  release:\n    types: [published]\n"
                    "jobs:\n  sbom:\n    steps:\n"
                    "      - run: trivy fs --format spdx-json --output sbom-python.spdx.json /src\n"
                    "      - run: |\n"
                    "          docker build -t polaris-app:sbom .\n"
                    "          docker build -t polaris-caddy:sbom .\n"
                    "          docker build -t polaris-pgbouncer:sbom .\n"
                    "          docker build -t polaris-postgres:sbom .\n"
                    "          docker build -t polaris-etcd:sbom .\n"
                    "      - run: gh release upload \"$TAG\" sbom/*.spdx.json\n")
    assert checks.check_sbom_workflow(tmp_path)[0].level == "OK", \
        "must PASS with release trigger, SPDX, all five images, python, and upload"


def test_sbom_trivy_match_check_discriminates(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    ci = wf / "ci.yml"
    sbom = wf / "sbom.yml"

    # Drift: the scanner and the SBOM generator use different Trivy versions.
    ci.write_text("run: docker run aquasec/trivy:0.58.1 image x\n")
    sbom.write_text("env:\n  TRIVY_IMAGE: aquasec/trivy:0.59.0\n")
    assert checks.check_sbom_trivy_matches_scan(tmp_path)[0].level == "FAIL", \
        "must FAIL when the two Trivy versions differ"

    sbom.write_text("env:\n  TRIVY_IMAGE: aquasec/trivy:0.58.1\n")
    assert checks.check_sbom_trivy_matches_scan(tmp_path)[0].level == "OK", \
        "must PASS when both use the same Trivy version"


def test_release_provenance_check_discriminates(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    sbom = wf / "sbom.yml"
    sec = tmp_path / "SECURITY.md"
    sec.write_text("## Verifying a release\n"
                   "gh attestation verify sbom-python.spdx.json --repo x\n")

    # SBOMs generated but never attested.
    sbom.write_text("permissions:\n  id-token: write\n  attestations: write\n"
                    "jobs:\n  sbom:\n    steps:\n"
                    "      - run: trivy fs --format spdx-json /src\n")
    assert checks.check_release_provenance(tmp_path)[0].level == "FAIL", \
        "must FAIL when the workflow does not attest provenance"

    # Attests, but missing the keyless-signing permissions.
    sbom.write_text("permissions:\n  contents: write\n"
                    "jobs:\n  sbom:\n    steps:\n"
                    "      - uses: actions/attest-build-provenance@v2\n")
    assert checks.check_release_provenance(tmp_path)[0].level == "FAIL", \
        "must FAIL when id-token/attestations write permissions are absent"

    # Attests with permissions, but the docs carry no verify command.
    sbom.write_text("permissions:\n  id-token: write\n  attestations: write\n"
                    "jobs:\n  sbom:\n    steps:\n"
                    "      - uses: actions/attest-build-provenance@v2\n")
    sec.write_text("## Security Policy\nReport things.\n")
    assert checks.check_release_provenance(tmp_path)[0].level == "FAIL", \
        "must FAIL when SECURITY.md has no verify command"

    sec.write_text("gh attestation verify file --repo x\n")
    assert checks.check_release_provenance(tmp_path)[0].level == "OK", \
        "must PASS with attestation, permissions, and a documented verify command"


def test_zk_tree_depth_synced_check_discriminates(tmp_path):
    zk = tmp_path / "polaris_zk"
    src = zk / "src"
    w2 = zk / "witness2"
    src.mkdir(parents=True)
    w2.mkdir(parents=True)
    rs = src / "lib.rs"
    py = w2 / "merkle.py"

    def write(rs_default, py_default, env=True):
        envtok = "POLARIS_ZK_TREE_DEPTH" if env else "SOMETHING_ELSE"
        rs.write_text(f'match std::env::var("{envtok}") {{ Err(_) => {rs_default}, }}\n'
                      f'pub const DEFAULT_TREE_DEPTH: usize = {rs_default};\n')
        py.write_text(f'os.environ.get("{envtok}")\n'
                      f'DEFAULT_TREE_DEPTH = {py_default}\n')

    # Defaults diverge -> a default-config prover and witness disagree.
    write(14, 16)
    assert checks.check_zk_tree_depth_synced(tmp_path)[0].level == "FAIL", \
        "must FAIL when the Rust and Python default depths differ"

    # One side does not read the shared env var.
    write(14, 14, env=False)
    assert checks.check_zk_tree_depth_synced(tmp_path)[0].level == "FAIL", \
        "must FAIL when a side does not read POLARIS_ZK_TREE_DEPTH"

    write(14, 14)
    assert checks.check_zk_tree_depth_synced(tmp_path)[0].level == "OK", \
        "must PASS when both read the env var and share the default"


def test_coverage_gated_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    wf = tmp_path / ".github" / "workflows"
    scripts.mkdir()
    wf.mkdir(parents=True)
    cov = scripts / "polaris-coverage.sh"
    ci = wf / "ci.yml"

    # No coverage script -> coverage not measured.
    ci.write_text("jobs:\n  test:\n    steps:\n      - run: python -m unittest\n")
    assert checks.check_coverage_gated(tmp_path)[0].level == "FAIL", \
        "must FAIL when polaris-coverage.sh is absent"

    # Script measures but does not gate.
    cov.write_text("coverage report\n")
    assert checks.check_coverage_gated(tmp_path)[0].level == "FAIL", \
        "must FAIL when the script has no --fail-under floor"

    # Gates in the script, but CI never runs it.
    cov.write_text("coverage report --fail-under=$COVERAGE_FLOOR\n")
    assert checks.check_coverage_gated(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not run polaris-coverage.sh"

    # CI runs it with a floor, but no Rust coverage gate.
    ci.write_text("jobs:\n  test:\n    steps:\n"
                  "      - env:\n          COVERAGE_FLOOR: \"72\"\n"
                  "        run: bash scripts/polaris-coverage.sh\n")
    assert checks.check_coverage_gated(tmp_path)[0].level == "FAIL", \
        "must FAIL when Rust coverage is not gated (no fail-under-lines)"

    ci.write_text("jobs:\n  test:\n    steps:\n"
                  "      - env:\n          COVERAGE_FLOOR: \"72\"\n"
                  "        run: bash scripts/polaris-coverage.sh\n"
                  "      - run: cargo llvm-cov --fail-under-lines 85\n")
    assert checks.check_coverage_gated(tmp_path)[0].level == "OK", \
        "must PASS with the Python script+floor, CI running it, and the Rust gate"


def test_dockerfile_copies_app_modules_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    # app.py imports two local modules; both exist as files.
    (web / "app.py").write_text(
        "import os\nimport security\nimport pqc_signing  # v9.58 trailing comment\n")
    (web / "security.py").write_text("# local\n")
    (web / "pqc_signing.py").write_text("# local\n")

    def write_dockerfiles(dev_copy, prod_copy):
        (web / "Dockerfile").write_text(f"FROM python\n{dev_copy}\n")
        (web / "Dockerfile.prod").write_text(f"FROM python\n{prod_copy}\n")

    # 1. Dev Dockerfile omits pqc_signing.py (the real v9.58 bug) -> FAIL.
    write_dockerfiles("COPY app.py security.py ./",
                      "COPY app.py security.py pqc_signing.py ./")
    out = checks.check_dockerfile_copies_app_modules(tmp_path)
    assert out[0].level == "FAIL" and "pqc_signing" in out[0].message, \
        "must FAIL when a Dockerfile omits a local module app.py imports"

    # 2. Prod Dockerfile omits it -> FAIL (both images are checked).
    write_dockerfiles("COPY app.py security.py pqc_signing.py ./",
                      "COPY app.py security.py ./")
    assert checks.check_dockerfile_copies_app_modules(tmp_path)[0].level == "FAIL", \
        "must FAIL when the prod Dockerfile omits a local module"

    # 3. Both COPY every local module -> OK.
    write_dockerfiles("COPY app.py security.py pqc_signing.py ./",
                      "COPY --chown=x:y app.py security.py pqc_signing.py ./")
    assert checks.check_dockerfile_copies_app_modules(tmp_path)[0].level == "OK", \
        "must PASS when both Dockerfiles COPY every local app module"


def test_prod_hardening_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    GOOD_INIT = (
        'if [ "${POLARIS_ENV:-}" = "production" ]; then\n'
        "  psql <<'SQL'\n"
        "  UPDATE AppUser SET is_active = FALSE WHERE username IN ('admin', 'operator', 'auditor');\n"
        "SQL\n"
        "fi\n")
    GOOD_COMPOSE = "services:\n  app:\n    environment:\n      POLARIS_REDIS_URL: redis://redis:6379/0\n"

    def write(init, compose):
        (web / "docker-init.sh").write_text(init)
        (web / "docker-compose.prod.yml").write_text(compose)

    # 1. docker-init does not neutralize demo accounts in prod -> FAIL.
    write('echo "no prod hardening"\n', GOOD_COMPOSE)
    assert checks.check_prod_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when demo accounts are not disabled in production"

    # 2. Demo accounts handled, but no Redis URL in prod compose -> FAIL.
    write(GOOD_INIT, "services:\n  app:\n    environment:\n      POLARIS_PORT: '8000'\n")
    assert checks.check_prod_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when the prod rate limiter is not wired to Redis"

    # 3. Both present -> OK.
    write(GOOD_INIT, GOOD_COMPOSE)
    assert checks.check_prod_hardening(tmp_path)[0].level == "OK", \
        "must PASS when demo accounts are neutralized and Redis is wired"


def test_backup_encryption_check_discriminates(tmp_path):
    sc = tmp_path / "scripts"
    sc.mkdir()
    bk = sc / "polaris-backup.sh"
    rs = sc / "polaris-restore.sh"

    # 1. Backup script has no encryption support -> FAIL.
    bk.write_text("tar -czf backup.tar.gz .\n")
    rs.write_text("tar -xzf backup.tar.gz\n")
    assert checks.check_backup_encryption(tmp_path)[0].level == "FAIL", \
        "must FAIL when backups are not encryptable"

    # 2. Backup encrypts but restore cannot decrypt -> FAIL.
    bk.write_text('KEY="$POLARIS_BACKUP_KEY_FILE"\nopenssl enc -aes-256-cbc -in t -out t.enc\n')
    rs.write_text("tar -xzf backup.tar.gz\n")
    assert checks.check_backup_encryption(tmp_path)[0].level == "FAIL", \
        "must FAIL when restore cannot decrypt .enc backups"

    # 3. Both present -> OK.
    bk.write_text('KEY="$POLARIS_BACKUP_KEY_FILE"\nopenssl enc -aes-256-cbc -in t -out t.enc\n')
    rs.write_text('if [[ "$f" == *.enc ]]; then openssl enc -d -aes-256-cbc -in "$f"; fi\n')
    assert checks.check_backup_encryption(tmp_path)[0].level == "OK", \
        "must PASS when backup encrypts and restore decrypts"


def test_pqc_real_signing_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    gh = tmp_path / ".github" / "workflows"
    web.mkdir(); gh.mkdir(parents=True)
    GOOD_PQC = ("POLARIS_PQC_SIGNING_KEY_FILE\ndef generate_keypair(): ...\ndef verify(): ...\n")
    GOOD_CI = "jobs:\n  pqc-real:\n    steps: [pip install liboqs-python]\n"

    def write(pqc, ci):
        (web / "pqc_signing.py").write_text(pqc)
        (gh / "ci.yml").write_text(ci)

    # 1. Ephemeral-only (no persistent key file) -> FAIL.
    write("def generate_keypair(): ...\ndef verify(): ...\n", GOOD_CI)
    assert checks.check_pqc_real_signing(tmp_path)[0].level == "FAIL", \
        "must FAIL when there is no persistent signing key"

    # 2. Persistent key but CI never tests real PQC -> FAIL.
    write(GOOD_PQC, "jobs:\n  test:\n    steps: []\n")
    assert checks.check_pqc_real_signing(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not exercise the real ML-DSA path"

    # 3. Persistent key + verify + CI pqc-real job with liboqs -> OK.
    write(GOOD_PQC, GOOD_CI)
    assert checks.check_pqc_real_signing(tmp_path)[0].level == "OK", \
        "must PASS with a persistent key, verify, and a real-PQC CI job"


def test_sql_console_readonly_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()

    def write(body):
        (web / "app.py").write_text(
            "def sql_query():\n" + body + "\n\ndef next_route():\n    pass\n"
        )

    # 1. Keyword whitelist only, no DB-level read-only -> FAIL (CTE-bypassable).
    write("    cur.execute('SET statement_timeout = 5000')\n    cur.execute(sql)")
    assert checks.check_sql_console_readonly(tmp_path)[0].level == "FAIL", \
        "must FAIL when the console relies only on the SELECT/WITH keyword gate"

    # 2. A mid-transaction SET default_transaction_read_only does NOT bind the
    #    query's own already-started transaction -> still FAIL (the real bug the
    #    DB-backed test caught; the check must not accept this non-fix).
    write("    cur.execute('SET statement_timeout = 5000')\n"
          "    cur.execute('SET default_transaction_read_only = on')\n"
          "    cur.execute(sql)")
    assert checks.check_sql_console_readonly(tmp_path)[0].level == "FAIL", \
        "must FAIL on the non-functional mid-transaction SET (it does not bind the query)"

    # 3. Session set read-only before any statement -> OK.
    write("    conn.set_session(readonly=True)\n"
          "    cur.execute('SET statement_timeout = 5000')\n"
          "    cur.execute(sql)")
    assert checks.check_sql_console_readonly(tmp_path)[0].level == "OK", \
        "must PASS once the session is set read-only before any statement"

    # 4. read-only set in some OTHER function, not sql_query -> FAIL (scoped to the handler).
    (web / "app.py").write_text(
        "def sql_query():\n    cur.execute(sql)\n\n"
        "def elsewhere():\n    conn.set_session(readonly=True)\n"
    )
    assert checks.check_sql_console_readonly(tmp_path)[0].level == "FAIL", \
        "must FAIL when read-only is set outside the sql_query handler"

    # 5. Missing app.py -> FAIL.
    (web / "app.py").unlink()
    assert checks.check_sql_console_readonly(tmp_path)[0].level == "FAIL", \
        "must FAIL when app.py is absent"


def test_prod_image_no_test_deps_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    RUNTIME = "Flask==3.1.3\npsycopg2-binary==2.9.12\nredis>=5.0,<6.0\n"
    DEV = "-r requirements.txt\nhypothesis>=6.0,<7.0\npytest>=7.0,<9.0\nplaywright>=1.40,<2.0\n"
    DF = "FROM python:3.12-slim\nCOPY requirements.txt /tmp/\nRUN pip install -r /tmp/requirements.txt\n"

    def write(runtime, dev=DEV, df=DF, dfp=DF):
        (web / "requirements.txt").write_text(runtime)
        if dev is not None:
            (web / "requirements-dev.txt").write_text(dev)
        elif (web / "requirements-dev.txt").exists():
            (web / "requirements-dev.txt").unlink()
        (web / "Dockerfile").write_text(df)
        (web / "Dockerfile.prod").write_text(dfp)

    # 1. A test framework in the runtime surface -> FAIL.
    write(RUNTIME + "pytest>=7.0,<9.0\n")
    assert checks.check_prod_image_no_test_deps(tmp_path)[0].level == "FAIL", \
        "must FAIL when requirements.txt lists a test-only package"

    # 2. Clean runtime but no requirements-dev.txt -> FAIL.
    write(RUNTIME, dev=None)
    assert checks.check_prod_image_no_test_deps(tmp_path)[0].level == "FAIL", \
        "must FAIL when the dev requirements file is absent"

    # 3. Dev file does not pull in the runtime surface -> FAIL.
    write(RUNTIME, dev="pytest>=7.0,<9.0\n")
    assert checks.check_prod_image_no_test_deps(tmp_path)[0].level == "FAIL", \
        "must FAIL when requirements-dev.txt omits `-r requirements.txt`"

    # 4. A Dockerfile installs the dev file -> FAIL.
    write(RUNTIME, dfp="FROM x\nCOPY requirements-dev.txt /tmp/\nRUN pip install -r /tmp/requirements-dev.txt\n")
    assert checks.check_prod_image_no_test_deps(tmp_path)[0].level == "FAIL", \
        "must FAIL when an image installs the dev requirements"

    # 5. Clean runtime, dev file with -r, images install runtime only -> OK.
    write(RUNTIME)
    assert checks.check_prod_image_no_test_deps(tmp_path)[0].level == "OK", \
        "must PASS when test tooling is isolated and the images install runtime only"


def test_cve_scanning_check_discriminates(tmp_path):
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)
    GATING = "      run: pip-audit -r polaris_web/requirements.txt --progress-spinner off --strict\n"

    def write_ci(text):
        (gh / "ci.yml").write_text(text)

    def write_dependabot():
        (tmp_path / ".github" / "dependabot.yml").write_text("version: 2\nupdates: []\n")

    # 1. No pip-audit in CI -> FAIL.
    write_ci("jobs:\n  test:\n    steps: []\n")
    write_dependabot()
    assert checks.check_cve_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not run pip-audit"

    # 2. pip-audit present but not gating (--strict) on requirements.txt -> FAIL.
    write_ci("jobs:\n  scan:\n    steps:\n      run: pip-audit -r polaris_web/requirements.txt\n")
    assert checks.check_cve_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when the runtime audit is not --strict (non-gating)"

    # 3. Gating audit but no dependabot.yml -> FAIL.
    write_ci("jobs:\n  scan:\n    steps:\n" + GATING)
    (tmp_path / ".github" / "dependabot.yml").unlink()
    assert checks.check_cve_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dependabot is not configured"

    # 4. Gating audit + dependabot -> OK.
    write_ci("jobs:\n  scan:\n    steps:\n" + GATING)
    write_dependabot()
    assert checks.check_cve_scanning(tmp_path)[0].level == "OK", \
        "must PASS with a gating runtime audit and Dependabot configured"


def test_image_cve_scanning_check_discriminates(tmp_path):
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)
    web = tmp_path / "polaris_web"
    web.mkdir()

    GOOD_CI = ("jobs:\n  image-cve-scan:\n    steps:\n      run: |\n"
               "        trivy image --severity CRITICAL --ignore-unfixed --ignorefile /.trivyignore "
               "--exit-code 1 polaris-app:cve\n")
    DOCKERFILES = {
        "Dockerfile.prod": "FROM python:3.12-slim-bookworm\nRUN apt-get update && apt-get -y upgrade\n",
        "Dockerfile.caddy": "FROM caddy:2-alpine\nRUN apk upgrade --no-cache\n",
        "Dockerfile.pgbouncer": "FROM alpine:3.20\nRUN apk upgrade --no-cache && apk add pgbouncer\n",
        "Dockerfile.postgres": "FROM postgres:16-alpine\nRUN apk upgrade --no-cache\n",
    }

    def write(ci=GOOD_CI, dockerfiles=None, trivyignore=True):
        (gh / "ci.yml").write_text(ci)
        for name, body in (dockerfiles or DOCKERFILES).items():
            (web / name).write_text(body)
        ti = tmp_path / ".trivyignore"
        if trivyignore:
            ti.write_text("# justified\nCVE-2025-68121\n")
        elif ti.exists():
            ti.unlink()

    # 1. No Trivy in CI -> FAIL.
    write(ci="jobs:\n  x:\n    steps:\n      run: echo hi\n")
    assert checks.check_image_cve_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not run Trivy on the images"

    # 2. Trivy present but not gating (no --exit-code 1) -> FAIL.
    write(ci="jobs:\n  s:\n    steps:\n      run: trivy image --severity CRITICAL --ignore-unfixed app\n")
    assert checks.check_image_cve_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when the Trivy scan does not gate (--exit-code 1)"

    # 3. Gating Trivy but a Dockerfile does not upgrade its base -> FAIL.
    bad = dict(DOCKERFILES); bad["Dockerfile.prod"] = "FROM python:3.12-slim-bookworm\nRUN echo no-upgrade\n"
    write(dockerfiles=bad)
    assert checks.check_image_cve_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when a self-built Dockerfile does not patch its base"

    # 4. Everything but no .trivyignore -> FAIL.
    write(trivyignore=False)
    assert checks.check_image_cve_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when exceptions are not documented in .trivyignore"

    # 5. Gating Trivy + patched Dockerfiles + documented .trivyignore -> OK.
    write()
    assert checks.check_image_cve_scanning(tmp_path)[0].level == "OK", \
        "must PASS with a gating image scan, base patching, and documented exceptions"


def test_migration_timeouts_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()

    def write(sh):
        (scripts / "polaris-migrate.sh").write_text(sh)

    # 1. No timeouts at all -> FAIL.
    write("BEGIN;\n\\i up.sql\nCOMMIT;\n")
    assert checks.check_migration_timeouts(tmp_path)[0].level == "FAIL", \
        "must FAIL when the runner sets no migration timeouts"

    # 2. lock_timeout only (statement_timeout missing) -> FAIL.
    write("BEGIN;\nSET LOCAL lock_timeout = '3s';\n\\i up.sql\nCOMMIT;\n")
    assert checks.check_migration_timeouts(tmp_path)[0].level == "FAIL", \
        "must FAIL when statement_timeout is not also bounded"

    # 3. Both SET LOCAL timeouts -> OK.
    write("BEGIN;\nSET LOCAL lock_timeout = '3s';\n"
          "SET LOCAL statement_timeout = '60s';\n\\i up.sql\nCOMMIT;\n")
    assert checks.check_migration_timeouts(tmp_path)[0].level == "OK", \
        "must PASS when both lock_timeout and statement_timeout are SET LOCAL"

    # 4. Missing script -> FAIL.
    (scripts / "polaris-migrate.sh").unlink()
    assert checks.check_migration_timeouts(tmp_path)[0].level == "FAIL", \
        "must FAIL when the migrate script is absent"


def test_web_concurrency_honored_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()

    def write(conf):
        (web / "gunicorn.conf.py").write_text(conf)

    # 1. Reads only POLARIS_WORKERS -> FAIL (WEB_CONCURRENCY inert).
    write("workers = int(os.environ.get('POLARIS_WORKERS', '4'))\n")
    assert checks.check_web_concurrency_honored(tmp_path)[0].level == "FAIL", \
        "must FAIL when the config ignores WEB_CONCURRENCY"

    # 2. Honors WEB_CONCURRENCY -> OK.
    write("workers = int(os.environ.get('POLARIS_WORKERS') "
          "or os.environ.get('WEB_CONCURRENCY') or 4)\n")
    assert checks.check_web_concurrency_honored(tmp_path)[0].level == "OK", \
        "must PASS when WEB_CONCURRENCY is honored"

    # 3. Missing config -> FAIL.
    (web / "gunicorn.conf.py").unlink()
    assert checks.check_web_concurrency_honored(tmp_path)[0].level == "FAIL", \
        "must FAIL when gunicorn.conf.py is absent"


def test_health_liveness_readiness_split_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    GOOD_LIVE = (
        "@app.route('/api/health/ready')\n"
        "def api_health_ready():\n    body, code = _compute_readiness()\n    return body, code\n\n"
        "@app.route('/api/health/live')\n"
        "def api_health_live():\n    return {'status': 'alive'}, 200\n\n"
        "def next_route():\n    pass\n"
    )
    GOOD_DF = "HEALTHCHECK CMD curl http://localhost:8000/api/health/live | grep alive\n"

    def write(app_py, df=GOOD_DF):
        (web / "app.py").write_text(app_py)
        (web / "Dockerfile.prod").write_text(df)

    # 1. Only the old /api/health (no split) -> FAIL.
    write("@app.route('/api/health')\ndef api_health():\n    return {}, 200\n")
    assert checks.check_health_liveness_readiness_split(tmp_path)[0].level == "FAIL", \
        "must FAIL when liveness/readiness are not split"

    # 2. Both routes, liveness cheap, HEALTHCHECK uses liveness -> OK.
    write(GOOD_LIVE)
    assert checks.check_health_liveness_readiness_split(tmp_path)[0].level == "OK", \
        "must PASS with both probes split and a cheap liveness handler"

    # 3. Liveness handler runs the dependency roll-up -> FAIL (not cheap).
    write(
        "@app.route('/api/health/ready')\ndef api_health_ready():\n    return _compute_readiness()\n\n"
        "@app.route('/api/health/live')\n"
        "def api_health_live():\n    body, code = _compute_readiness()\n    return body, code\n\n"
        "def next_route():\n    pass\n"
    )
    assert checks.check_health_liveness_readiness_split(tmp_path)[0].level == "FAIL", \
        "must FAIL when the liveness probe runs the dependency checks"

    # 4. Both routes but the prod HEALTHCHECK still uses the dependency roll-up -> FAIL.
    write(GOOD_LIVE, df="HEALTHCHECK CMD curl http://localhost:8000/api/health | grep healthy\n")
    assert checks.check_health_liveness_readiness_split(tmp_path)[0].level == "FAIL", \
        "must FAIL when the container HEALTHCHECK does not use the liveness probe"


def test_compose_resource_limits_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()

    def service(name, with_limits, with_logging):
        s = f"  {name}:\n    image: {name}:latest\n"
        if with_limits:
            s += ("    deploy:\n      resources:\n        limits:\n"
                  "          cpus: '0.5'\n          memory: 128M\n")
        if with_logging:
            s += ("    logging:\n      driver: json-file\n"
                  "      options:\n        max-size: 10m\n        max-file: '5'\n")
        return s

    def write(*svcs):
        (web / "docker-compose.prod.yml").write_text("services:\n" + "".join(svcs))

    # 1. Two services, neither limited or rotated -> FAIL.
    write(service("a", False, False), service("b", False, False))
    assert checks.check_compose_resource_limits(tmp_path)[0].level == "FAIL", \
        "must FAIL when services have no resource limits"

    # 2. Limits on all, logging on only one -> FAIL (rotation not universal).
    write(service("a", True, True), service("b", True, False))
    assert checks.check_compose_resource_limits(tmp_path)[0].level == "FAIL", \
        "must FAIL when not every service configures log rotation"

    # 3. Logging on all, limits on only one -> FAIL.
    write(service("a", True, True), service("b", False, True))
    assert checks.check_compose_resource_limits(tmp_path)[0].level == "FAIL", \
        "must FAIL when not every service sets resource limits"

    # 4. Both on every service -> OK.
    write(service("a", True, True), service("b", True, True))
    assert checks.check_compose_resource_limits(tmp_path)[0].level == "OK", \
        "must PASS when every service has limits + rotating logging"

    # 5. Missing compose -> FAIL.
    (web / "docker-compose.prod.yml").unlink()
    assert checks.check_compose_resource_limits(tmp_path)[0].level == "FAIL", \
        "must FAIL when the prod compose is absent"


def test_pgbouncer_self_built_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    GOOD_COMPOSE = ("services:\n  pgbouncer:\n    build:\n      context: .\n"
                    "      dockerfile: Dockerfile.pgbouncer\n    image: polaris-pgbouncer:prod\n")
    GOOD_ENTRY = ("#!/bin/sh\nPWFILE=\"${POLARIS_DB_PASSWORD_FILE:-/run/secrets/x}\"\n"
                  "SERVER_LOGIN_RETRY=\"${PGBOUNCER_SERVER_LOGIN_RETRY:-1}\"\nDNS_NXDOMAIN_TTL=\"${PGBOUNCER_DNS_NXDOMAIN_TTL:-1}\"\n"
                  "SERVER_CONNECT_TIMEOUT=\"${PGBOUNCER_SERVER_CONNECT_TIMEOUT:-3}\"\nTCP_USER_TIMEOUT=\"${PGBOUNCER_TCP_USER_TIMEOUT:-5000}\"\n"
                  "QUERY_TIMEOUT=\"${PGBOUNCER_QUERY_TIMEOUT:-15}\"\n"
                  "cat > ini <<EOF\nserver_login_retry = $SERVER_LOGIN_RETRY\ndns_nxdomain_ttl = $DNS_NXDOMAIN_TTL\n"
                  "server_connect_timeout = $SERVER_CONNECT_TIMEOUT\ntcp_user_timeout = $TCP_USER_TIMEOUT\nquery_timeout = $QUERY_TIMEOUT\nEOF\n")
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)
    (gh / "ci.yml").write_text("jobs:\n  d:\n    steps:\n      run: docker build -f polaris_web/Dockerfile.pgbouncer .\n")

    def write(compose=GOOD_COMPOSE, df="FROM alpine\n", entry=GOOD_ENTRY):
        (web / "docker-compose.prod.yml").write_text(compose)
        if df is not None:
            (web / "Dockerfile.pgbouncer").write_text(df)
        elif (web / "Dockerfile.pgbouncer").exists():
            (web / "Dockerfile.pgbouncer").unlink()
        (web / "pgbouncer-entrypoint.sh").write_text(entry)

    # 1. Still references the removed bitnami image -> FAIL.
    write(compose="services:\n  pgbouncer:\n    image: bitnami/pgbouncer:1.22\n")
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when the compose still pulls bitnami/pgbouncer"

    # 2. No Dockerfile.pgbouncer present -> FAIL.
    write(df=None)
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when the self-built Dockerfile is absent"

    # 3. Entrypoint reads the password from env, not the file secret -> FAIL.
    write(entry="#!/bin/sh\nPASSWORD=\"$PGBOUNCER_PASSWORD\"\n")
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when the entrypoint does not use the file-mounted secret"

    # 4. Self-built, builds Dockerfile.pgbouncer, reads the file secret -> OK.
    write()
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "OK", \
        "must PASS for a self-built pooler reading the file-mounted secret"

    # 5. Dockerfile.pgbouncer named only in a COMMENT while a third-party image
    #    is actually pulled -> FAIL (substring match would false-pass here).
    write(compose="# we use Dockerfile.pgbouncer now\nservices:\n  pgbouncer:\n"
                  "    image: third-party/pgbouncer:2.0\n")
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dockerfile.pgbouncer is only mentioned in a comment"

    # 6. POLARIS_DB_PASSWORD_FILE named only in a COMMENT while the password is
    #    actually read from the environment -> FAIL.
    write(entry="#!/bin/sh\n# TODO: switch to POLARIS_DB_PASSWORD_FILE\n"
                "PASSWORD=\"$PGBOUNCER_PASSWORD\"\n")
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when the secret is only named in a comment, not read in code"

    # 7. Upper/mixed-case BITNAMI reference (Docker refs are case-insensitive) -> FAIL.
    write(compose="services:\n  pgbouncer:\n    image: BITNAMI/PgBouncer:1.22\n")
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL on a case-variant bitnami/pgbouncer reference"

    # 8. v9.242: the pooler on PgBouncer's 15 s retry default (a half-second
    #    database crash is a 16 s outage) -> FAIL; and a default of 15 -> FAIL.
    write(entry="#!/bin/sh\nPWFILE=\"${POLARIS_DB_PASSWORD_FILE:-/run/secrets/x}\"\n")
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when the entrypoint leaves server_login_retry at PgBouncer's default"
    write(entry=GOOD_ENTRY.replace("PGBOUNCER_SERVER_LOGIN_RETRY:-1", "PGBOUNCER_SERVER_LOGIN_RETRY:-15"))
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when the retry default is 15 seconds"
    # 8b. v9.243: a hung backend connect left at PgBouncer's 15 s default -> FAIL.
    write(entry=GOOD_ENTRY.replace("PGBOUNCER_SERVER_CONNECT_TIMEOUT:-3", "PGBOUNCER_SERVER_CONNECT_TIMEOUT:-15"))
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when a hung backend connect is allowed 15 seconds"
    # 9. The knob is read but never written into the ini -> FAIL.
    write(entry=GOOD_ENTRY.replace("server_login_retry = $SERVER_LOGIN_RETRY\n", ""))
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when the retry is read from the environment but not written to the ini"
    # 10. A dead pgbouncer.ini beside the generated one -> FAIL.
    write()
    (web / "pgbouncer.ini").write_text("[pgbouncer]\nserver_login_retry = 5\n")
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when a pgbouncer.ini nothing consumes sits beside the generated config"
    (web / "pgbouncer.ini").unlink()
    write()
    assert checks.check_pgbouncer_self_built(tmp_path)[0].level == "OK"


def test_caddy_self_built_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)

    RL_CADDYFILE = "site {\n    rate_limit {\n        zone z { events 200 }\n    }\n}\n"
    BUILD_COMPOSE = ("services:\n  caddy:\n    build:\n      context: .\n"
                     "      dockerfile: Dockerfile.caddy\n    image: polaris-caddy:prod\n")
    GOOD_DF = ("FROM caddy:2.11.4-builder-alpine AS builder\n"
               "RUN xcaddy build --with github.com/mholt/caddy-ratelimit\n"
               "FROM caddy:2.11.4-alpine\nCOPY --from=builder /usr/bin/caddy /usr/bin/caddy\n")
    GOOD_CI = "jobs:\n  e:\n    steps:\n      run: docker build -f polaris_web/Dockerfile.caddy . && caddy validate\n"

    def write(caddyfile=RL_CADDYFILE, compose=BUILD_COMPOSE, df=GOOD_DF, ci=GOOD_CI):
        (web / "Caddyfile").write_text(caddyfile)
        (web / "docker-compose.prod.yml").write_text(compose)
        if df is not None:
            (web / "Dockerfile.caddy").write_text(df)
        elif (web / "Dockerfile.caddy").exists():
            (web / "Dockerfile.caddy").unlink()
        (gh / "ci.yml").write_text(ci)

    # 1. Caddyfile uses rate_limit but the compose pulls the STOCK image -> FAIL.
    write(compose="services:\n  caddy:\n    image: caddy:2-alpine@sha256:abc\n")
    assert checks.check_caddy_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when a plugin directive is used but the edge is the stock image"

    # 2. Builds Dockerfile.caddy but the plugin is not compiled in -> FAIL.
    write(df="FROM caddy:2.11.4-alpine\n")
    assert checks.check_caddy_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dockerfile.caddy does not compile in the caddy-ratelimit plugin"

    # 3. Self-built + plugin compiled in, but CI does not validate the Caddyfile -> FAIL.
    write(ci="jobs:\n  e:\n    steps:\n      run: echo nothing\n")
    assert checks.check_caddy_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not build + validate the Caddyfile against the edge image"

    # 4. Dockerfile.caddy named only in a COMMENT while the stock image is pulled -> FAIL.
    write(compose="# build: Dockerfile.caddy\nservices:\n  caddy:\n    image: caddy:2-alpine\n")
    assert checks.check_caddy_self_built(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dockerfile.caddy is only mentioned in a comment"

    # 5. No third-party directive in the Caddyfile -> the stock image is fine -> OK.
    write(caddyfile="site {\n    reverse_proxy app:8000\n}\n",
          compose="services:\n  caddy:\n    image: caddy:2-alpine@sha256:abc\n")
    assert checks.check_caddy_self_built(tmp_path)[0].level == "OK", \
        "must PASS (nothing to enforce) when the Caddyfile uses no plugin directives"

    # 6. rate_limit used, self-built, plugin compiled in, CI validates -> OK.
    write()
    assert checks.check_caddy_self_built(tmp_path)[0].level == "OK", \
        "must PASS for a self-built edge with the plugin compiled in and CI validation"


def test_prod_stack_boot_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)
    ci = gh / "ci.yml"

    GOOD_CI = ("jobs:\n  prod-stack-boot:\n    steps:\n      run: |\n"
               "        bash scripts/polaris-generate-secrets.sh\n"
               "        docker compose -f docker-compose.prod.yml -f docker-compose.citest.yml up -d\n"
               "        curl -sk https://localhost:8443/api/health\n")

    def write(ci_text=GOOD_CI, override=True, caddyfile=True):
        ci.write_text(ci_text)
        ov = web / "docker-compose.citest.yml"
        cf = web / "Caddyfile.citest"
        if override: ov.write_text("services:\n  caddy: {}\n")
        elif ov.exists(): ov.unlink()
        if caddyfile: cf.write_text("localhost:443 { tls internal }\n")
        elif cf.exists(): cf.unlink()

    # 1. No citest override file -> FAIL.
    write(override=False)
    assert checks.check_prod_stack_boot(tmp_path)[0].level == "FAIL", \
        "must FAIL without the docker-compose.citest.yml override"

    # 2. Override present but CI never boots the prod compose -> FAIL.
    write(ci_text="jobs:\n  x:\n    steps:\n      run: echo hi\n")
    assert checks.check_prod_stack_boot(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not boot the full prod compose with the override"

    # 3. Boots the compose but does not generate secrets -> FAIL.
    write(ci_text="jobs:\n  b:\n    steps:\n      run: |\n"
                  "        docker compose -f docker-compose.prod.yml -f docker-compose.citest.yml up -d\n"
                  "        curl https://localhost:8443/api/health\n")
    assert checks.check_prod_stack_boot(tmp_path)[0].level == "FAIL", \
        "must FAIL when the boot does not generate real secrets"

    # 4. Boots + secrets but never asserts it serves /api/health -> FAIL.
    write(ci_text="jobs:\n  b:\n    steps:\n      run: |\n"
                  "        bash scripts/polaris-generate-secrets.sh\n"
                  "        docker compose -f docker-compose.prod.yml -f docker-compose.citest.yml up -d\n")
    assert checks.check_prod_stack_boot(tmp_path)[0].level == "FAIL", \
        "must FAIL when the boot does not assert serving through the edge"

    # 5. Override + Caddyfile + boots prod compose + secrets + health probe -> OK.
    write()
    assert checks.check_prod_stack_boot(tmp_path)[0].level == "OK", \
        "must PASS for a full prod-compose boot that generates secrets and probes /api/health"


def test_container_hardening_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)
    (gh / "ci.yml").write_text("jobs:\n  prod-stack-boot:\n    steps:\n      run: echo boot\n")
    compose = web / "docker-compose.prod.yml"

    def svc(name, hardened=True, cap_add=None):
        block = f"  {name}:\n    image: x:1\n"
        if hardened:
            block += ("    security_opt:\n      - no-new-privileges:true\n"
                      "    cap_drop:\n      - ALL\n")
        if cap_add:
            block += f"    cap_add:\n      - {cap_add}\n"
        if name == "caddy":
            block += '    ports:\n      - "80:8080"\n      - "443:8443"\n'
        return block

    (web / "Dockerfile.caddy").write_text("FROM caddy:2\nUSER caddy:caddy\n")
    TWO_HARDENED = "services:\n" + svc("caddy") + svc("b")

    # 1. Two services, neither hardened -> FAIL.
    compose.write_text("services:\n" + svc("caddy", False) + svc("b", False))
    assert checks.check_container_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when services lack no-new-privileges + cap_drop"

    # 2. One hardened, one not -> FAIL (not all services).
    compose.write_text("services:\n" + svc("caddy", True) + svc("b", False))
    assert checks.check_container_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when only some services are hardened"

    # 3. Has cap_drop ALL but no no-new-privileges -> FAIL.
    compose.write_text("services:\n  caddy:\n    image: x:1\n    cap_drop:\n      - ALL\n"
                       "  b:\n    image: x:1\n    cap_drop:\n      - ALL\n")
    assert checks.check_container_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when privilege-escalation is not forbidden"

    # 4. All hardened but CI lacks the prod-stack-boot validator -> FAIL.
    compose.write_text(TWO_HARDENED)
    (gh / "ci.yml").write_text("jobs:\n  x:\n    steps:\n      run: echo nothing\n")
    assert checks.check_container_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not boot the hardened stack to prove it still serves"

    # 5. All hardened + the boot validator present -> OK.
    (gh / "ci.yml").write_text("jobs:\n  prod-stack-boot:\n    steps:\n      run: echo boot\n")
    assert checks.check_container_hardening(tmp_path)[0].level == "OK", \
        "must PASS when every service drops caps + forbids escalation, validated by the boot job"

    # 6. v9.239: the edge adds NET_BIND_SERVICE back -> FAIL (root-with-a-capability posture).
    compose.write_text("services:\n" + svc("caddy", cap_add="NET_BIND_SERVICE") + svc("b"))
    assert checks.check_container_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when the edge adds a capability back instead of running unprivileged"

    # 7. v9.239: the edge image runs as root -> FAIL.
    compose.write_text(TWO_HARDENED)
    (web / "Dockerfile.caddy").write_text("FROM caddy:2\nUSER root\n")
    assert checks.check_container_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dockerfile.caddy runs the edge as root"
    (web / "Dockerfile.caddy").write_text("FROM caddy:2\n")
    assert checks.check_container_hardening(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dockerfile.caddy sets no USER at all"


def test_edge_pq_kex_check_discriminates(tmp_path):
    ref = tmp_path / "docs" / "reference"
    ref.mkdir(parents=True)
    doc = ref / "PQC-POSTURE.md"
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)
    ci = gh / "ci.yml"

    CLAIM_DOC = "## edge\nThe edge negotiates X25519MLKEM768 hybrid KEX.\n"
    PROOF_CI = ("jobs:\n  caddy-edge:\n    steps:\n      run: |\n"
                "        g=$(openssl s_client ... | grep -i 'Negotiated TLS1.3 group')\n"
                "        echo \"$g\" | grep -q 'X25519MLKEM768' || exit 1\n")

    # 1. Doc makes NO edge-KEX claim -> OK (nothing to pin).
    doc.write_text("## edge\nThe edge uses classical ECDHE.\n")
    ci.write_text("jobs:\n  x:\n    steps:\n      run: echo hi\n")
    assert checks.check_edge_pq_kex(tmp_path)[0].level == "OK", \
        "must PASS (nothing to pin) when the doc makes no hybrid-KEX claim"

    # 2. Doc CLAIMS the hybrid group but CI never mentions it -> FAIL.
    doc.write_text(CLAIM_DOC)
    ci.write_text("jobs:\n  x:\n    steps:\n      run: echo hi\n")
    assert checks.check_edge_pq_kex(tmp_path)[0].level == "FAIL", \
        "must FAIL when the doc claims the hybrid KEX but CI does not prove it"

    # 3. CI names the group but never reads the negotiated group -> FAIL.
    doc.write_text(CLAIM_DOC)
    ci.write_text("jobs:\n  x:\n    steps:\n      run: echo X25519MLKEM768 is great\n")
    assert checks.check_edge_pq_kex(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI mentions the group but does not read the negotiated group"

    # 4. CI reads the group but does not GATE on it (no grep -q assertion) -> FAIL.
    doc.write_text(CLAIM_DOC)
    ci.write_text("jobs:\n  x:\n    steps:\n      run: |\n"
                  "        echo X25519MLKEM768; echo 'Negotiated TLS1.3 group: x'\n")
    assert checks.check_edge_pq_kex(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not gate on the negotiated group"

    # 5. Doc claims it AND CI proves + gates on it -> OK.
    doc.write_text(CLAIM_DOC)
    ci.write_text(PROOF_CI)
    assert checks.check_edge_pq_kex(tmp_path)[0].level == "OK", \
        "must PASS when the doc claim is backed by a gating CI handshake proof"


def test_sast_scanning_check_discriminates(tmp_path):
    gh = tmp_path / ".github" / "workflows"
    gh.mkdir(parents=True)

    def write_ci(text):
        (gh / "ci.yml").write_text(text)

    # 1. No bandit in CI -> FAIL.
    write_ci("jobs:\n  test:\n    steps: []\n")
    assert checks.check_sast_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not run bandit"

    # 2. bandit present but not gating on high severity -> FAIL.
    write_ci("jobs:\n  s:\n    steps:\n      run: bandit -r polaris_web\n")
    assert checks.check_sast_scanning(tmp_path)[0].level == "FAIL", \
        "must FAIL when bandit does not gate on high severity"

    # 3. bandit gating on high severity -> OK.
    write_ci("jobs:\n  s:\n    steps:\n      run: bandit -r polaris_web polaris_cli --severity-level high -q\n")
    assert checks.check_sast_scanning(tmp_path)[0].level == "OK", \
        "must PASS when bandit gates on high severity"


def test_verify_enforced_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    gh = tmp_path / ".github" / "workflows"
    web.mkdir(); gh.mkdir(parents=True)
    GOOD_PQC = (
        "def signature_with_key_for_token(t):\n"
        "    if flag:\n"
        "        r = sign(t)\n"
        "        if not verify(t, r.signature_hex, r.public_key_hex):\n"
        "            raise SigningError('nope')\n"
        "        return r\n"
        "    return digest, LABEL, None\n\n"
        "def verify(m, s, k):\n    return True\n"
        "def trust_anchor_public_key_hex():\n    return None\n"
        "def verify_token_signature(t, s, a):\n    return True\n"
    )
    GOOD_CI = "jobs:\n  pqc-real:\n    steps:\n      run: assert verify_token_signature(x)\n"

    def write(pqc, ci=GOOD_CI):
        (web / "pqc_signing.py").write_text(pqc)
        (gh / "ci.yml").write_text(ci)

    # 1. Missing verify_token_signature / trust anchor -> FAIL.
    write("def signature_bytes_for_token(t):\n    return digest\n\ndef verify(m,s,k):\n    return True\n")
    assert checks.check_verify_enforced(tmp_path)[0].level == "FAIL", \
        "must FAIL without the use-path verification primitive + trust anchor"

    # 2. Has the functions, but issuance does not self-verify -> FAIL.
    write("def signature_with_key_for_token(t):\n    return sign(t).sig, lbl, pk\n\n"
          "def verify(m,s,k):\n    return True\n"
          "def trust_anchor_public_key_hex():\n    return None\n"
          "def verify_token_signature(t,s,a):\n    return True\n")
    assert checks.check_verify_enforced(tmp_path)[0].level == "FAIL", \
        "must FAIL when signature_with_key_for_token does not self-verify"

    # 3. Self-verifies + functions present + CI exercises it -> OK.
    write(GOOD_PQC)
    assert checks.check_verify_enforced(tmp_path)[0].level == "OK", \
        "must PASS when issuance self-verifies and CI exercises verify_token_signature"

    # 4. CI does not exercise verify_token_signature -> FAIL.
    write(GOOD_PQC, ci="jobs:\n  pqc-real:\n    steps:\n      run: echo nothing\n")
    assert checks.check_verify_enforced(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not exercise verify-at-use"


def test_pqc_second_witness_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    gh = tmp_path / ".github" / "workflows"
    web.mkdir(); gh.mkdir(parents=True)

    # A passing module: verify_both + an independent (cryptography MLDSA65) witness,
    # a refused disagreement, and all three real-verify sites routed through it.
    GOOD_PQC = (
        "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "def _verify_second_witness(m, s, k):\n"
        "    return mldsa.MLDSA65PublicKey.from_public_bytes(b'').verify(s, m)\n"
        "def verify_both(m, s, k):\n"
        "    if primary != witness:\n"
        "        log('DISAGREEMENT')\n"
        "        return False\n"
        "    return primary\n"
        "def signature_with_key_for_token(t):\n"
        "    if not verify_both(t, r.signature_hex, r.public_key_hex):\n"
        "        raise SigningError('nope')\n"
        "    return r\n"
        "def verify_stored_signature(t, s, k):\n    return verify_both(t, s, k)\n"
        "def verify_token_signature(t, s, a):\n    return verify_both(t, s, anchor)\n"
    )
    GOOD_CI = "jobs:\n  pqc-real:\n    steps:\n      run: python -m unittest SecondWitnessTests\n"

    def write(pqc, ci=GOOD_CI):
        (web / "pqc_signing.py").write_text(pqc)
        (gh / "ci.yml").write_text(ci)

    # 1. No verify_both / second witness -> FAIL.
    write("def verify(m, s, k):\n    return True\n")
    assert checks.check_pqc_second_witness(tmp_path)[0].level == "FAIL", \
        "must FAIL without verify_both + _verify_second_witness"

    # 2. A second witness that is just another liboqs call (no independent impl) -> FAIL.
    write(GOOD_PQC.replace("from cryptography.hazmat.primitives.asymmetric import mldsa\n", "")
                  .replace("mldsa.MLDSA65PublicKey.from_public_bytes(b'').verify(s, m)", "oqs.verify(s, m)"))
    assert checks.check_pqc_second_witness(tmp_path)[0].level == "FAIL", \
        "must FAIL when the witness is not an independent implementation (cryptography MLDSA65)"

    # 3. Disagreement not refused -> FAIL.
    write(GOOD_PQC.replace("log('DISAGREEMENT')\n        ", ""))
    assert checks.check_pqc_second_witness(tmp_path)[0].level == "FAIL", \
        "must FAIL when a witness disagreement is not refused/logged"

    # 4. A real-verify site bypasses verify_both -> FAIL.
    write(GOOD_PQC.replace(
        "def verify_token_signature(t, s, a):\n    return verify_both(t, s, anchor)\n",
        "def verify_token_signature(t, s, a):\n    return verify(t, s, anchor)\n"))
    assert checks.check_pqc_second_witness(tmp_path)[0].level == "FAIL", \
        "must FAIL when a verify site routes around verify_both (lone verifier)"

    # 5. CI does not run the two-witness agreement test -> FAIL.
    write(GOOD_PQC, ci="jobs:\n  pqc-real:\n    steps:\n      run: echo nothing\n")
    assert checks.check_pqc_second_witness(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not prove the two witnesses agree"

    # 6. All present -> OK.
    write(GOOD_PQC)
    assert checks.check_pqc_second_witness(tmp_path)[0].level == "OK", (
        "must PASS with verify_both, an independent witness, a refused disagreement, "
        "all sites routed through it, and CI proving agreement")


def test_pqc_posture_check_discriminates(tmp_path):
    ref = tmp_path / "docs" / "reference"
    ref.mkdir(parents=True)
    doc = ref / "PQC-POSTURE.md"

    GOOD = (
        "# PQC Posture\n"
        "Audited against NIST FIPS 204 and IR 8547 (deprecate 2030, disallow 2035).\n"
        "See the production-readiness ledger; nothing here claims deployability.\n"
        "## What is post-quantum today\n"
        "The token signature is ML-DSA-65 (FIPS 204), the ZK proof is FRI-based.\n"
        "## What is still classical\n"
        "TLS key exchange is classical ECDHE (harvest-now). WebAuthn operator MFA "
        "uses classical ECDSA/EdDSA/RSA.\n"
    )

    # 1. Missing doc -> FAIL.
    assert checks.check_pqc_posture(tmp_path)[0].level == "FAIL", "must FAIL with no posture doc"

    # 2. Only the rosy half (no 'what is still classical') -> FAIL.
    doc.write_text(GOOD.split("## What is still classical")[0])
    assert checks.check_pqc_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when the still-classical half is absent (one-sided claim)"

    # 3. Has both sections but omits a classical surface (no WebAuthn) -> FAIL.
    doc.write_text(GOOD.replace("WebAuthn operator MFA uses classical ECDSA/EdDSA/RSA.", "Nothing else."))
    assert checks.check_pqc_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when a classical surface (WebAuthn) is not named"

    # 4. Drops the NIST timeline mapping -> FAIL.
    doc.write_text(GOOD.replace("deprecate 2030, disallow 2035", "someday"))
    assert checks.check_pqc_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL without the NIST 2030/2035 timeline"

    # 5. Overclaims by dropping the production-readiness disclaimer -> FAIL.
    doc.write_text(GOOD.replace(
        "See the production-readiness ledger; nothing here claims deployability.\n", ""))
    assert checks.check_pqc_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when the production-readiness disclaimer is gone"

    # 6. Honest, two-sided, timeline-mapped, disclaimed -> OK.
    doc.write_text(GOOD)
    assert checks.check_pqc_posture(tmp_path)[0].level == "OK", \
        "must PASS an honest, two-sided, NIST-mapped, non-overclaiming audit"


def test_prod_images_digest_pinned_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    gh = tmp_path / ".github"
    web.mkdir(); gh.mkdir()
    (gh / "dependabot.yml").write_text("version: 2\nupdates:\n  - package-ecosystem: docker\n")

    def write(compose):
        (web / "docker-compose.prod.yml").write_text(compose)

    PINNED = ("services:\n"
              "  caddy:\n    image: caddy:2-alpine@sha256:" + "a" * 64 + "\n"
              "  app:\n    build: .\n    image: polaris-app:prod\n"
              "  redis:\n    image: redis:7-alpine@sha256:" + "b" * 64 + "\n")

    # 1. A third-party image pinned only by tag -> FAIL.
    write("services:\n  caddy:\n    image: caddy:2-alpine\n"
          "  app:\n    image: polaris-app:prod\n")
    assert checks.check_prod_images_digest_pinned(tmp_path)[0].level == "FAIL", \
        "must FAIL when a third-party image is tag-pinned only"

    # 2. All third-party images digest-pinned, locally-built exempt -> OK.
    write(PINNED)
    assert checks.check_prod_images_digest_pinned(tmp_path)[0].level == "OK", \
        "must PASS when every third-party image is @sha256-pinned (polaris-* exempt)"

    # 2b. v9.237: a self-built image whose Dockerfile pulls a base by tag -> FAIL;
    #     pinned base, and FROM lines that name an earlier stage, -> OK.
    BUILT = PINNED + "  pgbouncer:\n    build:\n      context: .\n      dockerfile: Dockerfile.pgbouncer\n    image: polaris-pgbouncer:prod\n"
    write(BUILT)
    (web / "Dockerfile.pgbouncer").write_text("FROM alpine:3.24\nRUN true\n")
    assert checks.check_prod_images_digest_pinned(tmp_path)[0].level == "FAIL", \
        "must FAIL when a self-built image's base is pinned by tag only"
    (web / "Dockerfile.pgbouncer").write_text(
        "FROM alpine:3.24@sha256:" + "c" * 64 + " AS builder\nRUN true\nFROM builder\nRUN true\n")
    assert checks.check_prod_images_digest_pinned(tmp_path)[0].level == "OK", \
        "must PASS when every base is digest-pinned and stage references are not counted as pulls"
    write(PINNED)

    # 3. Digest-pinned but Dependabot lacks the docker ecosystem -> FAIL.
    (gh / "dependabot.yml").write_text("version: 2\nupdates:\n  - package-ecosystem: pip\n")
    write(PINNED)
    assert checks.check_prod_images_digest_pinned(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dependabot does not track docker (pins would never update)"


def test_alert_rules_check_discriminates(tmp_path):
    obs = tmp_path / "deploy" / "observability"
    obs.mkdir(parents=True)
    GOOD_RULES = ("groups:\n  - name: polaris\n    rules:\n"
                  "      - alert: PolarisAppDown\n        expr: up == 0\n"
                  "      - alert: PolarisHigh5xx\n        expr: ratio > 0.01\n")
    GOOD_CFG = ("scrape_configs:\n  - job_name: polaris\n    metrics_path: /metrics\n"
                "rule_files:\n  - polaris-alerts.yml\n")

    GOOD_CFG = GOOD_CFG.replace("  - polaris-alerts.yml\n", "  - polaris-alerts.yml\n  - polaris-slo.yml\n")
    GOOD_SLO = ("groups:\n  - name: polaris-slo\n    rules:\n"
                + "".join(f"      - record: {r}\n        expr: x\n" for r in (
                    "polaris:sli_availability:ratio_30d", "polaris:error_budget_spent:ratio_30d",
                    "polaris:error_budget_burn_rate:1h", "polaris:sli_request_latency_p99:30d",
                    "polaris:sli_db_latency_p99:30d")))
    def write(rules=GOOD_RULES, cfg=GOOD_CFG, slo=GOOD_SLO):
        (obs / "polaris-alerts.yml").write_text(rules)
        (obs / "prometheus.yml").write_text(cfg)
        (obs / "polaris-slo.yml").write_text(slo)

    # 1. Rules file missing a key alert -> FAIL.
    write(rules="groups:\n  - name: polaris\n    rules:\n      - alert: SomethingElse\n        expr: x\n")
    assert checks.check_alert_rules(tmp_path)[0].level == "FAIL", \
        "must FAIL when PolarisHigh5xx/PolarisAppDown are absent"

    # 2. Scrape config does not load the rules -> FAIL.
    write(cfg="scrape_configs:\n  - job_name: polaris\n    metrics_path: /metrics\n")
    assert checks.check_alert_rules(tmp_path)[0].level == "FAIL", \
        "must FAIL when prometheus.yml does not load the rule file"

    # 3. Both present + wired -> OK.
    write()
    assert checks.check_alert_rules(tmp_path)[0].level == "OK", \
        "must PASS with shipped rules + a scrape config that loads them"

    # 3b. v9.241: the SLO recording rules.
    write(slo="groups:\n  - name: polaris-slo\n    rules:\n      - record: polaris:sli_availability:ratio_30d\n        expr: x\n")
    assert checks.check_alert_rules(tmp_path)[0].level == "FAIL", \
        "must FAIL when a recorded SLI SLOS.md names is missing"
    write(cfg="scrape_configs:\n  - job_name: polaris\n    metrics_path: /metrics\nrule_files:\n  - polaris-alerts.yml\n")
    assert checks.check_alert_rules(tmp_path)[0].level == "FAIL", \
        "must FAIL when prometheus.yml does not load the SLO rules"
    write()
    dash = tmp_path / "deploy" / "observability" / "grafana" / "dashboards"
    dash.mkdir(parents=True)
    (dash / "polaris-overview.json").write_text('{"uid": "polaris-overview", "panels": [{"targets": [{"expr": "up"}]}]}')
    assert checks.check_alert_rules(tmp_path)[0].level == "FAIL", \
        "must FAIL when the overview dashboard does not show the error budget"
    (dash / "polaris-overview.json").write_text('{"uid": "polaris-overview", "panels": [{"targets": [{"expr": "polaris:error_budget_spent:ratio_30d"}]}]}')
    assert checks.check_alert_rules(tmp_path)[0].level == "OK", \
        "must PASS when the dashboard shows the budget"

    # 4. Missing files -> FAIL.
    (obs / "polaris-alerts.yml").unlink()
    assert checks.check_alert_rules(tmp_path)[0].level == "FAIL", \
        "must FAIL when the artifact does not ship"


def test_alert_runbooks_check_discriminates(tmp_path):
    obs = tmp_path / "deploy" / "observability"
    ref = tmp_path / "docs" / "operator"
    obs.mkdir(parents=True)
    ref.mkdir(parents=True)
    RULES = ("groups:\n  - name: polaris\n    rules:\n"
             "      - alert: PolarisAppDown\n        expr: up == 0\n"
             "      - alert: PolarisHigh5xx\n        expr: ratio > 0.01\n")

    def write_rules(text=RULES):
        (obs / "polaris-alerts.yml").write_text(text)

    def write_book(text):
        (ref / "RUNBOOKS.md").write_text(text)

    # 1. An alert with no runbook section -> FAIL.
    write_rules()
    write_book("# RUNBOOKS\n\n## PolarisAppDown\n\nbody\n")
    out = checks.check_alert_runbooks(tmp_path)
    assert out[0].level == "FAIL", "must FAIL when an alert lacks a runbook section"
    assert "PolarisHigh5xx" in out[0].message

    # 2. Every alert documented, one-to-one -> OK.
    write_book("# RUNBOOKS\n\n## PolarisAppDown\n\nbody\n\n## PolarisHigh5xx\n\nbody\n")
    assert checks.check_alert_runbooks(tmp_path)[0].level == "OK", \
        "must PASS when every alert has exactly one runbook section"

    # 3. An orphan runbook for an alert that no longer exists -> FAIL.
    write_book("# RUNBOOKS\n\n## PolarisAppDown\n\nbody\n\n## PolarisHigh5xx\n\nbody\n"
               "\n## PolarisGhostAlert\n\nbody\n")
    out = checks.check_alert_runbooks(tmp_path)
    assert out[0].level == "FAIL", "must FAIL on an orphan runbook section"
    assert "PolarisGhostAlert" in out[0].message

    # 4. Missing RUNBOOKS.md entirely -> FAIL.
    (ref / "RUNBOOKS.md").unlink()
    assert checks.check_alert_runbooks(tmp_path)[0].level == "FAIL", \
        "must FAIL when RUNBOOKS.md does not exist"


def test_encryption_at_rest_posture_check_discriminates(tmp_path):
    op = tmp_path / "docs" / "operator"
    sql = tmp_path / "polaris_sql"
    op.mkdir(parents=True)
    sql.mkdir(parents=True)
    GOOD_SCHEMA = "proof_path JSONB NOT NULL,\n-- v1 stores proof_path in plaintext\n"
    GOOD_DOC = (
        "# at-rest posture\n"
        "Polaris does **not** encrypt the live database at rest.\n"
        "Sensitive at rest: Individual.legal_name, Individual.date_of_birth, and\n"
        "TokenStateEpochLeaf.proof_path (stored in plaintext, schema-acknowledged).\n"
        "The operator-gated control is host volume encryption (LUKS / fscrypt).\n"
    )

    def write(doc=GOOD_DOC, schema=GOOD_SCHEMA):
        (op / "ENCRYPTION-AT-REST.md").write_text(doc)
        (sql / "01_schema.sql").write_text(schema)

    # 1. all present and honest -> OK.
    write()
    assert checks.check_encryption_at_rest_posture(tmp_path)[0].level == "OK", \
        "must PASS an honest, schema-grounded posture doc"

    # 2. doc does not name proof_path -> FAIL.
    write(doc=GOOD_DOC.replace("proof_path", "the merkle leaves"))
    assert checks.check_encryption_at_rest_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when the plaintext proof_path surface is not named"

    # 3. doc does not name the PII columns -> FAIL.
    write(doc=GOOD_DOC.replace("legal_name", "the name"))
    assert checks.check_encryption_at_rest_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when the PII columns are not named"

    # 4. schema still plaintext but doc never says 'plaintext' -> FAIL (drift).
    write(doc=GOOD_DOC.replace("plaintext", "stored"))
    assert checks.check_encryption_at_rest_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when the doc drifts from the schema's plaintext reality"

    # 5. no host-level encryption path named -> FAIL.
    write(doc=GOOD_DOC.replace("(LUKS / fscrypt)", "(somehow)"))
    assert checks.check_encryption_at_rest_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL without the host-level LUKS/fscrypt path"

    # 6. overclaiming: drops the honest 'does not encrypt' disclaimer -> FAIL.
    write(doc=GOOD_DOC.replace("does **not** encrypt the live database at rest",
                               "encrypts the live database at rest"))
    assert checks.check_encryption_at_rest_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when the doc overclaims that the live DB is encrypted"

    # 7. doc missing entirely -> FAIL.
    (op / "ENCRYPTION-AT-REST.md").unlink()
    assert checks.check_encryption_at_rest_posture(tmp_path)[0].level == "FAIL", \
        "must FAIL when the posture doc is absent"


def test_erasure_procedure_check_discriminates(tmp_path):
    sql = tmp_path / "polaris_sql"
    op = tmp_path / "docs" / "operator"
    sql.mkdir(parents=True)
    op.mkdir(parents=True)
    GOOD_SCHEMA = "CREATE TABLE IndividualErasureEvent (erasure_id SERIAL);\n"
    GOOD_TRIG = "CREATE TRIGGER trg_erasure_append_only BEFORE UPDATE OR DELETE ON IndividualErasureEvent\n"
    GOOD_PRIVACY = "Erasure is real: uc_pseudonymize_individual pseudonymizes legal_name.\n"
    GOOD_PROC = (
        "CREATE OR REPLACE PROCEDURE uc_pseudonymize_individual(p_id INTEGER, p_actor INTEGER, p_reason VARCHAR)\n"
        "LANGUAGE plpgsql AS $$\n"
        "BEGIN\n"
        "    IF v_role <> 'admin' THEN RAISE EXCEPTION 'must be admin'; END IF;\n"
        "    UPDATE Individual SET legal_name = 'PSEUDONYMIZED' WHERE individual_id = p_id;\n"
        "    INSERT INTO IndividualErasureEvent (individual_id) VALUES (p_id);\n"
        "END$$;\n"
    )

    def write(schema=GOOD_SCHEMA, proc=GOOD_PROC, trig=GOOD_TRIG, privacy=GOOD_PRIVACY):
        (sql / "01_schema.sql").write_text(schema)
        (sql / "05_procedures.sql").write_text(proc)
        (sql / "06_triggers.sql").write_text(trig)
        (op / "PRIVACY.md").write_text(privacy)

    # 1. fully wired -> OK.
    write()
    assert checks.check_erasure_procedure(tmp_path)[0].level == "OK", \
        "must PASS the complete erasure wiring"

    # 2. no erasure-log table -> FAIL.
    write(schema="-- no table here\n")
    assert checks.check_erasure_procedure(tmp_path)[0].level == "FAIL", \
        "must FAIL without the IndividualErasureEvent table"

    # 3. procedure issues a DELETE (covert deletion path around C1) -> FAIL.
    write(proc=GOOD_PROC.replace(
        "INSERT INTO IndividualErasureEvent (individual_id) VALUES (p_id);",
        "DELETE FROM Individual WHERE individual_id = p_id;\n"
        "    INSERT INTO IndividualErasureEvent (individual_id) VALUES (p_id);"))
    assert checks.check_erasure_procedure(tmp_path)[0].level == "FAIL", \
        "must FAIL when the procedure can DELETE (it must only pseudonymize)"

    # 4. procedure is not admin-gated -> FAIL.
    write(proc=GOOD_PROC.replace("must be admin", "anyone may"))
    assert checks.check_erasure_procedure(tmp_path)[0].level == "FAIL", \
        "must FAIL when the procedure is not admin-gated"

    # 5. the erasure log is not append-only (no trigger) -> FAIL.
    write(trig="-- no erasure trigger\n")
    assert checks.check_erasure_procedure(tmp_path)[0].level == "FAIL", \
        "must FAIL when IndividualErasureEvent has no append-only trigger"

    # 6. PRIVACY.md does not point at the real mechanism -> FAIL.
    write(privacy="Erasure is theoretically possible.\n")
    assert checks.check_erasure_procedure(tmp_path)[0].level == "FAIL", \
        "must FAIL when PRIVACY.md does not reference uc_pseudonymize_individual"


def test_replication_scaffolding_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    scripts = tmp_path / "scripts"
    op = tmp_path / "docs" / "operator"
    gh = tmp_path / ".github" / "workflows"
    for d in (web, scripts, op, gh):
        d.mkdir(parents=True)
    GOOD_INIT = (
        "psql -c \"ALTER SYSTEM SET wal_level = replica;\"\n"
        "psql -c \"CREATE ROLE polaris_replicator WITH LOGIN REPLICATION PASSWORD 'x'\"\n"
        "echo 'host replication polaris_replicator samenet scram-sha-256' >> pg_hba.conf\n"
    )
    GOOD_COMPOSE = ("services:\n  postgres:\n    environment:\n"
                    "      POLARIS_REPLICATOR_PASSWORD_FILE: /run/secrets/polaris_replicator_password\n"
                    "    secrets:\n      - polaris_replicator_password\n")
    GOOD_SECRETS = "write_secret_if_missing polaris_replicator_password 24\n"
    GOOD_DOC = ("# failover\nStandby is operator-supplied and placement.\n"
                "Bootstrap with pg_basebackup -R; promote with lease().\n")
    GOOD_CI = "docker run pg_basebackup ...\npsql -c 'SELECT * FROM pg_stat_replication'\n"

    def write(init=GOOD_INIT, compose=GOOD_COMPOSE, secrets=GOOD_SECRETS, doc=GOOD_DOC, ci=GOOD_CI):
        (web / "docker-init.sh").write_text(init)
        (web / "docker-compose.prod.yml").write_text(compose)
        (scripts / "polaris-generate-secrets.sh").write_text(secrets)
        (op / "FAILOVER.md").write_text(doc)
        (gh / "ci.yml").write_text(ci)

    # 1. fully wired -> OK.
    write()
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "OK", \
        "must PASS the complete replication scaffolding"

    # 2. primary not made replication-ready (no wal_level) -> FAIL.
    write(init=GOOD_INIT.replace("ALTER SYSTEM SET wal_level = replica", "echo nope"))
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL without wal_level=replica in docker-init"

    # 3. no replication role -> FAIL.
    write(init=GOOD_INIT.replace("REPLICATION", "NOREPL"))
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL without the polaris_replicator REPLICATION role"

    # 4. secret not minted -> FAIL.
    write(secrets="write_secret_if_missing polaris_db_password 24\n")
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when the replicator password is not generated"

    # 5. compose does not mount the secret -> FAIL.
    write(compose="services:\n  postgres:\n    environment:\n      POLARIS_ENV: production\n")
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when the prod compose does not mount the replicator secret"

    # 6. doc does not document the bootstrap/promotion -> FAIL.
    write(doc="# failover\nStandby is operator-supplied and placement.\nSomehow promote it.\n")
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when FAILOVER.md omits pg_basebackup/lease"

    # 7. doc overclaims (not honest about operator-supplied standby) -> FAIL.
    write(doc="# failover\nA running standby ships out of the box.\n"
              "Bootstrap with pg_basebackup -R; promote with lease().\n")
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when FAILOVER.md does not say the standby host is operator-supplied"

    # 8. no CI round-trip -> FAIL.
    write(ci="echo no replication test here\n")
    assert checks.check_replication_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when ci.yml has no replication round-trip"


def test_pgbackrest_scaffolding_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    op = tmp_path / "docs" / "operator"
    gh = tmp_path / ".github" / "workflows"
    scripts = tmp_path / "scripts"
    for d in (web, op, gh, scripts):
        d.mkdir(parents=True)
    GOOD_DF = "FROM postgres:16-alpine@sha256:abc\nRUN apk add --no-cache pgbackrest\n"
    GOOD_CONF = ("[global]\nrepo1-path=/var/lib/pgbackrest\n# swap repo1 for s3 for offsite;\n"
                 "# S3 keys via a 0600 file mounted at /etc/pgbackrest/conf.d/, not env\n"
                 "[polaris]\npg1-path=/var/lib/postgresql/data\n")
    GOOD_COMPOSE = ("services:\n  postgres:\n    build:\n      dockerfile: Dockerfile.postgres\n"
                    "    environment:\n      POLARIS_PGBACKREST_ENABLED: \"0\"\n"
                    "    volumes:\n      - ./pgbackrest.conf:/etc/pgbackrest/pgbackrest.conf:ro\n")
    GOOD_INIT = ("if [ \"$POLARIS_PGBACKREST_ENABLED\" = \"1\" ]; then\n"
                 "  psql -c \"ALTER SYSTEM SET archive_mode = on;\"\n"
                 "  psql -c \"ALTER SYSTEM SET archive_command = 'pgbackrest --stanza=polaris archive-push %p';\"\n"
                 "  if ! grep -qE 'repo1-type[[:space:]]*=[[:space:]]*s3' /etc/pgbackrest/pgbackrest.conf; then\n"
                 "    echo 'WARNING: archiving to a LOCAL repo (no repo1-type=s3)' >&2\n  fi\nfi\n")
    GOOD_DR = "Bootstrap: pgbackrest --stanza=polaris stanza-create\n"
    GOOD_CI = "docker build Dockerfile.postgres\npgbackrest --stanza=polaris restore\n"
    GOOD_DEPLOY = ("if [ \"$POLARIS_PGBACKREST_ENABLED\" = \"1\" ]; then\n"
                   "  docker compose exec postgres pgbackrest --stanza=polaris stanza-create\nfi\n")

    def write(df=GOOD_DF, conf=GOOD_CONF, compose=GOOD_COMPOSE, init=GOOD_INIT, dr=GOOD_DR,
              ci=GOOD_CI, deploy=GOOD_DEPLOY):
        (web / "Dockerfile.postgres").write_text(df)
        (web / "pgbackrest.conf").write_text(conf)
        (web / "docker-compose.prod.yml").write_text(compose)
        (web / "docker-init.sh").write_text(init)
        (op / "DR.md").write_text(dr)
        (gh / "ci.yml").write_text(ci)
        (scripts / "polaris-deploy.sh").write_text(deploy)

    # 1. fully wired -> OK.
    write()
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "OK", \
        "must PASS the complete pgBackRest scaffolding"

    # 2. image does not install pgbackrest -> FAIL.
    write(df="FROM postgres:16-alpine@sha256:abc\nRUN echo hi\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when the postgres image lacks pgbackrest"

    # 3. base not digest-pinned -> FAIL.
    write(df="FROM postgres:16-alpine\nRUN apk add --no-cache pgbackrest\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when the image base is not digest-pinned"

    # 4. config does not document the offsite S3 swap -> FAIL (overclaiming).
    write(conf="[global]\nrepo1-path=/var/lib/pgbackrest\n[polaris]\npg1-path=/var/lib/postgresql/data\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when pgbackrest.conf does not document the offsite repo"

    # 5. archiving is not opt-in (no POLARIS_PGBACKREST_ENABLED gate) -> FAIL.
    write(init="psql -c \"ALTER SYSTEM SET archive_mode = on; archive-push\"\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when archiving is not gated behind POLARIS_PGBACKREST_ENABLED"

    # 6. DR.md does not document stanza-create -> FAIL.
    write(dr="just restore somehow\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when DR.md omits stanza-create"

    # 7. no CI restore round-trip -> FAIL.
    write(ci="echo no backup test\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when ci.yml has no pgBackRest restore round-trip"

    # 8. the deploy does not auto-bootstrap the stanza -> FAIL (v9.130).
    write(deploy="echo deploy without pgbackrest\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when polaris-deploy.sh does not stanza-create when archiving is enabled"

    # 9. docker-init does not warn about a local repo -> FAIL (v9.130).
    write(init=GOOD_INIT.replace("WARNING: archiving to a LOCAL repo (no repo1-type=s3)", "ok"))
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when docker-init does not warn on a local (non-s3) repo"

    # 10. the S3-cred guidance does not use a file-mounted config (conf.d) -> FAIL (v9.130).
    write(conf="[global]\nrepo1-path=/var/lib/pgbackrest\n# s3 swap\n[polaris]\npg1-path=/data\n",
          dr="Bootstrap: pgbackrest --stanza=polaris stanza-create\n")
    assert checks.check_pgbackrest_scaffolding(tmp_path)[0].level == "FAIL", \
        "must FAIL when S3-credential guidance does not use a mounted conf.d (env literals leak)"


def test_duress_alertable_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    obs = tmp_path / "deploy" / "observability"
    web.mkdir(parents=True)
    obs.mkdir(parents=True)
    GOOD_APP = (
        "_METRICS_DURESS = _PromCounter('polaris_duress_events_total', 'x')\n"
        "def _record_duress_async(token_id, context_id, requesting_agency_id):\n"
        "    observability.record_duress_event(individual_id=token_id)\n"
        "    _METRICS_DURESS.inc()\n"
        "\n\n"
        "def other():\n    pass\n"
    )
    GOOD_ALERTS = ("- alert: PolarisDuressEvent\n"
                   "  expr: increase(polaris_duress_events_total[5m]) > 0\n")

    def write(app=GOOD_APP, alerts=GOOD_ALERTS):
        (web / "app.py").write_text(app)
        (obs / "polaris-alerts.yml").write_text(alerts)

    # 1. fully wired -> OK.
    write()
    assert checks.check_duress_alertable(tmp_path)[0].level == "OK", \
        "must PASS when the duress counter is exposed, incremented, and alerted"

    # 2. duress is only in the JSON metrics, not a Prometheus counter -> FAIL.
    write(app="def _record_duress_async(t, c, a):\n    observability.record_duress_event(individual_id=t)\n\n\ndef o():\n    pass\n")
    assert checks.check_duress_alertable(tmp_path)[0].level == "FAIL", \
        "must FAIL when polaris_duress_events_total is not exposed on /metrics"

    # 3. counter exists but is NOT incremented at the record site -> FAIL.
    write(app=GOOD_APP.replace("    _METRICS_DURESS.inc()\n", ""))
    assert checks.check_duress_alertable(tmp_path)[0].level == "FAIL", \
        "must FAIL when the counter is never incremented (the alert would never fire)"

    # 4. no alert on the counter -> FAIL.
    write(alerts="- alert: PolarisAppDown\n  expr: up == 0\n")
    assert checks.check_duress_alertable(tmp_path)[0].level == "FAIL", \
        "must FAIL when no PolarisDuressEvent alert references the counter"


def test_prod_fail_closed_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    GOOD = (
        "_PRODUCTION = os.environ.get('POLARIS_ENV') == 'production'\n"
        "if _PRODUCTION:\n"
        "    m = os.environ.get('POLARIS_DB_SSLMODE', 'prefer')\n"
        "    if m not in ('require', 'verify-ca', 'verify-full'):\n"
        "        sys.exit(2)\n"
        "    if m in ('verify-ca', 'verify-full') and not os.environ.get('POLARIS_DB_SSLROOTCERT'):\n"
        "        sys.exit(2)\n"
        "    if os.environ.get('POLARIS_DURESS_SYNC') == '1':\n"
        "        sys.exit(2)\n"
    )
    # The 'prefer' token must appear (the message names the plaintext-capable modes).
    GOOD = GOOD + "# rejects prefer/allow/disable\n"
    # v9.277 (PE.4) — the HSM-sole-signer guard (flag-gated, outside _PRODUCTION).
    HSM_GUARD = (
        "if os.environ.get('POLARIS_REQUIRE_HSM_SOLE_SIGNER') == '1':\n"
        "    if os.environ.get('POLARIS_CUSTODY_DRIVER') != 'pkcs11':\n"
        "        sys.exit(2)\n"
        "    if os.environ.get('POLARIS_PQC_SIGNING_KEY_FILE'):\n"
        "        sys.exit(2)\n"
    )
    GOOD = GOOD + HSM_GUARD

    def write(app=GOOD):
        (web / "app.py").write_text(app)

    # 1. all guards present -> OK.
    write()
    assert checks.check_prod_fail_closed(tmp_path)[0].level == "OK", \
        "must PASS when the production fail-closed guards are present"

    # 2. no _PRODUCTION flag -> FAIL.
    write(app=GOOD.replace("_PRODUCTION", "_prod_flag"))
    assert checks.check_prod_fail_closed(tmp_path)[0].level == "FAIL", \
        "must FAIL without a _PRODUCTION flag"

    # 3. the sslmode guard is gone -> FAIL.
    write(app="_PRODUCTION = True\nif _PRODUCTION:\n    if os.environ.get('POLARIS_DURESS_SYNC') == '1':\n        sys.exit(2)\n")
    assert checks.check_prod_fail_closed(tmp_path)[0].level == "FAIL", \
        "must FAIL when the POLARIS_DB_SSLMODE guard is missing"

    # 4. verify-* does not require POLARIS_DB_SSLROOTCERT -> FAIL (v9.132).
    write(app="_PRODUCTION = True\nif _PRODUCTION:\n    m = os.environ.get('POLARIS_DB_SSLMODE', 'prefer')\n"
              "    if m not in ('require','verify-ca','verify-full'):\n        sys.exit(2)\n    # rejects prefer\n"
              "    if os.environ.get('POLARIS_DURESS_SYNC') == '1':\n        sys.exit(2)\n")
    assert checks.check_prod_fail_closed(tmp_path)[0].level == "FAIL", \
        "must FAIL when verify-* does not require POLARIS_DB_SSLROOTCERT"

    # 5. the duress-sync guard is gone -> FAIL.
    write(app="_PRODUCTION = True\nif _PRODUCTION:\n    m = os.environ.get('POLARIS_DB_SSLMODE', 'prefer')\n"
              "    if m not in ('require','verify-ca','verify-full'):\n        sys.exit(2)\n    # rejects prefer\n"
              "    if not os.environ.get('POLARIS_DB_SSLROOTCERT'):\n        sys.exit(2)\n")
    assert checks.check_prod_fail_closed(tmp_path)[0].level == "FAIL", \
        "must FAIL when the POLARIS_DURESS_SYNC guard is missing"

    # 6. (PE.4) the HSM-sole-signer guard is gone -> FAIL.
    write(app=GOOD.replace(HSM_GUARD, ""))
    assert checks.check_prod_fail_closed(tmp_path)[0].level == "FAIL", \
        "must FAIL when the HSM-sole-signer guard is missing"
    # 7. (PE.4) the HSM guard no longer forbids the file-key fallback -> FAIL.
    write(app=GOOD.replace("    if os.environ.get('POLARIS_PQC_SIGNING_KEY_FILE'):\n        sys.exit(2)\n", ""))
    assert checks.check_prod_fail_closed(tmp_path)[0].level == "FAIL", \
        "must FAIL when the HSM guard does not forbid POLARIS_PQC_SIGNING_KEY_FILE"


def test_prod_real_pqc_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    gh = tmp_path / ".github" / "workflows"
    web.mkdir(); gh.mkdir(parents=True)
    GOOD_DF = "FROM x\nRUN pip install liboqs-python\n"
    GOOD_COMPOSE = ("services:\n  app:\n    environment:\n"
                    "      POLARIS_USE_REAL_PQC: '1'\n"
                    "      POLARIS_PQC_SIGNING_KEY_FILE: /run/secrets/polaris_signing_key\n"
                    "    secrets:\n      - polaris_signing_key\n")
    GOOD_CI = "jobs:\n  d:\n    steps:\n      - name: Verify real ML-DSA-65 signing inside the prod image\n"

    def write(df=GOOD_DF, compose=GOOD_COMPOSE, ci=GOOD_CI):
        (web / "Dockerfile.prod").write_text(df)
        (web / "docker-compose.prod.yml").write_text(compose)
        (gh / "ci.yml").write_text(ci)

    # 1. liboqs not installed in the prod image -> FAIL.
    write(df="FROM x\nRUN pip install flask\n")
    assert checks.check_prod_real_pqc(tmp_path)[0].level == "FAIL", \
        "must FAIL when Dockerfile.prod does not install liboqs"

    # 2. liboqs present but the flag is off -> FAIL.
    write(compose="services:\n  app:\n    environment:\n      POLARIS_ENV: production\n")
    assert checks.check_prod_real_pqc(tmp_path)[0].level == "FAIL", \
        "must FAIL when POLARIS_USE_REAL_PQC is not set in prod"

    # 3. Flag on but no signing-key secret -> FAIL.
    write(compose="services:\n  app:\n    environment:\n      POLARIS_USE_REAL_PQC: '1'\n")
    assert checks.check_prod_real_pqc(tmp_path)[0].level == "FAIL", \
        "must FAIL when the signing-key secret is not mounted (no trust anchor)"

    # 4. CI does not verify real PQC in the prod image -> FAIL.
    write(ci="jobs:\n  d:\n    steps:\n      - name: build\n")
    assert checks.check_prod_real_pqc(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not verify real PQC inside the prod image"

    # 5. All three + CI verification -> OK.
    write()
    assert checks.check_prod_real_pqc(tmp_path)[0].level == "OK", \
        "must PASS with liboqs in the image, the flag on, the key secret, and CI verification"


def test_signature_self_contained_verify_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"; sql = tmp_path / "polaris_sql"
    web.mkdir(); sql.mkdir()

    def write(pqc, schema, proc, app):
        (web / "pqc_signing.py").write_text(pqc)
        (sql / "01_schema.sql").write_text(schema)
        (sql / "05_procedures.sql").write_text(proc)
        (web / "app.py").write_text(app)

    GOOD_PQC = "def signature_with_key_for_token(): ...\ndef verify_stored_signature(): ...\n"
    GOOD_SCHEMA = "CREATE TABLE TokenSignature (signing_public_key_hex TEXT);\n"
    GOOD_PROC = "FUNCTION uc1_issue_and_activate(p_signing_public_key_hex TEXT) ...\n"
    GOOD_APP = "x = pqc_signing.verify_stored_signature(a, b, c)\n"

    # 1. pqc_signing missing the functions -> FAIL.
    write("def sign(): ...\n", GOOD_SCHEMA, GOOD_PROC, GOOD_APP)
    assert checks.check_signature_self_contained_verify(tmp_path)[0].level == "FAIL"

    # 2. schema missing the column -> FAIL.
    write(GOOD_PQC, "CREATE TABLE TokenSignature (signature_bytes BYTEA);\n", GOOD_PROC, GOOD_APP)
    assert checks.check_signature_self_contained_verify(tmp_path)[0].level == "FAIL"

    # 3. procedure missing the param -> FAIL.
    write(GOOD_PQC, GOOD_SCHEMA, "FUNCTION uc1_issue_and_activate(p_signature_bytes BYTEA) ...\n", GOOD_APP)
    assert checks.check_signature_self_contained_verify(tmp_path)[0].level == "FAIL"

    # 4. token-detail does not verify -> FAIL.
    write(GOOD_PQC, GOOD_SCHEMA, GOOD_PROC, "render_template('tokens_detail.html')\n")
    assert checks.check_signature_self_contained_verify(tmp_path)[0].level == "FAIL"

    # 5. all wired -> OK.
    write(GOOD_PQC, GOOD_SCHEMA, GOOD_PROC, GOOD_APP)
    assert checks.check_signature_self_contained_verify(tmp_path)[0].level == "OK"


def test_deploy_syncs_db_objects_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    GOOD_MIG = "case x in\n  --sync-objects) MODE=sync ;;\nesac\nsync-objects) do_sync_objects ;;\n"
    GOOD_DEP = ('polaris-migrate.sh --up --target=docker-stack\n'
                'polaris-migrate.sh --sync-objects --target=docker-stack\n')

    def write(mig=GOOD_MIG, dep=GOOD_DEP):
        (scripts / "polaris-migrate.sh").write_text(mig)
        (scripts / "polaris-deploy.sh").write_text(dep)

    # 1. migrate script lacks --sync-objects -> FAIL.
    write(mig="case x in\n  --up) MODE=up ;;\nesac\n")
    assert checks.check_deploy_syncs_db_objects(tmp_path)[0].level == "FAIL", \
        "must FAIL when polaris-migrate.sh has no --sync-objects mode"

    # 2. deploy does not run sync-objects/migrate against the stack -> FAIL.
    write(dep="docker compose up -d\n")
    assert checks.check_deploy_syncs_db_objects(tmp_path)[0].level == "FAIL", \
        "must FAIL when the deploy does not apply migrations + sync objects"

    # 3. both present -> OK.
    write()
    assert checks.check_deploy_syncs_db_objects(tmp_path)[0].level == "OK", \
        "must PASS when migrate has --sync-objects and the deploy runs migrate + sync on the stack"


def test_prometheus_multiprocess_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    GOOD_APP = "PROMETHEUS_MULTIPROC_DIR\nMultiProcessCollector(reg)\n"
    GOOD_GCONF = "def child_exit(server, worker):\n    multiprocess.mark_process_dead(worker.pid)\n"
    GOOD_COMPOSE = "services:\n  app:\n    environment:\n      PROMETHEUS_MULTIPROC_DIR: /tmp/x\n"

    def write(app=GOOD_APP, gconf=GOOD_GCONF, compose=GOOD_COMPOSE):
        (web / "app.py").write_text(app)
        (web / "gunicorn.conf.py").write_text(gconf)
        (web / "docker-compose.prod.yml").write_text(compose)

    # 1. app.py does not aggregate via MultiProcessCollector -> FAIL.
    write(app="generate_latest(_METRICS_REGISTRY)\n")
    assert checks.check_prometheus_multiprocess(tmp_path)[0].level == "FAIL", \
        "must FAIL when /metrics does not aggregate across workers"

    # 2. gunicorn does not reap dead workers -> FAIL.
    write(gconf="def on_starting(s):\n    pass\n")
    assert checks.check_prometheus_multiprocess(tmp_path)[0].level == "FAIL", \
        "must FAIL without child_exit + mark_process_dead"

    # 3. prod compose does not set the dir -> FAIL.
    write(compose="services:\n  app:\n    environment:\n      POLARIS_ENV: production\n")
    assert checks.check_prometheus_multiprocess(tmp_path)[0].level == "FAIL", \
        "must FAIL when the prod compose does not set PROMETHEUS_MULTIPROC_DIR"

    # 4. all wired -> OK.
    write()
    assert checks.check_prometheus_multiprocess(tmp_path)[0].level == "OK", \
        "must PASS with multiprocess collector + child_exit reaping + the dir set"


def test_app_db_tls_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    GOOD_APP = ("DB_CONFIG = {'sslmode': os.environ.get('POLARIS_DB_SSLMODE', 'prefer')}\n"
                "if os.environ.get('POLARIS_DB_SSLROOTCERT'):\n"
                "    DB_CONFIG['sslrootcert'] = os.environ['POLARIS_DB_SSLROOTCERT']\n")
    GOOD_COMPOSE = ("services:\n  app:\n    environment:\n"
                    "      POLARIS_DB_SSLMODE: verify-ca\n"
                    "      POLARIS_DB_SSLROOTCERT: /etc/polaris-pgb-certs/pgbouncer.crt\n"
                    "  pgbouncer:\n    environment:\n"
                    "      PGBOUNCER_SERVER_TLS_SSLMODE: verify-ca\n"
                    "      PGBOUNCER_SERVER_TLS_CA_FILE: /etc/polaris-pg-certs/postgres.crt\n"
                    "      PGBOUNCER_CLIENT_TLS_SSLMODE: require\n"
                    "      PGBOUNCER_CLIENT_TLS_CERT_FILE: /etc/polaris-pgb-certs/pgbouncer.crt\n")
    GOOD_INIT = "psql -c \"ALTER SYSTEM SET ssl = on;\"\n"
    GOOD_ENTRY = ("server_tls_sslmode = $X\nserver_tls_ca_file = $C\nclient_tls_sslmode = $Y\n"
                  "case $S in verify-ca|verify-full) "
                  "echo 'requires PGBOUNCER_SERVER_TLS_CA_FILE' >&2; exit 1;; esac\n")

    def write(app=GOOD_APP, compose=GOOD_COMPOSE, init=GOOD_INIT, entry=GOOD_ENTRY):
        (web / "app.py").write_text(app)
        (web / "docker-compose.prod.yml").write_text(compose)
        (web / "docker-init.sh").write_text(init)
        (web / "pgbouncer-entrypoint.sh").write_text(entry)

    # 1. app does not set a configurable sslmode -> FAIL.
    write(app="DB_CONFIG = {'host': 'x'}\n")
    assert checks.check_app_db_tls(tmp_path)[0].level == "FAIL", \
        "must FAIL when DB_CONFIG has no configurable sslmode"

    # 2. app cannot pin the peer cert (no sslrootcert) -> FAIL.
    write(app="DB_CONFIG = {'sslmode': os.environ.get('POLARIS_DB_SSLMODE', 'prefer')}\n")
    assert checks.check_app_db_tls(tmp_path)[0].level == "FAIL", \
        "must FAIL when DB_CONFIG cannot pin the peer cert (no POLARIS_DB_SSLROOTCERT/sslrootcert)"

    # 3. compose only encrypts (require), does not verify-ca pin -> FAIL.
    write(compose=GOOD_COMPOSE.replace("POLARIS_DB_SSLMODE: verify-ca", "POLARIS_DB_SSLMODE: require"))
    assert checks.check_app_db_tls(tmp_path)[0].level == "FAIL", \
        "must FAIL when the app hop is only 'require' (encrypt), not verify-ca"

    # 4. pgbouncer backend hop not verify-ca / no CA file -> FAIL.
    write(compose=GOOD_COMPOSE.replace("PGBOUNCER_SERVER_TLS_SSLMODE: verify-ca", "PGBOUNCER_SERVER_TLS_SSLMODE: require"))
    assert checks.check_app_db_tls(tmp_path)[0].level == "FAIL", \
        "must FAIL when the pgbouncer<->postgres hop does not verify-ca pin"

    # 5. entrypoint does not wire the server CA file -> FAIL.
    write(entry="server_tls_sslmode = $X\nclient_tls_sslmode = $Y\n")
    assert checks.check_app_db_tls(tmp_path)[0].level == "FAIL", \
        "must FAIL when the entrypoint does not wire server_tls_ca_file"

    # 6. docker-init does not enable Postgres TLS -> FAIL.
    write(init="echo no tls\n")
    assert checks.check_app_db_tls(tmp_path)[0].level == "FAIL", \
        "must FAIL when docker-init does not enable Postgres ssl"

    # 7. all wired -> OK.
    write()
    assert checks.check_app_db_tls(tmp_path)[0].level == "OK", \
        "must PASS with verify-ca pinning on both hops + sslrootcert + CA file"


def test_correlation_id_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    GOOD_OBS = (
        "import contextvars, re, uuid\n"
        "_RE = re.compile(r'\\A[A-Za-z0-9-]{8,64}\\Z')\n"
        "_v = contextvars.ContextVar('rid', default='-')\n"
        "def validate_or_new_request_id(raw):\n"
        "    if isinstance(raw, str) and _RE.fullmatch(raw):\n"
        "        return raw\n"
        "    return uuid.uuid4().hex\n"
    )
    GOOD_APP = (
        "@app.before_request\n"
        "def _corr():\n"
        "    g._t = observability.set_request_id("
        "observability.validate_or_new_request_id(request.headers.get('X-Request-ID')))\n"
        "@app.teardown_request\n"
        "def _td(e):\n"
        "    reset_request_id(g._t)\n"
        "@app.after_request\n"
        "def _echo(r):\n"
        "    r.headers['X-Request-ID'] = observability.get_request_id()\n"
        "    return r\n"
    )
    GOOD_SEC = "def client_ip():\n    return request.remote_addr\n"

    def write(obs=GOOD_OBS, app=GOOD_APP, sec=GOOD_SEC):
        (web / "observability.py").write_text(obs)
        (web / "app.py").write_text(app)
        (web / "security.py").write_text(sec)

    # 1. all wired correctly -> OK.
    write()
    assert checks.check_correlation_id(tmp_path)[0].level == "OK", \
        "must PASS the correct wiring"

    # 2. unbounded validator (drop the {8,64} length bound) -> FAIL.
    write(obs=GOOD_OBS.replace("{8,64}", "+"))
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL when the id length is unbounded (log-injection / memory hole)"

    # 3. no uuid4 generation fallback -> FAIL.
    write(obs=GOOD_OBS.replace("uuid.uuid4().hex", "raw"))
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL without a generated id when none is supplied"

    # 4. the id-owning module gains DB access -> FAIL.
    write(obs=GOOD_OBS + "def leak(c):\n    c.execute('INSERT INTO audit VALUES (1)')\n")
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL when observability.py can touch the DB"

    # 5. no teardown reset -> FAIL (id leaks across requests).
    write(app=GOOD_APP.replace("reset_request_id(g._t)", "pass"))
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL without a teardown reset"

    # 6. set_request_id fed a raw header instead of the validator -> FAIL.
    bad = GOOD_APP.replace(
        "observability.set_request_id(observability.validate_or_new_request_id("
        "request.headers.get('X-Request-ID')))",
        "observability.set_request_id(request.headers.get('X-Request-ID'))")
    write(app=bad)
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL when a raw inbound header is bound without validation"

    # 7. VOCATION: the DB-write/audit module references the id -> FAIL.
    write(sec=GOOD_SEC + "def audit():\n    log(get_request_id())\n")
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL when security.py references the request id (surveillance vector)"

    # 8. VOCATION: the id co-occurs with an audit call in app.py -> FAIL.
    write(app=GOOD_APP + "    security._audit(get_db, 'X', detail=observability.get_request_id())\n")
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL when the id is threaded into an _audit() call"

    # 9. missing files -> FAIL.
    (web / "observability.py").unlink()
    assert checks.check_correlation_id(tmp_path)[0].level == "FAIL", \
        "must FAIL when a wiring file is absent"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


def test_template_endpoint_check_fails_on_unknown_endpoint(tmp_path):
    web = tmp_path / "polaris_web"
    (web / "templates").mkdir(parents=True)
    (web / "app.py").write_text(
        "@app.route('/x')\n"
        "@security.login_required\n"
        "def x_page():\n    pass\n")

    # 1. Template referencing a non-route name -> FAIL.
    (web / "templates" / "t.html").write_text(
        '<a href="{{ url_for(\'nonexistent_page\') }}">x</a>\n')
    out = checks.check_template_endpoints_resolve(tmp_path)
    assert out[0].level == "FAIL", \
        "must FAIL when a template url_for() names no @app.route function"

    # 2. Decorator stacks between @app.route and def must still resolve.
    (web / "templates" / "t.html").write_text(
        '<a href="{{ url_for(\'x_page\') }}">x</a>\n'
        '<img src="{{ url_for(\'static\', filename=\'a.css\') }}">\n')
    out = checks.check_template_endpoints_resolve(tmp_path)
    assert out[0].level == "OK", \
        "must PASS when every url_for() resolves (static is built-in)"

    # 3. A function WITHOUT @app.route is not an endpoint -> FAIL.
    (web / "app.py").write_text(
        "def helper_not_a_route():\n    pass\n"
        "@app.route('/x')\n"
        "def x_page():\n    pass\n")
    (web / "templates" / "t.html").write_text(
        '<a href="{{ url_for(\'helper_not_a_route\') }}">x</a>\n')
    out = checks.check_template_endpoints_resolve(tmp_path)
    assert out[0].level == "FAIL", \
        "must FAIL when url_for() names a function that has no @app.route"


# ---------------------------------------------------------------------------
# Operator-tooling sweep (v9.153). Each of these pins a defect that was found by
# RUNNING the script, not by reading it.
# ---------------------------------------------------------------------------

def test_purge_archive_binding_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    sh = scripts / "polaris-purge.sh"

    # No binding at all: an archive from another database purges rows it cannot
    # reconstitute (demonstrated with a canary row absent from the archive).
    sh.write_text('CUTOFF_ISO=$(read_manifest cutoff_iso)\n'
                  'run_psql -c "CALL uc_archive_purge(...)"\n')
    assert checks.check_purge_binds_archive_to_database(tmp_path)[0].level == "FAIL", \
        "must FAIL when purge never checks the archive's source_database"

    # Binds the database but still does not verify that the archive covers the
    # rows about to be deleted.
    sh.write_text('MF_DB=$(read_manifest source_database)\n'
                  '[[ "${MF_DB}" != "${TGT_DB}" ]] && exit 3\n')
    assert checks.check_purge_binds_archive_to_database(tmp_path)[0].level == "FAIL", \
        "must FAIL when purge binds the database but skips the coverage pre-check"

    sh.write_text('MF_DB=$(read_manifest source_database)\n'
                  '[[ "${MF_DB}" != "${TGT_DB}" ]] && exit 3\n'
                  'echo "coverage mismatch on ${ptable}" >&2\n')
    assert checks.check_purge_binds_archive_to_database(tmp_path)[0].level == "OK", \
        "must PASS when purge binds the source database and pre-checks coverage"


def test_archive_version_derived_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    sh = scripts / "polaris-archive.sh"

    # The real defect: a literal that drifted to 8.84 while the product shipped
    # 9.152, so every archive misreported its own provenance.
    sh.write_text('cat <<PY\n    "polaris_version": "8.84",\nPY\n')
    assert checks.check_archive_version_derived(tmp_path)[0].level == "FAIL", \
        "must FAIL when the MANIFEST hardcodes a version literal"

    sh.write_text('POLARIS_VERSION="$(sed -n s/x/p polaris_web/__version__.py)"\n'
                  'cat <<PY\n    "polaris_version": polaris_version,\nPY\n')
    assert checks.check_archive_version_derived(tmp_path)[0].level == "OK", \
        "must PASS when the version is derived from the canonical __version__.py"


def test_no_grep_q_psql_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    sh = scripts / "polaris-create-operator.sh"

    # The real defect: grep -q exits on first match, SIGPIPEs psql mid-file, the
    # COMMIT never runs, and pipefail reports failure for a rolled-back txn.
    sh.write_text('if ! run_psql -f "${SQL_TMP}" 2>&1 | grep -qE \'INSERT|COMMIT\'; then\n'
                  '    exit 5\nfi\n')
    assert checks.check_no_grep_q_transaction_scrape(tmp_path)[0].level == "FAIL", \
        "must FAIL when a file-executed psql transaction is scraped through grep -q"

    # A commented-out example of the old form must not trip the check.
    sh.write_text('# if ! run_psql -f "${SQL_TMP}" 2>&1 | grep -qE \'INSERT\'; then\n'
                  'run_psql -v ON_ERROR_STOP=1 -f "${SQL_TMP}"\n')
    assert checks.check_no_grep_q_transaction_scrape(tmp_path)[0].level == "OK", \
        "must PASS when the offending form appears only inside a comment"

    # A read-only listing has no transaction to abort, so it stays allowed.
    sh.write_text('if psql -lqt | cut -d"|" -f1 | grep -qw "$DB"; then ok; fi\n')
    assert checks.check_no_grep_q_transaction_scrape(tmp_path)[0].level == "OK", \
        "must PASS for a read-only psql listing piped into grep -q"


def test_psql_status_set_e_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    sh = scripts / "polaris-recover-admin.sh"

    # The real defect: under set -e the shell exits at the assignment, so _rc is
    # never read and the refuse-loudly block below is unreachable.
    sh.write_text('set -euo pipefail\n'
                  'run_psql() {\n'
                  '    _out=$(psql -h "$H" -tA "$@" 2>&1)\n'
                  '    _rc=$?\n'
                  '    if [[ "${_rc}" -ne 0 ]]; then exit 5; fi\n'
                  '}\n')
    assert checks.check_psql_status_capture_set_e_safe(tmp_path)[0].level == "FAIL", \
        "must FAIL when `X=$(psql ...)` is followed by `RC=$?` under set -e"

    sh.write_text('set -euo pipefail\n'
                  'run_psql() {\n'
                  '    local _rc=0\n'
                  '    _out=$(psql -h "$H" -tA "$@" 2>&1) || _rc=$?\n'
                  '    if [[ "${_rc}" -ne 0 ]]; then exit 5; fi\n'
                  '}\n')
    assert checks.check_psql_status_capture_set_e_safe(tmp_path)[0].level == "OK", \
        "must PASS when the status is captured inline with `|| _rc=$?`"


def test_recover_admin_self_pairing_check_discriminates(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    sh = scripts / "polaris-recover-admin.sh"

    # The real defect: the authorizer was validated only as *an* active admin
    # and never compared to the target, so one admin could self-authorize an
    # MFA-bypass window while the banner asserted "second-admin pairing".
    sh.write_text('auth_row=$(run_psql -c "SELECT username FROM AppUser '
                  'WHERE user_id = ${AUTHORIZING_USER_ID}")\n'
                  'TARGET_USER_ID="${target_row}"\n'
                  'echo "  Authorized by: ${auth_row} (second-admin pairing)"\n')
    assert checks.check_recover_admin_refuses_self_pairing(tmp_path)[0].level == "FAIL", \
        "must FAIL when the authorizer is never compared to the recovery target"

    sh.write_text('TARGET_USER_ID="${target_row}"\n'
                  'if [[ -n "${AUTHORIZING_USER_ID}" && '
                  '"${AUTHORIZING_USER_ID}" == "${TARGET_USER_ID}" ]]; then\n'
                  '    echo "error: self-authorization refused" >&2\n'
                  '    exit "${EXIT_AUTHORIZER}"\n'
                  'fi\n')
    assert checks.check_recover_admin_refuses_self_pairing(tmp_path)[0].level == "OK", \
        "must PASS when self-authorization is refused"


def test_test_reload_loud_check_discriminates(tmp_path):
    web = tmp_path / "polaris_web"
    web.mkdir()
    app = web / "test_app.py"

    # The real defect: psql exits 0 even when every statement errored, so a
    # permission-denied reload read as success and broke test isolation with no
    # signal at all.
    app.write_text("def reload_sample_data():\n"
                   "    cmd = ['psql', '-h', db_host, '-U', db_user, '-f', fpath]\n"
                   "    result = subprocess.run(cmd)\n"
                   "    if result.returncode != 0:\n"
                   "        raise RuntimeError('failed')\n"
                   "\n"
                   "def other():\n    pass\n")
    assert checks.check_test_reload_fails_loudly(tmp_path)[0].level == "FAIL", \
        "must FAIL when reload_sample_data runs psql without ON_ERROR_STOP"

    app.write_text("def reload_sample_data():\n"
                   "    cmd = ['psql', '-v', 'ON_ERROR_STOP=1', '-f', fpath]\n"
                   "    result = subprocess.run(cmd)\n"
                   "    if result.returncode != 0:\n"
                   "        raise RuntimeError('failed')\n"
                   "\n"
                   "def other():\n    pass\n")
    assert checks.check_test_reload_fails_loudly(tmp_path)[0].level == "OK", \
        "must PASS when the reload uses ON_ERROR_STOP"

    # ON_ERROR_STOP elsewhere in the file must not satisfy the check.
    app.write_text("def reload_sample_data():\n"
                   "    cmd = ['psql', '-f', fpath]\n"
                   "\n"
                   "def unrelated():\n"
                   "    run(['psql', '-v', 'ON_ERROR_STOP=1'])\n")
    assert checks.check_test_reload_fails_loudly(tmp_path)[0].level == "FAIL", \
        "must FAIL when ON_ERROR_STOP appears only outside reload_sample_data"


def test_ci_pin_drift_check_discriminates(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    ci = wf / "ci.yml"

    # The real defect: a second copy of the pin, which drifted to 48.0.0 while
    # requirements.txt moved to 50.0.1 for the ML-DSA CVEs.
    ci.write_text("jobs:\n  pqc:\n    steps:\n"
                  "      - run: pip install \"cryptography==48.0.0\"\n")
    assert checks.check_ci_does_not_duplicate_pins(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI hardcodes a version literal that requirements.txt owns"

    # Deriving the pin from requirements.txt is the fix.
    ci.write_text("jobs:\n  pqc:\n    steps:\n"
                  "      - run: pip install \"$(grep -E '^cryptography==' "
                  "polaris_web/requirements.txt)\"\n")
    assert checks.check_ci_does_not_duplicate_pins(tmp_path)[0].level == "OK", \
        "must PASS when the pin is derived from requirements.txt"

    # Installing from a requirements file is obviously fine.
    ci.write_text("jobs:\n  t:\n    steps:\n"
                  "      - run: pip install -r polaris_web/requirements-dev.txt\n")
    assert checks.check_ci_does_not_duplicate_pins(tmp_path)[0].level == "OK", \
        "must PASS for a plain -r requirements install"

    # A commented-out pin is not a real second source of truth.
    ci.write_text("jobs:\n  t:\n    steps:\n"
                  "      # - run: pip install \"cryptography==48.0.0\"\n"
                  "      - run: pip install -r polaris_web/requirements.txt\n")
    assert checks.check_ci_does_not_duplicate_pins(tmp_path)[0].level == "OK", \
        "must PASS when the literal appears only in a comment"


def test_ci_ssl_probe_check_discriminates(tmp_path):
    wf = tmp_path / ".github" / "workflows"
    wf.mkdir(parents=True)
    ci = wf / "ci.yml"

    # The real defect: per-row ssl output concatenates across pooled backends
    # ("tt" on a healthy stack) and the scalar compare fails nondeterministically.
    ci.write_text("jobs:\n  t:\n    steps:\n"
                  "      - run: psql -tAc \"SELECT ssl FROM pg_stat_ssl "
                  "s JOIN pg_stat_activity a USING(pid)\"\n")
    assert checks.check_ci_ssl_probe_aggregated(tmp_path)[0].level == "FAIL", \
        "must FAIL when a workflow selects raw per-row ssl from pg_stat_ssl"

    # Aggregated to a single boolean: immune to the pool's connection count.
    ci.write_text("jobs:\n  t:\n    steps:\n"
                  "      - run: psql -tAc \"SELECT COALESCE(bool_and(ssl), false) "
                  "FROM pg_stat_ssl s JOIN pg_stat_activity a USING(pid)\"\n")
    assert checks.check_ci_ssl_probe_aggregated(tmp_path)[0].level == "OK", \
        "must PASS when the probe aggregates with bool_and"

    # A commented-out example of the old form must not trip the check.
    ci.write_text("jobs:\n  t:\n    steps:\n"
                  "      # SELECT ssl FROM pg_stat_ssl is the broken form\n"
                  "      - run: echo ok\n")
    assert checks.check_ci_ssl_probe_aggregated(tmp_path)[0].level == "OK", \
        "must PASS when pg_stat_ssl appears only in a comment"


def test_offsite_backup_env_driven_check_discriminates(tmp_path):
    good = {
        "polaris_web/pgbackrest.conf": "[global]\nrepo1-retention-full=2\n[polaris]\npg1-path=/data\n",
        "polaris_web/pgbackrest-conf.sh": (
            "#!/usr/bin/env bash\n"
            "if [ -n \"${POLARIS_PGBACKREST_S3_KEY:-}${POLARIS_PGBACKREST_S3_KEY_SECRET:-}\" ]; then exit 3; fi\n"
            "if [ -z \"${POLARIS_PGBACKREST_S3_BUCKET:-}\" ]; then body=repo1-path=/var/lib/pgbackrest\n"
            "else body=\"repo1-type=s3\"; fi\n"),
        "polaris_web/pg-entrypoint.sh": "#!/bin/sh\n/usr/local/bin/polaris-pgbackrest-conf.sh || exit 1\n"
                                        "exec /usr/local/bin/docker-entrypoint.sh \"$@\"\n",
        "polaris_web/Dockerfile.postgres": "FROM postgres:16-alpine@sha256:abc\nRUN apk add pgbackrest\n"
                                           "COPY pgbackrest-conf.sh /usr/local/bin/polaris-pgbackrest-conf.sh\n"
                                           "COPY pg-entrypoint.sh /usr/local/bin/polaris-pg-entrypoint.sh\n"
                                           "ENTRYPOINT [\"/usr/local/bin/polaris-pg-entrypoint.sh\"]\n",
        "polaris_web/docker-compose.prod.yml": (
            "services:\n  postgres:\n    environment:\n"
            "      POLARIS_PGBACKREST_S3_BUCKET: \"${POLARIS_PGBACKREST_S3_BUCKET:-}\"\n"
            "    volumes:\n"
            "      - ./secrets/pgbackrest_repo_creds.conf:/etc/pgbackrest/conf.d/repo-creds.conf:ro\n"),
        "scripts/polaris-generate-secrets.sh": "write_pgbackrest_creds_if_missing() {\n  : > pgbackrest_repo_creds.conf\n}\nwrite_pgbackrest_creds_if_missing\n",
        "scripts/polaris-deploy.sh": "for secret in polaris_db_password pgbackrest_repo_creds.conf; do :; done\n",
        "scripts/polaris-offsite-drill.sh": (
            "MINIO_IMAGE=minio/minio@sha256:x\n"
            "docker run -e POLARIS_PGBACKREST_S3_KEY=leaked img && exit 1\n"
            "grep -q '^repo1-type=s3$' /etc/pgbackrest/conf.d/repo.conf\n"
            "pgbackrest --stanza=polaris restore\n"),
        ".github/workflows/ci.yml": "steps:\n  - run: bash scripts/polaris-offsite-drill.sh\n",
        "docs/operator/DR.md": "export POLARIS_PGBACKREST_S3_BUCKET=<bucket>\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_offsite_backup_env_driven(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # The load-bearing lesson: repo1-path back in the main conf duplicates the
    # rendered fragment and pgBackRest refuses to start.
    write({"polaris_web/pgbackrest.conf": "[global]\nrepo1-path=/var/lib/pgbackrest\n[polaris]\npg1-path=/d\n"})
    f = checks.check_offsite_backup_env_driven(tmp_path)[0]
    assert f.level == "FAIL" and "multiple times" in f.message, "must FAIL when pgbackrest.conf sets repo1-path"

    # The renderer that no longer refuses the key pair in env.
    write({"polaris_web/pgbackrest-conf.sh": "body=repo1-type=s3\nbody=repo1-path=/x\n"
                                             "echo $POLARIS_PGBACKREST_S3_BUCKET\n"})
    assert checks.check_offsite_backup_env_driven(tmp_path)[0].level == "FAIL", \
        "must FAIL when the renderer does not refuse (exit 3) the key pair in env"

    # The compose carrying the key pair as env.
    write({"polaris_web/docker-compose.prod.yml": good["polaris_web/docker-compose.prod.yml"]
           + "      POLARIS_PGBACKREST_S3_KEY: abc\n"})
    assert checks.check_offsite_backup_env_driven(tmp_path)[0].level == "FAIL", \
        "must FAIL when the compose passes the S3 key pair through environment"

    # The v9.173 CI failure: the function called before it is defined.
    write({"scripts/polaris-generate-secrets.sh": "write_pgbackrest_creds_if_missing\n"
           "write_pgbackrest_creds_if_missing() {\n  : > pgbackrest_repo_creds.conf\n}\n"})
    f = checks.check_offsite_backup_env_driven(tmp_path)[0]
    assert f.level == "FAIL" and "DEFINE" in f.message, \
        "must FAIL when generate-secrets calls the function before defining it"

    # CI no longer running the offsite drill.
    write({".github/workflows/ci.yml": "steps:\n  - run: echo local round-trip only\n"})
    assert checks.check_offsite_backup_env_driven(tmp_path)[0].level == "FAIL", \
        "must FAIL when CI does not run the offsite drill"


def test_pager_integration_check_discriminates(tmp_path):
    AM = ("route:\n  receiver: pager\n  routes:\n"
          "    - matchers: ['alertname=\"PolarisDuressEvent\"']\n      receiver: pager\n      group_wait: 0s\n"
          "receivers:\n  - name: pager\n    webhook_configs:\n"
          "      - url_file: /etc/alertmanager/secrets/pager_webhook_url\n")
    good = {
        "deploy/observability/alertmanager.yml": AM,
        "deploy/observability/prometheus.yml": "alerting:\n  alertmanagers:\n    - static_configs:\n"
                                               "        - targets: ['alertmanager:9093']\n",
        "scripts/polaris-page-drill.sh": ("promtool check rules x\namtool check-config alertmanager.yml\n"
                                          "polaris_duress_events_total 1\ngrep PolarisDuressEvent webhook\n"),
        ".github/workflows/ci.yml": "steps:\n  - run: bash scripts/polaris-page-drill.sh\n",
        "docs/operator/RUNBOOKS.md": "## Paging\nmount pager_webhook_url\n",
        "polaris_web/test_app.py": "def test_duress_increments_prometheus_counter(self):\n    pass\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_pager_integration(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # The pager URL inline in the config (the integration key would be committed).
    write({"deploy/observability/alertmanager.yml": AM.replace(
        "      - url_file: /etc/alertmanager/secrets/pager_webhook_url\n",
        "      - url: https://events.pagerduty.com/x/abc123\n")})
    f = checks.check_pager_integration(tmp_path)[0]
    assert f.level == "FAIL" and "url_file" in f.message, "must FAIL on an inline pager URL"

    # Duress routed with a grouping wait.
    write({"deploy/observability/alertmanager.yml": AM.replace("group_wait: 0s", "group_wait: 30s")})
    f = checks.check_pager_integration(tmp_path)[0]
    assert f.level == "FAIL" and "group_wait" in f.message, "must FAIL when duress waits on grouping"

    # prometheus.yml with the alerting block commented out (the pre-P0.10 state).
    write({"deploy/observability/prometheus.yml": "# alerting:\n#   alertmanagers:\n"})
    assert checks.check_pager_integration(tmp_path)[0].level == "FAIL", \
        "must FAIL when prometheus.yml does not reach an Alertmanager"

    # CI no longer running the drill.
    write({".github/workflows/ci.yml": "steps:\n  - run: echo no drill\n"})
    assert checks.check_pager_integration(tmp_path)[0].level == "FAIL", "must FAIL when CI skips the drill"

    # The app-half test removed.
    write({"polaris_web/test_app.py": "def test_something_else(self):\n    pass\n"})
    assert checks.check_pager_integration(tmp_path)[0].level == "FAIL", \
        "must FAIL when the duress-counter test is gone"


def test_linux_server_deployment_check_discriminates(tmp_path):
    INST = ("#!/usr/bin/env bash\napt-get install -y docker-ce\ndnf -y install docker-ce\n"
            "curl -fsSL https://download.docker.com/linux/debian/gpg -o /tmp/k\n"
            "gpg --show-keys /tmp/k | grep 9DC858229FC7DD38854AE2D88D81803C0EBFCD88\n"
            "gpg --show-keys /tmp/k2 | grep 060A61C51B558A7F742B77AAC52FEB6B621E9F35\n"
            "bash scripts/polaris-generate-secrets.sh\nsystemctl daemon-reload\nsystemctl enable polaris\n"
            "bash scripts/polaris-migrate.sh --up\ncurl https://x/api/health\n")
    good = {
        "deploy/linux/install.sh": INST,
        "deploy/linux/polaris.service": ("[Unit]\nRequires=docker.service\n[Service]\nEnvironmentFile=/etc/polaris/polaris.env\n"
                                         "ExecStart=/usr/bin/docker compose -f docker-compose.prod.yml up -d\n"
                                         "ExecStop=/usr/bin/docker compose -f docker-compose.prod.yml down\n"
                                         "[Install]\nWantedBy=multi-user.target\n"),
        "deploy/linux/polaris-backup.service": "[Service]\nExecStart=/opt/polaris/scripts/polaris-backup.sh\n",
        "deploy/linux/polaris-backup.timer": "[Timer]\nOnCalendar=*-*-* 03:00:00 UTC\nPersistent=true\n",
        "deploy/linux/polaris.env.example": "POLARIS_DOMAIN=polaris.example.org\n",
        "docs/operator/LINUX-SERVER.md": "run install.sh then systemctl status polaris; see HARDENING.md\n",
        "docs/operator/HARDENING.md": "ssh unattended-upgrades ufw firewalld chrony daemon.json auditd /metrics\n",
        "README.md": "[LINUX-SERVER](docs/operator/LINUX-SERVER.md)\n",
        "docs/operator/README.md": "LINUX-SERVER.md HARDENING.md\n",
        ".github/workflows/ci.yml": ("run: bash deploy/linux/install.sh\ndebian@sha256:abc\nrockylinux@sha256:def\n"
                                     "run: systemctl is-active polaris.service\n"),
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_linux_server_deployment(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    write({"deploy/linux/install.sh": INST + "curl -fsSL https://get.docker.com | sh\n"})
    f = checks.check_linux_server_deployment(tmp_path)[0]
    assert f.level == "FAIL" and "pipe" in f.message, "must FAIL on curl | sh"

    write({"deploy/linux/install.sh": INST.replace("9DC858229FC7DD38854AE2D88D81803C0EBFCD88", "whatever")})
    assert checks.check_linux_server_deployment(tmp_path)[0].level == "FAIL", "must FAIL without key verification"

    write({"deploy/linux/polaris.service": good["deploy/linux/polaris.service"].replace("Requires=docker.service\n", "")})
    assert checks.check_linux_server_deployment(tmp_path)[0].level == "FAIL", "must FAIL when the unit ignores docker.service"

    write({".github/workflows/ci.yml": "run: bash deploy/linux/install.sh --stage packages\ndebian@sha256:a\nrockylinux@sha256:b\n"})
    assert checks.check_linux_server_deployment(tmp_path)[0].level == "FAIL", "must FAIL when CI never starts the unit"

    write({"README.md": "no server path here\n"})
    assert checks.check_linux_server_deployment(tmp_path)[0].level == "FAIL", "must FAIL when README does not link the guide"


def test_key_custody_abstraction_check_discriminates(tmp_path):
    CU = ("class FileCustody: pass\nclass Pkcs11Custody:\n  def sign(self): Mechanism.ML_DSA\n"
          "def pkcs11_generate_key(): ML_DSA_KEY_PAIR_GEN; {EXTRACTABLE: False}\n"
          "class AwsKmsCustody: ML_DSA_65; ML_DSA_SHAKE_256; MessageType=\"RAW\"\n"
          "def from_env():\n  os.environ.get(\"POLARIS_CUSTODY_PKCS11_PIN\"); POLARIS_CUSTODY_PKCS11_PIN_FILE\n"
          "def get_custody(): pass\n")
    PQ = ("def verify_both(): pass\ndef signature_with_key_for_token():\n    verify_both()\n"
          "def sign():\n    cust = custody.get_custody()\n"
          "def trust_anchor_public_keys():\n    os.environ.get(\"POLARIS_PQC_TRUST_ANCHORS_FILE\")\n")
    good = {
        "polaris_web/custody.py": CU,
        "polaris_web/pqc_signing.py": PQ,
        "polaris_web/test_custody.py": "class FileCustodyTests: pass\nclass AwsKmsCustodyTests: pass\n"
                                       "class Pkcs11CustodyTests: pass\nclass _KmsStandIn: pass\n"
                                       "POLARIS_PQC_TRUST_ANCHORS_FILE\n",
        "polaris_web/requirements-custody.txt": "python-pkcs11==0.9.5\nboto3==1.43.85\n",
        ".github/workflows/ci.yml": "run: dnf install kryoptic; pip install -r polaris_web/requirements-custody.txt; "
                                    "POLARIS_CUSTODY_PKCS11_REQUIRE=1 python -m unittest test_custody\n",
        "docs/operator/KEY-CEREMONY.md": "## Ceremony\npkcs11-keygen ML_DSA_65\n## Rotation\n",
        "polaris_web/app.py": "def _health_check_custody(): pass\nchecks = {'custody': _health_check_custody()}\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_key_custody_abstraction(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # A secret-key signing path that bypasses custody (the pre-P1.2 code).
    write({"polaris_web/pqc_signing.py": PQ + "with _oqs.Signature(_ALG_NAME, secret_key=sk) as s: pass\n"})
    f = checks.check_key_custody_abstraction(tmp_path)[0]
    assert f.level == "FAIL" and "custody.get_custody" in f.message, "must FAIL on direct secret-key signing"

    # The PIN accepted from env.
    write({"polaris_web/custody.py": CU.replace("os.environ.get(\"POLARIS_CUSTODY_PKCS11_PIN\"); ", "")})
    assert checks.check_key_custody_abstraction(tmp_path)[0].level == "FAIL", "must FAIL when the PIN can come from env"

    # KMS signing with a pre-hash / non-RAW message type.
    write({"polaris_web/custody.py": CU.replace('MessageType=\"RAW\"', 'MessageType=\"DIGEST\"')})
    assert checks.check_key_custody_abstraction(tmp_path)[0].level == "FAIL", "must FAIL when KMS is not RAW pure ML-DSA"

    # CI without the real-token PKCS#11 run.
    write({".github/workflows/ci.yml": "run: pip install -r polaris_web/requirements-custody.txt; python -m unittest test_custody\n"})
    assert checks.check_key_custody_abstraction(tmp_path)[0].level == "FAIL", "must FAIL when CI has no real PKCS#11 token run"

    # No rotation procedure.
    write({"docs/operator/KEY-CEREMONY.md": "## Ceremony\npkcs11-keygen ML_DSA_65\n"})
    assert checks.check_key_custody_abstraction(tmp_path)[0].level == "FAIL", "must FAIL without a Rotation section"


def test_secrets_lifecycle_sealed_check_discriminates(tmp_path):
    ST = ("class AgeBackend: pass\nclass AwsKmsBackend:\n  def seal(self): self._kms.generate_data_key(); AESGCM\n"
          "  def unseal(self): self._kms.decrypt(CiphertextBlob=edk, KeyId=self.key_id)\n"
          "def rotate_wrapping(): pass\ndef verify(): pass\nmanifest = {\"mode\": 1}\n")
    good = {
        "polaris_web/secretstore.py": ST,
        "scripts/polaris-secrets.sh": "unseal-if-configured) mount -t tmpfs -o mode=0700 tmpfs $d\n",
        "scripts/polaris-deploy.sh": "polaris-secrets.sh unseal-if-configured\nSECRETS_DIR=${POLARIS_SECRETS_DIR:-x}\n",
        "scripts/polaris-rotate-secret.sh": ("SECRETS_DIR=${POLARIS_SECRETS_DIR:-x}\npolaris-secrets.sh seal --only $SECRET\n"
                                            "case x in\n    polaris_db_password)\n        docker compose up -d --no-deps --force-recreate pgbouncer\n"
                                            "        docker compose up -d --no-deps --force-recreate app\n        ;;\nesac\n"),
        "deploy/linux/polaris.service": "ExecStartPre=polaris-secrets.sh unseal-if-configured\n",
        "polaris_web/test_secretstore.py": "class AgeBackendTests: rotate_wrapping\nclass AwsKmsBackendTests: drift\n",
        "polaris_web/docker-compose.prod.yml": "secrets:\n  k:\n    file: ${POLARIS_SECRETS_DIR:-./secrets}/k\n",
        ".github/workflows/ci.yml": ("run: bash scripts/polaris-secrets.sh seal; rm -rf polaris_web/secrets; "
                                     "bash scripts/polaris-rotate-secret.sh polaris_db_password; "
                                     "bash scripts/polaris-secrets.sh verify\n"),
        "docs/operator/SECRETS.md": "POLARIS_SECRETS_BACKEND=age ... rotate-wrapping\n",
        ".gitignore": "polaris_web/secrets/\npolaris_web/secrets.sealed/\n",
        "deploy/linux/polaris.env.example": "POLARIS_SECRETS_BACKEND=file\nPOLARIS_SECRETS_DIR=\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_secrets_lifecycle_sealed(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # POLARIS_SECRETS_DIR forced in the env example (the v9.180 install failure).
    write({"deploy/linux/polaris.env.example": "POLARIS_SECRETS_BACKEND=file\nPOLARIS_SECRETS_DIR=/run/polaris/secrets\n"})
    assert checks.check_secrets_lifecycle_sealed(tmp_path)[0].level == "FAIL", "must FAIL when the env example forces POLARIS_SECRETS_DIR"

    # A compose file that still reads ./secrets/ directly (the pre-P1.3 layout).
    write({"polaris_web/docker-compose.prod.yml": "secrets:\n  k:\n    file: ./secrets/k\n"})
    f = checks.check_secrets_lifecycle_sealed(tmp_path)[0]
    assert f.level == "FAIL" and "POLARIS_SECRETS_DIR" in f.message, "must FAIL on a direct ./secrets/ reference"

    # KMS Decrypt without the KeyId pin (a stale key would open a re-wrapped store).
    write({"polaris_web/secretstore.py": ST.replace(", KeyId=self.key_id", "")})
    assert checks.check_secrets_lifecycle_sealed(tmp_path)[0].level == "FAIL", "must FAIL without KeyId pinned on Decrypt"

    # Rotation that recreates only the app (pgbouncer keeps the old password).
    write({"scripts/polaris-rotate-secret.sh": "SECRETS_DIR=${POLARIS_SECRETS_DIR:-x}\npolaris-secrets.sh seal --only $SECRET\n"
           "case x in\n    polaris_db_password)\n        docker compose up -d --no-deps --force-recreate app\n        ;;\nesac\n"})
    f = checks.check_secrets_lifecycle_sealed(tmp_path)[0]
    assert f.level == "FAIL" and "pgbouncer" in f.message, "must FAIL when rotation skips pgbouncer"

    # Rotation that does not write through.
    write({"scripts/polaris-rotate-secret.sh": "SECRETS_DIR=${POLARIS_SECRETS_DIR:-x}\n"})
    assert checks.check_secrets_lifecycle_sealed(tmp_path)[0].level == "FAIL", "must FAIL when rotation does not write through"

    # CI that boots from plaintext (no seal / delete / live rotation).
    write({".github/workflows/ci.yml": "run: bash scripts/polaris-generate-secrets.sh; docker compose up -d\n"})
    assert checks.check_secrets_lifecycle_sealed(tmp_path)[0].level == "FAIL", "must FAIL when CI does not drill the sealed boot + rotation"

    # The systemd unit that starts compose without unsealing.
    write({"deploy/linux/polaris.service": "ExecStart=docker compose up -d\n"})
    assert checks.check_secrets_lifecycle_sealed(tmp_path)[0].level == "FAIL", "must FAIL when the unit skips unseal"


def test_migrations_expand_contract_check_discriminates(tmp_path):
    mig = tmp_path / "polaris_sql" / "migrations"
    mig.mkdir(parents=True)
    (mig / "README.md").write_text("## Expand-contract policy\n-- phase: contract\n-- expands: <id>\n")
    (mig / "2026-01-01-001-add-col.up.sql").write_text("ALTER TABLE t ADD COLUMN IF NOT EXISTS c TEXT;\n")
    (mig / "2026-01-01-001-add-col.down.sql").write_text("ALTER TABLE t DROP COLUMN c;\n")
    assert checks.check_migrations_expand_contract(tmp_path)[0].level == "OK", "additive up + destructive down must PASS"

    # A destructive up with no contract declaration (old code breaks mid-roll).
    (mig / "2026-02-01-001-drop-old.up.sql").write_text("-- clean up\nALTER TABLE t DROP COLUMN old_c;\n")
    f = checks.check_migrations_expand_contract(tmp_path)[0]
    assert f.level == "FAIL" and "drop-old" in f.message, "must FAIL on undeclared destructive DDL"

    # Declared, but expands a migration that does not exist.
    (mig / "2026-02-01-001-drop-old.up.sql").write_text("-- phase: contract\n-- expands: 2025-12-31-009-nope\nALTER TABLE t DROP COLUMN old_c;\n")
    assert checks.check_migrations_expand_contract(tmp_path)[0].level == "FAIL", "must FAIL when expands names a missing migration"

    # Declared and expanding an EARLIER migration: allowed.
    (mig / "2026-02-01-001-drop-old.up.sql").write_text("-- phase: contract\n-- expands: 2026-01-01-001-add-col\nALTER TABLE t DROP COLUMN old_c;\n")
    assert checks.check_migrations_expand_contract(tmp_path)[0].level == "OK", "a declared contract of an earlier expand must PASS"

    # Destructive words only inside comments must not count.
    (mig / "2026-03-01-001-comment.up.sql").write_text("-- we will DROP COLUMN x later\nCREATE INDEX IF NOT EXISTS i ON t(c);\n")
    assert checks.check_migrations_expand_contract(tmp_path)[0].level == "OK", "comments are not DDL"


def test_zero_downtime_deploy_check_discriminates(tmp_path):
    CADDY = ("admin unix//config/admin.sock\n"
             "reverse_proxy {$POLARIS_UPSTREAMS:app:8000} {\n  lb_try_duration 15s\n  health_uri /api/health/live\n}\n")
    COMPOSE = ("services:\n  app:\n    container_name: polaris-app\n    healthcheck:\n      test: x\n    stop_grace_period: 35s\n"
               "  pgbouncer:\n    image: y\n  caddy:\n    environment:\n      POLARIS_UPSTREAMS: \"${POLARIS_UPSTREAMS:-app:8000}\"\n")
    DEPLOY = ("read -r -a COMPOSE_EXTRA <<< \"${POLARIS_COMPOSE_EXTRA:-}\"\ncompose up -d --no-deps postgres pgbouncer redis caddy\n"
              "compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --address unix//config/admin.sock\n"
              "polaris-migrate.sh --up --target=docker-stack\nwait_healthy() { :; }\n"
              "mapfile -t APP_SERVICES < <(compose config --services | grep -E '^app(-green)?$' | sort -r)\n")
    WINDOW = ("caddy reload\n[[ \"$r_drops\" -le \"$_rmax\" ]]\ncompose up -d --no-deps --force-recreate caddy\n"
              "EDGE_CEILING=30\ncompose restart -t 10 postgres\nDB_CEILING=60\n")
    good = {
        "polaris_web/Caddyfile": CADDY, "polaris_web/Caddyfile.citest": CADDY,
        "polaris_web/docker-compose.prod.yml": COMPOSE,
        "polaris_web/docker-compose.bluegreen.yml": "services:\n  app-green:\n    container_name: polaris-app-green\n  caddy:\n    environment:\n      POLARIS_UPSTREAMS: \"app:8000 app-green:8000\"\n",
        "scripts/polaris-deploy.sh": DEPLOY,
        "scripts/polaris-rotate-secret.sh": "recreate_apps() { compose config --services | grep -E '^app(-green)?$'; }\n",
        "scripts/polaris-rolling-drill.sh": ("bash scripts/polaris-deploy.sh prod --no-pull\nassert s[\"drops\"] == 0\n"
                                             "compose stop -t 1 app app-green\nassert s[\"drops\"] > 0\n"),
        "scripts/polaris-window-drill.sh": WINDOW,
        ".github/workflows/ci.yml": ("run: docker compose -f docker-compose.bluegreen.yml up -d; bash scripts/polaris-rolling-drill.sh\n"
                                     "run: bash scripts/polaris-window-drill.sh\n"),
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # The edge pinned to one upstream with no retry (the pre-P1.4 Caddyfile).
    write({"polaris_web/Caddyfile": "reverse_proxy app:8000 {\n  health_uri /api/health\n}\n"})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when the edge cannot retry onto another colour"

    # Deploy that recreates the app BEFORE migrating (old order).
    write({"scripts/polaris-deploy.sh": ("read -r -a COMPOSE_EXTRA <<< \"${POLARIS_COMPOSE_EXTRA:-}\"\nwait_healthy() { :; }\n"
                                         "mapfile -t APP_SERVICES < <(compose config --services | grep -E '^app(-green)?$' | sort -r)\n"
                                         "compose up -d --no-deps postgres pgbouncer redis caddy\npolaris-migrate.sh --up --target=docker-stack\n")})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when the roll precedes the migration"

    # A drill with no negative control.
    write({"scripts/polaris-rolling-drill.sh": "bash scripts/polaris-deploy.sh prod --no-pull\nassert s[\"drops\"] == 0\n"})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when zero drops is not validated by a control"

    # Rotation that only recreates one colour.
    write({"scripts/polaris-rotate-secret.sh": "compose up -d --no-deps --force-recreate app\n"})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when rotation ignores app-green"
    # v9.240: the edge with its admin API off has no reload path.
    write({"polaris_web/Caddyfile": "admin off\n" + CADDY.replace("admin unix//config/admin.sock\n", "")})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when the edge cannot be reloaded live"
    # A deploy that never reloads the edge silently ignores a Caddyfile change.
    write({"scripts/polaris-deploy.sh": DEPLOY.replace("compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile --address unix//config/admin.sock\n", "")})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when the deploy does not reload the edge"
    # A window drill that measures nothing.
    write({"scripts/polaris-window-drill.sh": "echo windows are fine\n"})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when the windows are not measured"
    # The drill exists but CI never runs it.
    write({".github/workflows/ci.yml": "run: docker compose -f docker-compose.bluegreen.yml up -d; bash scripts/polaris-rolling-drill.sh\n"})
    assert checks.check_zero_downtime_deploy(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the window drill"


def test_chaos_program_check_discriminates(tmp_path):
    DRILL = ("crash() { docker run --rm --privileged --pid=host alpine kill -9 \"$pid\"; }\n"
             "crash polaris-app-green\n[[ \"$a_drops\" -eq 0 ]]\ncompose stop -t 1 app app-green\n"
             "grep -q '\"alertname\":\"PolarisAppDown\"'\n[[ \"$b_drops\" -gt 0 ]]\ncrash polaris-redis\n"
             "crash polaris-postgres\n[[ \"$app_ids_before\" == \"$app_ids_after\" ]]\n"
             "docker network disconnect\ndocker network connect \"${PGB_ALIAS_ARGS[@]}\" \"$NET\" polaris-pgbouncer\n"
             "wait_for 10 app_resolves_pgbouncer\nCEIL_RESTART=60\nCEIL_DB=90\nCEIL_PAGE=240\n"
             "-v polaris-alerts.yml -v alertmanager.yml\n--record\nfail() { record_row FAIL; }\n")
    WF = ("on:\n  schedule:\n    - cron: \"47 5 * * 1\"\npermissions:\n  contents: write\n"
          "run: docker compose -f docker-compose.bluegreen.yml up -d\nrun: bash scripts/polaris-chaos-drill.sh --record\n"
          "run: git add docs/operator/CHAOS-DRILLS.md && git push\n")
    CI = "on:\n  push:\n    paths-ignore:\n      - docs/operator/CHAOS-DRILLS.md\njobs:\n  test:\n    run: bash scripts/polaris-chaos-test.sh\n"
    good = {
        ".github/workflows/ci.yml": CI,
        ".github/workflows/chaos.yml": WF,
        "scripts/polaris-chaos-drill.sh": DRILL,
        "docs/operator/CHAOS-DRILLS.md": "| Date (UTC) | Version | Commit | Mode | Recovery | Page s | Status | Note |\n",
        "docs/operator/README.md": "| CHAOS-DRILLS.md | the chaos ledger |\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_chaos_program(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # The harness that only a contributor runs by hand (the pre-P2.11 state).
    write({".github/workflows/ci.yml": CI.replace("    run: bash scripts/polaris-chaos-test.sh\n", "")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when the fail-closed harness is not in CI"
    # A drill whose crash is `docker kill`: a manual stop the restart policy ignores.
    write({"scripts/polaris-chaos-drill.sh": DRILL.replace("crash() { docker run --rm --privileged --pid=host alpine kill -9 \"$pid\"; }\n", "")
                                                   .replace("crash polaris-", "docker kill -s KILL polaris-")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when the crash is a manual stop"
    # A reconnect without the aliases: the app can never resolve the pooler again.
    write({"scripts/polaris-chaos-drill.sh": DRILL.replace("docker network connect \"${PGB_ALIAS_ARGS[@]}\" \"$NET\" polaris-pgbouncer\n",
                                                           "docker network connect \"$NET\" polaris-pgbouncer\n")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when the reconnect loses the service alias"
    # A drill that crashes things but never proves the outage paged.
    write({"scripts/polaris-chaos-drill.sh": DRILL.replace("grep -q '\"alertname\":\"PolarisAppDown\"'\n", "")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when paging is not verified"
    # A drill without ceilings measures recovery and asserts nothing.
    write({"scripts/polaris-chaos-drill.sh": DRILL.replace("CEIL_DB=90\n", "")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when a recovery has no ceiling"
    # A workflow on demand only is not a standing program.
    write({".github/workflows/chaos.yml": WF.replace("  schedule:\n    - cron: \"47 5 * * 1\"\n", "")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when the drill is not scheduled"
    # A workflow that runs the drill but cannot commit the row.
    write({".github/workflows/chaos.yml": WF.replace("permissions:\n  contents: write\n", "")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when the ledger row cannot be committed"
    # The ledger without its header: nothing to append to.
    write({"docs/operator/CHAOS-DRILLS.md": "# Chaos drills\n"})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when the ledger has no table"
    # The weekly row spending a full CI run.
    write({".github/workflows/ci.yml": CI.replace("    paths-ignore:\n      - docs/operator/CHAOS-DRILLS.md\n", "")})
    assert checks.check_chaos_program(tmp_path)[0].level == "FAIL", "must FAIL when CI does not ignore the ledger path"


def test_ha_automation_check_discriminates(tmp_path):
    OVERLAY = ("services:\n  postgres:\n    command: [\"/usr/local/bin/polaris-patroni-entrypoint.sh\"]\n  postgres2:\n"
               "  etcd1:\n  etcd2:\n  etcd3:\n  pg-router:\n    image: haproxy:3.1-alpine@sha256:" + "a" * 64 + "\n"
               "  pgbouncer:\n    environment:\n      POLARIS_DB_HOST: pg-router\nnetworks:\n  polaris-dcs:\n    internal: true\n")
    ENTRY = ("failsafe_mode: false\nuse_pg_rewind: true\nttl: 20\n"
             "post_init: /usr/local/bin/polaris-patroni-post-init.sh\nexec patroni \"$CONF\"\n")
    DRILL = ("docker network disconnect\nnot_primary() { :; }\nreplica_streaming() { :; }\npatronictl switchover\n"
             "crash polaris-etcd1\nCEIL_FAILOVER=60\nCEIL_DEMOTE=45\nCEIL_SWITCHOVER=30\nCREATE TABLE ha_marker\n"
             "no_lost_write() { :; }\nreplica_current() { :; }\n")
    CI = ("run: docker compose -f docker-compose.ha.yml up -d\nrun: bash scripts/polaris-failover-drill.sh\n"
          "for img in polaris-postgres:cve polaris-etcd:cve; do\n")
    good = {
        "polaris_web/docker-compose.ha.yml": OVERLAY,
        "polaris_web/patroni-entrypoint.sh": ENTRY,
        "polaris_web/patroni-post-init.sh": "export POLARIS_INIT_MANAGED_BY=patroni\nexec bash /docker-entrypoint-initdb.d/00-init.sh\n",
        "polaris_web/docker-init.sh": "MANAGED=\"${POLARIS_INIT_MANAGED_BY:-}\"\n",
        "polaris_web/Dockerfile.postgres": "COPY polaris_web/requirements-patroni.txt /tmp/r.txt\nRUN pip3 install -r /tmp/r.txt && patroni --version\n",
        "polaris_web/requirements-patroni.txt": "patroni[etcd3]==4.1.5\n",
        "polaris_web/Dockerfile.etcd": "FROM alpine:3.24@sha256:" + "b" * 64 + "\nRUN apk add etcd\nUSER etcd\n",
        "polaris_web/haproxy-pg.cfg": "resolvers docker\noption httpchk GET /primary\noption httpchk GET /replica\ndefault-server on-marked-down shutdown-sessions tcp-ut 3000 on-error mark-down\n",
        "scripts/polaris-failover-drill.sh": DRILL,
        "scripts/polaris-image-build.sh": "build_one polaris_web/Dockerfile.etcd polaris-etcd:x polaris_web\n",
        ".github/workflows/ci.yml": CI,
        "docs/operator/FAILOVER.md": "## split-brain\nfailsafe_mode is off.\n`patronictl switchover`\nscripts/polaris-failover-drill.sh\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_ha_automation(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # A leader allowed to keep the primary role without its lease.
    write({"polaris_web/patroni-entrypoint.sh": ENTRY.replace("failsafe_mode: false", "failsafe_mode: true")})
    assert checks.check_ha_automation(tmp_path)[0].level == "FAIL", "must FAIL when failsafe_mode lets a leader keep writes without the lease"
    # The pooler still dialling one member by name: a failover moves nothing.
    write({"polaris_web/docker-compose.ha.yml": OVERLAY.replace("POLARIS_DB_HOST: pg-router", "POLARIS_DB_HOST: postgres")})
    assert checks.check_ha_automation(tmp_path)[0].level == "FAIL", "must FAIL when pgbouncer does not dial the router"
    # An unpinned HAProxy image.
    write({"polaris_web/docker-compose.ha.yml": OVERLAY.replace("@sha256:" + "a" * 64, "")})
    assert checks.check_ha_automation(tmp_path)[0].level == "FAIL", "must FAIL when the haproxy image is not digest-pinned"
    # A drill that never cuts the leader from the lease store.
    write({"scripts/polaris-failover-drill.sh": DRILL.replace("docker network disconnect\n", "")})
    assert checks.check_ha_automation(tmp_path)[0].level == "FAIL", "must FAIL when the split-brain guard is not exercised"
    # A bootstrap that loads a different schema path than the single node.
    write({"polaris_web/patroni-post-init.sh": "psql -f /some/other/schema.sql\n"})
    assert checks.check_ha_automation(tmp_path)[0].level == "FAIL", "must FAIL when post_init does not reuse docker-init.sh"
    # CI that never runs the drill.
    write({".github/workflows/ci.yml": CI.replace("run: bash scripts/polaris-failover-drill.sh\n", "")})
    assert checks.check_ha_automation(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the failover drill"
    # The analysis missing from the runbook.
    write({"docs/operator/FAILOVER.md": "`patronictl switchover`\nscripts/polaris-failover-drill.sh\n"})
    assert checks.check_ha_automation(tmp_path)[0].level == "FAIL", "must FAIL when FAILOVER.md has no split-brain analysis"


def test_event_table_partitioning_check_discriminates(tmp_path):
    TABLES = ("TokenLifecycleEvent", "VerificationEvent", "EnrollmentStatusEvent", "AuthAuditLog")
    def schema_block(t, idcol="event_id"):
        return (f"CREATE TABLE {t} (\n    {idcol} SERIAL,\n    event_timestamp TIMESTAMP NOT NULL,\n"
                f"    PRIMARY KEY ({idcol}, event_timestamp)\n)\nPARTITION BY RANGE (event_timestamp);\n"
                f"CREATE TABLE {t}_default PARTITION OF {t} DEFAULT;\n")
    SCHEMA = "".join(schema_block(t, "audit_id" if t == "AuthAuditLog" else "event_id") for t in TABLES)
    SCHEMA += ("CREATE OR REPLACE PROCEDURE uc_ensure_event_partitions(p_months_ahead integer DEFAULT 3) LANGUAGE plpgsql AS $$ BEGIN END $$;\n"
               "CREATE OR REPLACE PROCEDURE uc_detach_event_partitions_before(p_cutoff timestamptz, INOUT p_detached text[] DEFAULT '{}') LANGUAGE plpgsql AS $$ BEGIN END $$;\n"
               "CALL uc_ensure_event_partitions();\n")
    MIG = ("uc_convert_event_table_to_partitioned ... already partitioned ...\n"
           + "".join(f"CALL uc_convert_event_table_to_partitioned('{t.lower()}', 'event_id');\n" for t in TABLES)
           + "ATTACH PARTITION x DEFAULT\n")
    DOWN = "CALL uc_departition_event_table('verificationevent','event_id');\n"
    DRILL = ("uc_ensure_event_partitions\nDETACH PARTITION\ninsufficient_privilege\n"
             "uc_convert_event_table_to_partitioned\nATTACH PARTITION\n")
    CI = "run: bash scripts/polaris-partition-drill.sh\n"
    good = {
        "polaris_sql/01_schema.sql": SCHEMA,
        "polaris_sql/migrations/2026-09-05-003-event-table-partitioning.up.sql": MIG,
        "polaris_sql/migrations/2026-09-05-003-event-table-partitioning.down.sql": DOWN,
        "scripts/polaris-partition-drill.sh": DRILL,
        ".github/workflows/ci.yml": CI,
        "scripts/polaris-partition-maintenance.sh": "uc_ensure_event_partitions\n",
        "deploy/linux/polaris-partition-maintenance.timer": "OnCalendar=*-*-02 04:00:00 UTC\n",
        "deploy/linux/install.sh": "systemctl enable polaris-partition-maintenance.timer\n",
    }
    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
    write()
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # the standing maintenance timer missing
    write({"deploy/linux/polaris-partition-maintenance.timer": "no calendar here\n"})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL without the monthly maintenance timer"
    # a table not partitioned
    write({"polaris_sql/01_schema.sql": SCHEMA.replace("PARTITION BY RANGE (event_timestamp);\nCREATE TABLE VerificationEvent_default", ";\nCREATE TABLE VerificationEvent_default", 1)})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL when a table is not partitioned"
    # a table without its DEFAULT partition
    write({"polaris_sql/01_schema.sql": SCHEMA.replace("CREATE TABLE AuthAuditLog_default PARTITION OF AuthAuditLog DEFAULT;\n", "")})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL when a table has no DEFAULT partition"
    # the manager missing
    write({"polaris_sql/01_schema.sql": SCHEMA.replace("CREATE OR REPLACE PROCEDURE uc_ensure_event_partitions", "CREATE OR REPLACE PROCEDURE uc_other")})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL when the manager is absent"
    # the migration does not convert a table
    write({"polaris_sql/migrations/2026-09-05-003-event-table-partitioning.up.sql": MIG.replace("CALL uc_convert_event_table_to_partitioned('authauditlog', 'event_id');\n", "")})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL when the migration skips a table"
    # the down cannot departition
    write({"polaris_sql/migrations/2026-09-05-003-event-table-partitioning.down.sql": "DROP TABLE x;\n"})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL when the down does not departition"
    # the drill does not detach
    write({"scripts/polaris-partition-drill.sh": DRILL.replace("DETACH PARTITION\n", "")})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL when the drill does not detach"
    # CI does not run the drill
    write({".github/workflows/ci.yml": "run: echo nope\n"})
    assert checks.check_event_table_partitioning(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the drill"


def test_read_replica_routing_check_discriminates(tmp_path):
    PAD = '\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\nx = 1\n'
    _surfaces = ["api_atlas_clusters","api_atlas_points","api_atlas_stats","api_atlas_timeline",
                 "api_atlas_subject","tokens_export","verifications_list"]
    _defs = "".join(f"@replica_reads\ndef {n}(): pass\n{PAD}" for n in _surfaces)
    APP = ("DB_CONFIG_REPLICA = None\ndef replica_reads(fn): return fn\nREPLICA_MAX_LAG_S = 10\n"
           "def _replica_lag_seconds(conn): pass\nX-Polaris-Data-Source\nprimary-failback\n"
           "_METRICS_REPLICA_FAILBACK\ndatabase_replica\nfetch in ('all', 'one')\n" + _defs)
    PGB = "${DB_NAME}_ro = host=${REPLICA_HOST}\nPOLARIS_DB_REPLICA_HOST\n"
    HA = "POLARIS_DB_REPLICA_NAME: polaris_ro\nPOLARIS_DB_REPLICA_PORT: '5433'\n"
    DRILL = "database_replica=$RH\nhealthy/True\n"
    OPS = "The staleness contract: reads may lag.\n"
    good = {
        "polaris_web/app.py": APP,
        "polaris_web/pgbouncer-entrypoint.sh": PGB,
        "polaris_web/docker-compose.ha.yml": HA,
        "scripts/polaris-failover-drill.sh": DRILL,
        "docs/operator/OPERATIONS.md": OPS,
    }
    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
    write()
    assert checks.check_read_replica_routing(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # no failback path
    write({"polaris_web/app.py": APP.replace("primary-failback", "")})
    assert checks.check_read_replica_routing(tmp_path)[0].level == "FAIL", "must FAIL without a failback path"
    # a read-only surface not decorated
    write({"polaris_web/app.py": APP.replace("@replica_reads\ndef api_atlas_stats():", "def api_atlas_stats():", 1)})
    assert checks.check_read_replica_routing(tmp_path)[0].level == "FAIL", "must FAIL when a read-only surface is undecorated"
    # a write could be routed to the replica
    write({"polaris_web/app.py": APP.replace("fetch in ('all', 'one')", "fetch in ('all','one','none')")})
    assert checks.check_read_replica_routing(tmp_path)[0].level == "FAIL", "must FAIL when a write can be routed to the replica"
    # the pooler serves no read database
    write({"polaris_web/pgbouncer-entrypoint.sh": "no ro database here\n"})
    assert checks.check_read_replica_routing(tmp_path)[0].level == "FAIL", "must FAIL when the pooler serves no read database"
    # the drill does not assert replica serving
    write({"scripts/polaris-failover-drill.sh": "echo nothing\n"})
    assert checks.check_read_replica_routing(tmp_path)[0].level == "FAIL", "must FAIL when the drill does not prove replica serving"
    # the contract is undocumented
    write({"docs/operator/OPERATIONS.md": "nothing about routing\n"})
    assert checks.check_read_replica_routing(tmp_path)[0].level == "FAIL", "must FAIL when the staleness contract is undocumented"


def test_national_simulation_check_discriminates(tmp_path):
    # A reference module covering all 50 states + DC.
    _CODES = ("CA TX FL NY PA IL OH GA NC MI NJ VA WA AZ MA TN IN MD MO WI CO MN "
              "SC AL LA KY OR OK CT UT IA NV AR MS KS NM NE ID WV HI NH ME RI MT DE "
              "SD ND AK DC VT WY").split()
    REF = "US_STATES = [\n" + "".join(f'    ("US-{c}", "S", 1),\n' for c in _CODES) + "]\n"
    NAT = ("import random\n"
           "def plan_nation(scale_divisor, seed):\n"
           "    rng = random.Random(seed)\n    return rng\n")
    LOAD = ("def build_nation(conn, plan):\n"
            "    sig = pqc.signature_with_key_for_token(tv)\n"
            "    cur.execute('CALL uc_bulk_issue(%s)', (b,))\n")
    EVENTS = ("def write_verifications(conn, events):\n"
              "    cur.copy_expert('COPY VerificationEvent (...) FROM STDIN', buf)\n"
              "def revoke_tokens(conn, count, seed):\n"
              "    cur.execute('CALL uc8_revoke_token(%s,%s,%s,%s,%s)', a)\n")
    BENCH = ("def check_invariants(conn, purposes):\n    return {'C3': True}\n"
             "def measure_crypto_verification(conn, n):\n    return {'all_verified': True}\n"
             "def run_benchmark(conn, **kw):\n    return None\n")
    COV = "run polaris_cli unittest test_cli\nrun polaris_sim unittest test_sim\n"
    good = {
        "polaris_sim/reference.py": REF,
        "polaris_sim/nation.py": NAT,
        "polaris_sim/load.py": LOAD,
        "polaris_sim/events.py": EVENTS,
        "polaris_sim/benchmark.py": BENCH,
        "polaris_sim/test_sim.py": "import unittest\n",
        "docs/reference/BENCHMARK.md": "# Benchmark\n",
        "scripts/polaris-coverage.sh": COV,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)

    write()
    assert checks.check_national_simulation(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # a harness file is missing (an empty/absent file is falsy to the check)
    write({"polaris_sim/load.py": ""})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when a harness file is missing"
    write()
    # fewer than 51 jurisdictions (not the whole country)
    write({"polaris_sim/reference.py": 'US_STATES = [("US-CA", "S", 1), ("US-TX", "S", 1)]\n'})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL without all 50 states + DC"
    # not deterministic (no seeded PRNG)
    write({"polaris_sim/nation.py": "def plan_nation(scale_divisor, seed):\n    return 1\n"})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the plan is not seeded"
    # does not go through the real pipeline
    write({"polaris_sim/load.py": "def build_nation(conn, plan):\n    pass\n"})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the loader skips uc_bulk_issue"
    # bypasses the pipeline with a direct token insert
    write({"polaris_sim/load.py": LOAD + "    cur.execute('INSERT INTO IdentityToken (status) VALUES (%s)', ('ACTIVE',))\n"})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the loader writes tokens directly"
    # the suite is not wired into the coverage run
    write({"scripts/polaris-coverage.sh": "run polaris_cli unittest test_cli\n"})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the sim suite is not in coverage"
    # S2: the event stream is missing
    write({"polaris_sim/events.py": ""})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the event stream is missing"
    # the event stream drives lifecycle without the real procedure
    write({"polaris_sim/events.py": EVENTS.replace("uc8_revoke_token", "some_other_thing")})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when lifecycle skips uc8_revoke_token"
    # the event stream fabricates lifecycle rows directly (bypass)
    write({"polaris_sim/events.py": EVENTS + "    cur.execute('INSERT INTO TokenLifecycleEvent (event_type) VALUES (%s)', ('REVOKED',))\n"})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the stream writes lifecycle rows directly"
    # S3: the benchmark harness is missing
    write({"polaris_sim/benchmark.py": ""})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the benchmark harness is missing"
    # the benchmark does not certify invariants under load
    write({"polaris_sim/benchmark.py": "def run_benchmark(conn, **kw):\n    return None\n"})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the benchmark does not check invariants"
    # the committed load-certification report is missing
    write({"docs/reference/BENCHMARK.md": ""})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the committed report is missing"
    # v9.257: the loader does not sign (mass-issued tokens would be unsigned/placeholder)
    write({"polaris_sim/load.py": LOAD.replace("signature_with_key_for_token", "something_else")})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the loader does not sign through pqc_signing"
    # the benchmark does not measure real cryptographic verification
    write({"polaris_sim/benchmark.py": BENCH.replace("measure_crypto_verification", "measure_event_ingestion_only")})
    assert checks.check_national_simulation(tmp_path)[0].level == "FAIL", "must FAIL when the benchmark skips crypto verification"


def test_bulk_enrollment_check_discriminates(tmp_path):
    SCHEMA = (
        "CREATE TABLE IF NOT EXISTS BulkEnrollmentBatch (\n"
        "    batch_id SERIAL PRIMARY KEY,\n"
        "    issuing_agency_id INTEGER NOT NULL REFERENCES Agency(agency_id)\n);\n"
        "CREATE TABLE IF NOT EXISTS BulkEnrollmentStaging (\n"
        "    staging_id BIGSERIAL PRIMARY KEY,\n"
        "    batch_id INTEGER NOT NULL REFERENCES BulkEnrollmentBatch(batch_id),\n"
        "    individual_id INTEGER\n);\n"
    )
    PROC = (
        "CREATE OR REPLACE PROCEDURE uc_bulk_issue(p_batch_id INTEGER, INOUT p_rows_issued INTEGER DEFAULT NULL)\n"
        "LANGUAGE plpgsql AS $$\nBEGIN\n"
        "    IF EXISTS (SELECT 1 FROM BulkEnrollmentBatch WHERE batch_id = p_batch_id AND issued_at IS NOT NULL) THEN\n"
        "        RAISE EXCEPTION 'already issued' USING ERRCODE = 'invalid_parameter_value'; END IF;\n"
        "    SELECT authorization_type FROM AgencyAlgorithmAuth WHERE 1=1;\n"
        "    IF v_auth NOT IN ('ISSUE','BOTH') THEN RAISE EXCEPTION 'no' USING ERRCODE = 'insufficient_privilege'; END IF;\n"
        "    UPDATE BulkEnrollmentStaging SET individual_id = COALESCE(individual_id, nextval('individual_individual_id_seq'));\n"
        "    INSERT INTO Individual (individual_id) SELECT individual_id FROM BulkEnrollmentStaging s\n"
        "      WHERE NOT EXISTS (SELECT 1 FROM Individual i WHERE i.individual_id = s.individual_id);\n"
        "    INSERT INTO IdentityToken (status) SELECT 'RESERVE' FROM BulkEnrollmentStaging;\n"
        "    INSERT INTO TokenSignature (token_id) SELECT token_id FROM BulkEnrollmentStaging;\n"
        "    INSERT INTO TokenLifecycleEvent (event_type) SELECT 'ISSUED' FROM BulkEnrollmentStaging;\n"
        "    UPDATE IdentityToken SET status = 'ACTIVE';\n"
        "END $$;\n"
    )
    UP = "CREATE TABLE IF NOT EXISTS BulkEnrollmentBatch (batch_id SERIAL);\nCREATE TABLE IF NOT EXISTS BulkEnrollmentStaging (staging_id BIGSERIAL);\n"
    DOWN = "DROP PROCEDURE IF EXISTS uc_bulk_issue(INTEGER, INTEGER);\nDROP TABLE IF EXISTS BulkEnrollmentStaging CASCADE;\nDROP TABLE IF EXISTS BulkEnrollmentBatch CASCADE;\n"
    DRILL = (r"\copy bulk_in FROM '/x' csv" "\n"
             "CALL uc_bulk_issue(v_b);\nRAISE NOTICE 'BULK_THROUGHPUT rows=1';\n"
             "EXCEPTION WHEN unique_violation THEN NULL;\n"
             "WHEN insufficient_privilege THEN NULL;\nWHEN invalid_parameter_value THEN NULL;\nROLLBACK;\n")
    CI = "run: bash scripts/polaris-bulk-drill.sh\n"
    CLI = "def cmd_bulk_enroll(args):\n    cur.copy_expert('COPY ...', fh)\nHANDLERS = {'bulk-enroll': cmd_bulk_enroll}\n"
    good = {
        "polaris_sql/01_schema.sql": SCHEMA,
        "polaris_sql/05_procedures.sql": PROC,
        "polaris_sql/migrations/2026-09-06-001-bulk-enrollment.up.sql": UP,
        "polaris_sql/migrations/2026-09-06-001-bulk-enrollment.down.sql": DOWN,
        "scripts/polaris-bulk-drill.sh": DRILL,
        ".github/workflows/ci.yml": CI,
        "polaris_cli/polaris.py": CLI,
    }
    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
    write()
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # a staging table missing
    write({"polaris_sql/01_schema.sql": SCHEMA.replace("CREATE TABLE IF NOT EXISTS BulkEnrollmentStaging (", "CREATE TABLE IF NOT EXISTS Other (")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when a bulk table is missing"
    # staging cascades from the batch (forbidden: staging is cleaned explicitly)
    write({"polaris_sql/01_schema.sql": SCHEMA.replace("REFERENCES BulkEnrollmentBatch(batch_id),", "REFERENCES BulkEnrollmentBatch(batch_id) ON DELETE CASCADE,")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when staging cascades from the batch"
    # the authorization gate absent
    write({"polaris_sql/05_procedures.sql": PROC.replace("AgencyAlgorithmAuth", "SomeOtherTable")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL without the AgencyAlgorithmAuth gate"
    # the already-issued guard absent
    write({"polaris_sql/05_procedures.sql": PROC.replace("issued_at IS NOT NULL", "1=2")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL without the already-issued guard"
    # the new-person/re-card correlation absent (C3 would be unreachable across a batch)
    write({"polaris_sql/05_procedures.sql": PROC.replace("COALESCE(individual_id,", "(")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL without the individual_id correlation"
    # a set-based issue step absent
    write({"polaris_sql/05_procedures.sql": PROC.replace("INSERT INTO TokenSignature", "INSERT INTO NothingHere")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when the signature insert is missing"
    # the down migration cannot revert
    write({"polaris_sql/migrations/2026-09-06-001-bulk-enrollment.down.sql": "DROP TABLE x;\n"})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when the down does not drop staging + the procedure"
    # the drill does not stage with COPY
    write({"scripts/polaris-bulk-drill.sh": DRILL.replace(r"\copy", "insert")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when the drill does not COPY"
    # the drill does not exercise atomicity/C3
    write({"scripts/polaris-bulk-drill.sh": DRILL.replace("unique_violation", "nope")})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when the drill does not prove all-or-none"
    # CI does not run the drill
    write({".github/workflows/ci.yml": "run: echo nope\n"})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the drill"
    # the operator CLI command is absent
    write({"polaris_cli/polaris.py": "HANDLERS = {'issue': cmd_issue}\n"})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when the bulk-enroll CLI command is absent"
    # the CLI issues row-by-row instead of staging with COPY
    write({"polaris_cli/polaris.py": "def cmd_bulk_enroll(args):\n    pass\nHANDLERS = {'bulk-enroll': cmd_bulk_enroll}\n"})
    assert checks.check_bulk_enrollment(tmp_path)[0].level == "FAIL", "must FAIL when the CLI does not stage with COPY"


def test_atlas_console_check_discriminates(tmp_path):
    ATLAS = ('<button data-atlas-view-tab="overview" aria-selected="true" class="atlas-tab atlas-tab-active">Overview</button>\n'
             '<button data-atlas-view-tab="breakdown" aria-selected="false">Breakdown</button>\n'
             '<button data-atlas-view-tab="records" aria-selected="false">Records</button>\n'
             '<button data-atlas-view-tab="trends" aria-selected="false">Trends</button>\n'
             '<div data-trends-heatmap></div><div data-trends-stacked></div>'
             '<button data-trends-dim="context">Context</button>\n'
             '<button data-atlas-view-tab="map" aria-selected="false">Map</button>\n'
             '<input data-bd-search><div class="bd-scroll"><div data-bd-ranked></div></div>\n'
             '<table data-rec-grid><tbody data-rec-body></tbody></table><button data-rec-more>Load more</button>\n'
             '<button data-atlas-mapmode="regions" aria-pressed="true">Regions</button>\n'
             '<button data-atlas-mapmode="density">Density</button>\n'
             '<button data-atlas-mapmode="points">Points</button>\n'
             '<button data-atlas-projection>Globe</button>\n'
             '<div data-atlas-globalbar><div data-gf-facet="context"></div>'
             '<input data-gf-agency-search></div>\n'
             '<script src="atlas-console.js"></script>\n')
    def sqlfn(name, ret, extra_args=""):
        return (f"CREATE OR REPLACE FUNCTION {name}(\n    p_x INTEGER{extra_args}\n) RETURNS TABLE (\n{ret}\n)\n"
                f"LANGUAGE sql\nSTABLE\nAS $$ SELECT 1 $$;\n")
    # atlas_records is keyset-paginated (a cursor pair, not an OFFSET) and
    # redacts zero-knowledge rows — spelled out rather than via sqlfn().
    RECORDS = ("CREATE OR REPLACE FUNCTION atlas_records(\n"
               "    p_since TIMESTAMP, p_cursor_ts TIMESTAMP, p_cursor_id INTEGER, p_limit INTEGER\n"
               ") RETURNS TABLE (\n    event_id INTEGER, subject TEXT, location TEXT\n)\n"
               "LANGUAGE sql\nSTABLE\nAS $$ SELECT 1, '(zero-knowledge)', NULL $$;\n")
    # Map v2 (v9.253): the hexbin excludes ZK; the jurisdiction rollup counts
    # ZK (n_zk) but builds its centroid from located non-ZK events only.
    HEXBIN = ("CREATE OR REPLACE FUNCTION atlas_hexbin(\n    p_x DOUBLE PRECISION\n) RETURNS TABLE (\n"
              "    lat DOUBLE PRECISION, lon DOUBLE PRECISION, n_total BIGINT, n_failure BIGINT\n)\n"
              "LANGUAGE sql\nSTABLE\nAS $$ SELECT 1 WHERE disclosure_level <> 'ZERO_KNOWLEDGE' $$;\n")
    GEOJUR = ("CREATE OR REPLACE FUNCTION atlas_geo_jurisdictions(\n    p_x TIMESTAMP\n) RETURNS TABLE (\n"
              "    jurisdiction TEXT, n_total BIGINT, n_zk BIGINT, n_located BIGINT,\n"
              "    centroid_lat DOUBLE PRECISION, centroid_lon DOUBLE PRECISION\n)\n"
              "LANGUAGE sql\nSTABLE\nAS $$ SELECT avg(ve.latitude) FILTER (WHERE ve.disclosure_level <> 'ZERO_KNOWLEDGE') $$;\n")
    # Trends (v9.265): the heatmap + stacked series window on COALESCE(p_since)
    # so the generic plan prunes the monthly partitions.
    HEATMAP = ("CREATE OR REPLACE FUNCTION atlas_heatmap(\n    p_since TIMESTAMP\n) RETURNS TABLE (\n"
               "    dow INTEGER, hour INTEGER, n BIGINT, n_failure BIGINT\n)\n"
               "LANGUAGE sql\nSTABLE\nAS $$ SELECT 1 WHERE event_timestamp >= COALESCE(p_since, '-infinity'::timestamp) $$;\n")
    STACKED = ("CREATE OR REPLACE FUNCTION atlas_series_stacked(\n    p_since TIMESTAMP, p_buckets INTEGER, p_dimension TEXT\n) RETURNS TABLE (\n"
               "    bucket_ts TIMESTAMP, label TEXT, n BIGINT\n)\n"
               "LANGUAGE sql\nSTABLE\nAS $$ SELECT 1 WHERE event_timestamp >= COALESCE(p_since, '-infinity'::timestamp) $$;\n")
    SQL = (sqlfn("atlas_volume_series", "    bucket_ts TIMESTAMP, n_total BIGINT, n_failure BIGINT, n_zk BIGINT")
           + sqlfn("atlas_breakdown", "    label TEXT, n_total BIGINT, n_failure BIGINT", ",\n    p_search TEXT DEFAULT NULL")
           + sqlfn("atlas_crosstab", "    row_label TEXT, col_label TEXT, n_total BIGINT")
           + sqlfn("atlas_agency_facet", "    agency_id INTEGER, name TEXT, n_total BIGINT")
           + RECORDS + HEXBIN + GEOJUR + HEATMAP + STACKED)
    APP = ("_ATLAS_MAX_CLUSTERS=5000\n_ATLAS_MAX_POINTS=2000\n_ATLAS_MAX_EVENTS=500\n_ATLAS_MAX_CATEGORIES=50\n"
           "_ATLAS_BREAKDOWN_DIMENSIONS={'verification': ('agency',)}\n"
           "_ATLAS_CROSSTAB_ROWS={'verification': ('agency',)}\n"
           "_ATLAS_CROSSTAB_COLS={'verification': ('outcome',)}\n"
           "@app.route('/api/atlas/series')\n@replica_reads\ndef api_atlas_series():\n    pass\n"
           "@app.route('/api/atlas/breakdown')\n@replica_reads\ndef api_atlas_breakdown():\n    pass\n"
           "@app.route('/api/atlas/crosstab')\n@replica_reads\ndef api_atlas_crosstab():\n    pass\n"
           "@app.route('/api/atlas/facet/agencies')\n@replica_reads\ndef api_atlas_facet_agencies():\n    pass\n"
           "@app.route('/api/atlas/records')\n@replica_reads\ndef api_atlas_records():\n    pass\n"
           "@app.route('/api/atlas/hexbin')\n@replica_reads\ndef api_atlas_hexbin():\n    pass\n"
           "@app.route('/api/atlas/geo/jurisdictions')\n@replica_reads\ndef api_atlas_geo_jurisdictions():\n    pass\n"
           "_ATLAS_STACK_DIMENSIONS={'verification': ('context',)}\n"
           "@app.route('/api/atlas/heatmap')\n@replica_reads\ndef api_atlas_heatmap():\n    pass\n"
           "@app.route('/api/atlas/stacked')\n@replica_reads\ndef api_atlas_stacked():\n    pass\n")
    good = {
        "polaris_web/templates/atlas.html": ATLAS,
        "polaris_web/static/atlas-console.js": "/* console */\n",
        "polaris_sql/11_atlas.sql": SQL,
        "polaris_web/app.py": APP,
    }
    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
    write()
    assert checks.check_atlas_console(tmp_path)[0].level == "OK", "must PASS on the good fixture"
    # Overview is not the default view
    write({"polaris_web/templates/atlas.html": ATLAS.replace('aria-selected="true"', 'aria-selected="false"').replace('atlas-tab-active', 'atlas-tab')})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when Overview is not the default view"
    # the console script is not loaded
    write({"polaris_web/templates/atlas.html": ATLAS.replace('atlas-console.js', 'other.js')})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas-console.js is not loaded"
    # an aggregate leaks a location column (C6)
    write({"polaris_sql/11_atlas.sql": SQL.replace("bucket_ts TIMESTAMP, n_total BIGINT, n_failure BIGINT, n_zk BIGINT",
                                                   "bucket_ts TIMESTAMP, lat DOUBLE PRECISION, n_total BIGINT")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when an aggregate returns a location column"
    # an endpoint is missing
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/breakdown')", "@app.route('/api/atlas/other')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the breakdown endpoint is absent"
    # the series endpoint is not replica-routed
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/series')\n@replica_reads", "@app.route('/api/atlas/series')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when api_atlas_series is not @replica_reads"
    # the Breakdown tab is absent
    write({"polaris_web/templates/atlas.html": ATLAS.replace('data-atlas-view-tab="breakdown"', 'data-atlas-view-tab="other"')})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the Breakdown tab is absent"
    # the crosstab endpoint is absent
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/crosstab')", "@app.route('/api/atlas/other')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the crosstab endpoint is absent"
    # the crosstab dimensions are not whitelisted
    write({"polaris_web/app.py": APP.replace("_ATLAS_CROSSTAB_ROWS", "_SOMETHING_ELSE")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the crosstab dimensions are not whitelisted"
    # atlas_crosstab leaks a location column (C6)
    write({"polaris_sql/11_atlas.sql": SQL.replace("row_label TEXT, col_label TEXT, n_total BIGINT",
                                                   "row_label TEXT, lon DOUBLE PRECISION, n_total BIGINT")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_crosstab returns a location column"
    # the Breakdown is not searchable (a scale regression)
    write({"polaris_web/templates/atlas.html": ATLAS.replace("data-bd-search", "data-bd-other")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the Breakdown has no search box"
    # the Breakdown list does not scroll internally
    write({"polaris_web/templates/atlas.html": ATLAS.replace("bd-scroll", "bd-static")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the Breakdown list does not scroll internally"
    # atlas_breakdown cannot filter by label
    write({"polaris_sql/11_atlas.sql": SQL.replace("p_search", "p_other")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_breakdown has no label filter"
    # the global filter bar is absent
    write({"polaris_web/templates/atlas.html": ATLAS.replace("data-atlas-globalbar", "data-atlas-other")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL without the global filter bar"
    # the agency facet is a flat flyout, not a typeahead
    write({"polaris_web/templates/atlas.html": ATLAS.replace("data-gf-agency-search", "data-gf-agency-flyout")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the agency facet is not a typeahead"
    # the agency facet endpoint is absent
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/facet/agencies')", "@app.route('/api/atlas/facet/other')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the agency facet endpoint is absent"
    # v9.252: the Records tab is absent
    write({"polaris_web/templates/atlas.html": ATLAS.replace('data-atlas-view-tab="records"', 'data-atlas-view-tab="other"')})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the Records tab is absent"
    # the Records grid or its keyset 'load more' control is absent
    write({"polaris_web/templates/atlas.html": ATLAS.replace("data-rec-grid", "data-rec-other")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the Records grid is absent"
    write({"polaris_web/templates/atlas.html": ATLAS.replace("data-rec-more", "data-rec-other")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the keyset 'load more' control is absent"
    # atlas_records is absent
    write({"polaris_sql/11_atlas.sql": SQL.replace("CREATE OR REPLACE FUNCTION atlas_records(", "CREATE OR REPLACE FUNCTION atlas_other(")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_records is absent"
    # atlas_records is OFFSET-paginated, not keyset (a scale regression)
    write({"polaris_sql/11_atlas.sql": SQL.replace("p_cursor_ts TIMESTAMP, p_cursor_id INTEGER, ", "")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_records is not keyset-paginated"
    # atlas_records does not redact zero-knowledge rows (C6)
    write({"polaris_sql/11_atlas.sql": SQL.replace("'(zero-knowledge)'", "i.legal_name")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_records does not redact ZK rows"
    # the records endpoint is absent
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/records')", "@app.route('/api/atlas/other')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the records endpoint is absent"
    # the records endpoint is not replica-routed
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/records')\n@replica_reads", "@app.route('/api/atlas/records')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when api_atlas_records is not @replica_reads"
    # v9.253: a Map layer mode is absent (Regions/Density/Points)
    for mode in ('regions', 'density', 'points'):
        write({"polaris_web/templates/atlas.html": ATLAS.replace('data-atlas-mapmode="' + mode + '"', 'data-atlas-mapmode="other"')})
        assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", f"must FAIL when the {mode} map mode is absent"
    # the globe is not an opt-in projection toggle
    write({"polaris_web/templates/atlas.html": ATLAS.replace("data-atlas-projection", "data-atlas-other")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the globe projection toggle is absent"
    # a Map v2 SQL function is absent
    write({"polaris_sql/11_atlas.sql": SQL.replace("CREATE OR REPLACE FUNCTION atlas_hexbin(", "CREATE OR REPLACE FUNCTION atlas_other(")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_hexbin is absent"
    write({"polaris_sql/11_atlas.sql": SQL.replace("CREATE OR REPLACE FUNCTION atlas_geo_jurisdictions(", "CREATE OR REPLACE FUNCTION atlas_other(")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_geo_jurisdictions is absent"
    # a Map v2 endpoint is absent / not replica-routed
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/hexbin')", "@app.route('/api/atlas/other')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the hexbin endpoint is absent"
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/geo/jurisdictions')", "@app.route('/api/atlas/other')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the geo/jurisdictions endpoint is absent"
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/hexbin')\n@replica_reads", "@app.route('/api/atlas/hexbin')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when api_atlas_hexbin is not @replica_reads"
    # v9.265 (Trends): the Trends tab is absent
    write({"polaris_web/templates/atlas.html": ATLAS.replace('data-atlas-view-tab="trends"', 'data-atlas-view-tab="nope"')})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the Trends tab is absent"
    # the heatmap aggregate is missing
    write({"polaris_sql/11_atlas.sql": SQL.replace(HEATMAP, "")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when atlas_heatmap is absent"
    # the stacked series no longer prunes (windows on the wrong thing)
    write({"polaris_sql/11_atlas.sql": SQL.replace("COALESCE(p_since, '-infinity'::timestamp)", "now()")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when a Trends aggregate does not prune"
    # the stacked endpoint is absent
    write({"polaris_web/app.py": APP.replace("@app.route('/api/atlas/stacked')", "@app.route('/api/atlas/nope')")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the stacked Trends endpoint is absent"
    # the stacked dimensions are not whitelisted
    write({"polaris_web/app.py": APP.replace("_ATLAS_STACK_DIMENSIONS", "_NOPE")})
    assert checks.check_atlas_console(tmp_path)[0].level == "FAIL", "must FAIL when the stacked dimensions are not whitelisted"


def test_helm_reference_profile_check_discriminates(tmp_path):
    HELPERS = "runAsNonRoot: true\nseccompProfile:\n  type: RuntimeDefault\ncapabilities:\n  drop: [\"ALL\"]\nallowPrivilegeEscalation: false\n"
    NP = ("name: x-default-deny\npolicyTypes: [Ingress, Egress]\nname: x-allow-dns\n" + "kind: NetworkPolicy\n" * 7
          + "- {protocol: TCP, port: 8008}\napiServer\n")
    DRILL = ("kubectl apply -f calico.yaml\nkubectl label namespace polaris pod-security.kubernetes.io/enforce=restricted\n"
             "grep -q \"violates PodSecurity\"\nhelm install polaris\ncurl /api/health custody\n"
             "targets = [(\"polaris-postgres\", 5432)]\nprint(\"REACHED\")\nkubectl rollout restart deploy/polaris-app\n"
             "jsonpath='{.metadata.annotations.leader}'\nkubectl delete pod $L0\nctr -n k8s.io task pause\npatronictl switchover\nCREATE TABLE ha_marker\n"
             "fail \"inserts were acknowledged\"\n")
    PG = ("automountServiceAccountToken: true\nkind: Role\nkind: RoleBinding\n(dict \"uid\" 70 \"gid\" 70)\n"
          "value: /var/lib/postgresql/data/pgdata\n- {name: POLARIS_PATRONI_DCS, value: kubernetes}\n"
          "replicas: {{ .Values.postgres.replicas }}\nargs: [\"/usr/local/bin/polaris-patroni-entrypoint.sh\"]\n"
          "application: polaris-db\ncluster-name: x\nname: x-postgres-members\nname: x-postgres-replicas\nrole: replica\n")
    good = {
        "deploy/helm/polaris/Chart.yaml": "apiVersion: v2\nname: polaris\nversion: 0.1.0\n",
        "deploy/helm/polaris/values.yaml": "networkPolicy:\n  enabled: true\nsecrets:\n  existingSecret: \"\"\n",
        "deploy/helm/polaris/templates/_helpers.tpl": HELPERS,
        "deploy/helm/polaris/templates/networkpolicy.yaml": NP,
        "deploy/helm/polaris/templates/app.yaml": "automountServiceAccountToken: false\nmaxUnavailable: 0\npath: /api/health/live\nkind: PodDisruptionBudget\n",
        "deploy/helm/polaris/templates/postgres.yaml": PG,
        "deploy/helm/polaris/templates/caddy.yaml": "automountServiceAccountToken: false\n",
        "deploy/helm/polaris/templates/pgbouncer.yaml": "automountServiceAccountToken: false\n- {name: POLARIS_DB_HOST, value: {{ include \"polaris.fullname\" . }}-pg-router}\n",
        "deploy/helm/polaris/templates/pg-router.yaml": "option httpchk GET /primary\ncheck port 8008\ndefault-server on-marked-down shutdown-sessions\n",
        "deploy/helm/polaris/templates/redis.yaml": "automountServiceAccountToken: false\n", "deploy/helm/polaris/templates/secret.yaml": "x",
        "polaris_web/Dockerfile.caddy": "COPY caddy\nRUN setcap -r /usr/bin/caddy\n",
        "deploy/helm/polaris/templates/configmap-caddy.yaml": "x",
        "polaris_web/Dockerfile.postgres": ("COPY --chown=postgres:postgres polaris_sql /docker-entrypoint-initdb.d/sql\n"
                                            "COPY --chmod=0755 polaris_web/docker-init.sh /docker-entrypoint-initdb.d/00-init.sh\n"
                                            "COPY polaris_web/pgbackrest.conf /etc/pgbackrest/pgbackrest.conf\n"),
        "scripts/polaris-helm-drill.sh": DRILL,
        "deploy/helm/kind-config.yaml": "networking:\n  disableDefaultCNI: true\n",
        ".github/workflows/ci.yml": "uses: helm/kind-action@v1.14.0\nrun: bash scripts/polaris-helm-drill.sh\n",
        "docs/operator/KUBERNETES.md": "restricted Pod Security Standard; Calico enforces NetworkPolicy\n",
        "README.md": "[KUBERNETES](docs/operator/KUBERNETES.md)\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # kind with its default CNI (policies would be decorative).
    write({"deploy/helm/kind-config.yaml": "networking: {}\n"})
    f = checks.check_helm_reference_profile(tmp_path)[0]
    assert f.level == "FAIL" and "kindnet" in f.message, "must FAIL when the drill runs on a non-enforcing CNI"

    # A pod allowed to escalate privileges.
    write({"deploy/helm/polaris/templates/_helpers.tpl": HELPERS.replace("allowPrivilegeEscalation: false\n", "")})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL when the restricted standard is not met"

    # Postgres as root.
    write({"deploy/helm/polaris/templates/postgres.yaml": PG.replace("(dict \"uid\" 70 \"gid\" 70)", "(dict \"uid\" 0 \"gid\" 0)")})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL when postgres runs as root"
    # v9.244: postgres without the lease store (no Patroni, no Role) is one replica with no failover.
    write({"deploy/helm/polaris/templates/postgres.yaml": PG.replace("- {name: POLARIS_PATRONI_DCS, value: kubernetes}\n", "")})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL when the database is not under Patroni"
    write({"deploy/helm/polaris/templates/postgres.yaml": PG.replace("kind: Role\n", "")})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL when Patroni has no Role"
    # pgbouncer dialling the leader Service directly: a frozen leader holds its pool.
    write({"deploy/helm/polaris/templates/pgbouncer.yaml": "automountServiceAccountToken: false\n- {name: POLARIS_DB_HOST, value: {{ include \"polaris.fullname\" . }}-postgres}\n"})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL when pgbouncer bypasses the router"
    # A drill that never deletes the leader pod.
    write({"scripts/polaris-helm-drill.sh": DRILL.replace("kubectl delete pod $L0\n", "")})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL when the kind drill has no failover"

    # A drill with no negative policy probe.
    write({"scripts/polaris-helm-drill.sh": DRILL.replace("print(\"REACHED\")\n", "")})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL without the policy-denial probe"

    # The SQL not baked into the postgres image.
    write({"polaris_web/Dockerfile.postgres": "FROM postgres\n"})
    assert checks.check_helm_reference_profile(tmp_path)[0].level == "FAIL", "must FAIL when the postgres image is not self-contained"


def test_distributed_tracing_check_discriminates(tmp_path):
    TRACING = (
        "POLARIS_OTEL\ndef is_enabled():\n    pass\n"
        "boot.tracing_enabled boot.tracing_unavailable\n"
        "Psycopg2Instrumentor().instrument(tracer_provider=provider)\n"
        "rule = request.url_rule.rule if request.url_rule else 'UNMATCHED'\n"
        "span.set_status(StatusCode.ERROR, type(exc).__name__)\n"
        "if os.environ.get('POLARIS_TRUST_PROXY', '').lower() in _TRUTHY:\n"
        "    parent = _otel_extract(...)\n"
        "attributes={'http.target': path}\n"
    )
    OVERVIEW = ('{"uid": "polaris-overview", "title": "x", "panels": [{"targets": ['
                '{"expr": "sum(rate(polaris_requests_total[5m]))"},'
                '{"expr": "polaris_duress_events_total"}]}]}')
    TRACES = ('{"uid": "polaris-traces", "title": "x", "panels": [{"targets": ['
              '{"queryType": "traceql", "query": "{span.polaris.request_id=\\"$id\\"}"}]}]}')
    DRILL = ("POST /v1/traces\nassert rid.encode() in payload  # X-Request-ID join\n"
             "assert MARKER.encode() not in payload\n")
    good = {
        "polaris_web/tracing.py": TRACING,
        "polaris_web/observability.py": "def set_trace_context_provider(fn):\n    pass\n_ids = _trace_context_provider()\n",
        "polaris_web/app.py": "tracing.init_app(app)\n",
        "polaris_web/requirements.txt": ("opentelemetry-sdk==1.44.0\nopentelemetry-exporter-otlp-proto-http==1.44.0\n"
                                          "opentelemetry-instrumentation-psycopg2==0.65b0\n"),
        "polaris_web/docker-compose.prod.yml": 'POLARIS_OTEL: "x"\nOTEL_EXPORTER_OTLP_ENDPOINT: "x"\n',
        "polaris_web/docker-compose.observability.yml": (
            "image: grafana/tempo@sha256:x\nimage: grafana/grafana@sha256:y\n"
            "- ../deploy/observability/grafana/provisioning:/etc/grafana/provisioning:ro\n"
            "- ../deploy/observability/tempo.yml:/etc/tempo.yml:ro\n"),
        "deploy/observability/grafana/provisioning/datasources/datasources.yml": "uid: polaris-prometheus\nuid: polaris-tempo\n",
        "deploy/observability/grafana/provisioning/dashboards/dashboards.yml": "path: /var/lib/grafana/dashboards\n",
        "deploy/observability/grafana/dashboards/polaris-overview.json": OVERVIEW,
        "deploy/observability/grafana/dashboards/polaris-traces.json": TRACES,
        "deploy/observability/tempo.yml": "receivers:\n  otlp:\n",
        "scripts/polaris-trace-drill.sh": DRILL,
        ".github/workflows/ci.yml": "run: bash scripts/polaris-trace-drill.sh\n",
        "polaris_web/test_app.py": "class DistributedTracingTests: ...\n",
        "docs/operator/OPERATIONS.md": "### Distributed tracing (v9.187)\n",
        "deploy/observability/README.md": "docker-compose.observability.yml\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_distributed_tracing(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # Tracing without the opt-in gate (always-on telemetry).
    write({"polaris_web/tracing.py": TRACING.replace("POLARIS_OTEL\ndef is_enabled():\n    pass\n", "")})
    assert checks.check_distributed_tracing(tmp_path)[0].level == "FAIL", "must FAIL without the POLARIS_OTEL gate"

    # Inbound traceparent honoured from anyone (untrusted client steers correlation).
    write({"polaris_web/tracing.py": TRACING.replace("POLARIS_TRUST_PROXY", "ANY_CLIENT")})
    assert checks.check_distributed_tracing(tmp_path)[0].level == "FAIL", "must FAIL when traceparent is not proxy-gated"

    # A dashboard that dropped the duress panel (the alarm off the wall).
    write({"deploy/observability/grafana/dashboards/polaris-overview.json":
           OVERVIEW.replace('{"expr": "polaris_duress_events_total"}', '{"expr": "polaris_up"}')})
    assert checks.check_distributed_tracing(tmp_path)[0].level == "FAIL", "must FAIL when the overview omits the duress metric"

    # A drill that stopped asserting the query string absent from the wire.
    write({"scripts/polaris-trace-drill.sh": DRILL.replace("assert MARKER.encode() not in payload\n", "")})
    assert checks.check_distributed_tracing(tmp_path)[0].level == "FAIL", "must FAIL when the wire scrub is unproven"

    # The app never wires tracing in.
    write({"polaris_web/app.py": "pass\n"})
    assert checks.check_distributed_tracing(tmp_path)[0].level == "FAIL", "must FAIL when app.py does not call tracing.init_app"


def test_postgres_probes_use_tcp_check_discriminates(tmp_path):
    CI = ('          --health-cmd "pg_isready -h 127.0.0.1"\n'
          "docker exec -e PGPASSWORD=x pg psql -h 127.0.0.1 -U postgres -d polaris -tAc 'SELECT 1' && break\n"
          'docker exec -e PGPASSWORD=x pg psql -U postgres -q -c "CREATE ROLE polaris_app LOGIN"\n')
    DRILL = ("docker exec -e PGPASSWORD=rootpw \"$PRI\" psql -h 127.0.0.1 -U postgres -d polaris -tAc 'SELECT 1'\n"
             'docker logs "$PRI" 2>&1 | tail -40 >&2 || true\n')
    good = {
        ".github/workflows/ci.yml": CI,
        "scripts/polaris-deploy.sh": "compose exec -T postgres pg_isready -h 127.0.0.1 -U postgres\n",
        "scripts/polaris-offsite-drill.sh": DRILL,
        "polaris_web/docker-compose.prod.yml": 'test: ["CMD-SHELL", "pg_isready -h 127.0.0.1 -U postgres -d polaris"]\n',
        "deploy/helm/polaris/templates/postgres.yaml": 'command: ["pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "polaris"]\n',
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_postgres_probes_use_tcp(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # A compose healthcheck back on the Unix socket (answered by the temporary init server).
    write({"polaris_web/docker-compose.prod.yml": 'test: ["CMD-SHELL", "pg_isready -U postgres -d polaris"]\n'})
    assert checks.check_postgres_probes_use_tcp(tmp_path)[0].level == "FAIL", "must FAIL on a socket healthcheck"

    # A CI readiness loop back on the socket.
    write({".github/workflows/ci.yml": CI.replace("psql -h 127.0.0.1 -U postgres -d polaris -tAc 'SELECT 1'",
                                                  "psql -U postgres -d polaris -tAc 'SELECT 1'")})
    assert checks.check_postgres_probes_use_tcp(tmp_path)[0].level == "FAIL", "must FAIL on a socket SELECT 1 loop"

    # A Helm exec probe without the host flag.
    write({"deploy/helm/polaris/templates/postgres.yaml": 'command: ["pg_isready", "-U", "postgres", "-d", "polaris"]\n'})
    assert checks.check_postgres_probes_use_tcp(tmp_path)[0].level == "FAIL", "must FAIL on a socket Helm probe"

    # A commented-out socket probe, and a non-probe psql line, are not offenders.
    write({".github/workflows/ci.yml": CI + "# docker exec pg psql -U postgres -d polaris -tAc 'SELECT 1'\n"})
    assert checks.check_postgres_probes_use_tcp(tmp_path)[0].level == "OK", "a comment is not a probe"

    # The drill stopped dumping the primary's logs on failure.
    write({"scripts/polaris-offsite-drill.sh": DRILL.replace('docker logs "$PRI" 2>&1 | tail -40 >&2 || true\n', "")})
    assert checks.check_postgres_probes_use_tcp(tmp_path)[0].level == "FAIL", "must FAIL without the log dump"


def test_session_origin_hardening_check_discriminates(tmp_path):
    WA = ("POLARIS_WEBAUTHN_ATTESTATION POLARIS_WEBAUTHN_USER_VERIFICATION "
          "POLARIS_WEBAUTHN_REQUIRE_ATTESTATION POLARIS_WEBAUTHN_ALLOWED_AAGUIDS\n"
          "COSEAlgorithmIdentifier.ML_DSA_65\nclass AttestationPolicyViolation(Exception): pass\n"
          "def verify_registration():\n    x(require_user_verification=_require_user_verification())\n"
          "def verify_authentication():\n    x(require_user_verification=_require_user_verification())\n")
    SEC = ("POLARIS_NETWORK_POLICY_ POLARIS_SESSION_MAX_ POLARIS_SESSION_IDLE_MINUTES_\n"
           "def network_policy_allows(role, ip):\n    pass\n"
           "def validate_role_policies():\n    pass\n"
           "def register_session(get_conn, user):\n    pass\n"
           "def revoke_session(get_conn, sid, reason):\n    pass\n"
           "def authenticate(get_conn, username, password):\n"
           "    ip = client_ip()\n    if not network_policy_allows(user['role'], ip):\n"
           "        _audit(get_conn, 'NETWORK_POLICY_DENIED')\n"
           "def login_user(user, get_conn=None):\n    session['sid'] = register_session(get_conn, user)\n"
           "def logout_user(get_conn):\n    revoke_session(get_conn, session['sid'], 'logout')\n"
           "def validate_session(get_conn):\n    row['revoked_at']; row['is_active']; idle = 1\n"
           "    network_policy_allows(role, client_ip())\n")
    APP = ("_ROLE_POLICY = security.validate_role_policies()\n"
           "_WEBAUTHN_POLICY = webauthn_auth.validate_policy()\n"
           "@app.before_request\ndef _session_before_request():\n    return security.validate_session(get_db)\n"
           "except webauthn_auth.AttestationPolicyViolation as e:\n    pass\n")
    MIG = ("CREATE TABLE IF NOT EXISTS OperatorSession (\n"
           "'NETWORK_POLICY_DENIED', 'SESSION_EVICTED', 'SESSION_EXPIRED', 'SESSION_REVOKED', "
           "'WEBAUTHN_REGISTRATION_REFUSED'\n")
    COMPOSE = ('POLARIS_NETWORK_POLICY_ADMIN: "${POLARIS_NETWORK_POLICY_ADMIN:-}"\n'
               'POLARIS_SESSION_MAX_ADMIN: "${POLARIS_SESSION_MAX_ADMIN:-}"\n'
               'POLARIS_WEBAUTHN_ATTESTATION: "${POLARIS_WEBAUTHN_ATTESTATION:-none}"\n')
    good = {
        "polaris_web/requirements.txt": "webauthn==3.0.0\npyasn1-modules==0.4.2\n",
        ".github/dependabot.yml": 'ignore:\n  - dependency-name: "redis"\n',
        "polaris_web/webauthn_auth.py": WA,
        "polaris_web/security.py": SEC,
        "polaris_web/app.py": APP,
        "polaris_sql/migrations/2026-09-01-001-operator-session.up.sql": MIG,
        "polaris_sql/migrations/2026-09-01-001-operator-session.down.sql": "DROP TABLE IF EXISTS OperatorSession;\n",
        "polaris_sql/01_schema.sql": "DROP TABLE IF EXISTS OperatorSession CASCADE;\n",
        "polaris_cli/polaris.py": "UPDATE OperatorSession\nUPDATE OperatorSession\n",
        "polaris_web/test_app.py": "class WebAuthnCeremonyTests: ...\nclass NetworkPolicyTests: ...\nclass SessionLimitTests: ...\n",
        "docs/operator/HARDENING.md": "POLARIS_NETWORK_POLICY_<ROLE> POLARIS_SESSION_MAX_<ROLE>\n",
        "docs/operator/WEBAUTHN-ROLLOUT.md": "POLARIS_WEBAUTHN_ATTESTATION\n",
        "docs/operator/SECURITY-CONTROLS.md": "SESSION_EVICTED\n",
        "polaris_web/docker-compose.prod.yml": COMPOSE,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    write({"polaris_web/requirements.txt": "webauthn==2.7.1\npyasn1-modules==0.4.2\n"})
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "FAIL", "must FAIL on the 2.x pin"

    write({".github/dependabot.yml": 'ignore:\n  - dependency-name: "webauthn"\n'})
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "FAIL", "must FAIL while Dependabot still ignores webauthn"

    write({"polaris_web/webauthn_auth.py": WA.replace(
        "def verify_authentication():\n    x(require_user_verification=_require_user_verification())\n",
        "def verify_authentication():\n    x(require_user_verification=False)\n")})
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "FAIL", "must FAIL when UV is hardcoded off"

    write({"polaris_web/security.py": SEC.replace(
        "    ip = client_ip()\n    if not network_policy_allows(user['role'], ip):\n"
        "        _audit(get_conn, 'NETWORK_POLICY_DENIED')\n", "    pass\n")})
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "FAIL", "must FAIL when login skips the network policy"

    write({"polaris_web/security.py": SEC.replace("row['is_active']; ", "")})
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "FAIL", "must FAIL when live sessions ignore deactivation"

    write({"polaris_web/app.py": APP.replace("    return security.validate_session(get_db)\n", "    return None\n")})
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "FAIL", "must FAIL when the registry hook is not wired"

    write({"polaris_web/docker-compose.prod.yml": COMPOSE.replace('POLARIS_SESSION_MAX_ADMIN: "${POLARIS_SESSION_MAX_ADMIN:-}"\n', "")})
    assert checks.check_session_origin_hardening(tmp_path)[0].level == "FAIL", "must FAIL when compose drops a knob"


def test_schema_reload_idempotent_check_discriminates(tmp_path):
    SCHEMA = ("DROP TABLE IF EXISTS Beta CASCADE;\nDROP TABLE IF EXISTS Alpha CASCADE;\n"
              "CREATE TABLE Alpha (id int);\n")
    MIG = "CREATE TABLE IF NOT EXISTS Beta (id int);\n"

    def write(schema=SCHEMA, mig=MIG):
        (tmp_path / "polaris_sql" / "migrations").mkdir(parents=True, exist_ok=True)
        (tmp_path / "polaris_sql" / "01_schema.sql").write_text(schema)
        (tmp_path / "polaris_sql" / "migrations" / "2026-01-01-001-beta.up.sql").write_text(mig)

    write()
    assert checks.check_schema_reload_idempotent(tmp_path)[0].level == "OK", "must PASS when every table is dropped"

    write(mig="CREATE TABLE Gamma (id int);\n")
    assert checks.check_schema_reload_idempotent(tmp_path)[0].level == "FAIL", "must FAIL on a migration table missing from the drop list"

    write(schema="DROP TABLE IF EXISTS Beta CASCADE;\nCREATE TABLE Alpha (id int);\n")
    assert checks.check_schema_reload_idempotent(tmp_path)[0].level == "FAIL", "must FAIL on a schema table missing from the drop list"


def test_abuse_controls_check_discriminates(tmp_path):
    TRG = ("CREATE OR REPLACE FUNCTION enforce_agency_quota()\nBEGIN\n"
           "    IF v_cap IS NULL THEN RETURN NEW; END IF;\n"
           "    PERFORM pg_advisory_xact_lock(hashtext('polaris.quota.' || v_kind));\n"
           "    RAISE EXCEPTION 'quota exceeded: agency %', v_agency_id;\n"
           "END$$;\n"
           "CREATE TRIGGER trg_quota_issue BEFORE INSERT ON IdentityToken EXECUTE FUNCTION enforce_agency_quota('issue');\n"
           "CREATE TRIGGER trg_quota_revoke BEFORE UPDATE OF status ON IdentityToken EXECUTE FUNCTION enforce_agency_quota('revoke');\n"
           "CREATE TRIGGER trg_quota_verify BEFORE INSERT ON VerificationEvent EXECUTE FUNCTION enforce_agency_quota('verify');\n")
    APP = ("_PromCounter('polaris_agency_events_total')\n_PromCounter('polaris_quota_refusals_total')\n"
           "_record_agency_event('issue', a)\n_record_agency_event('revoke', a)\n_record_agency_event('verify', a)\n"
           "if _quota_refused(e, 'issue', a):\n    status = 429\n"
           "if _quota_refused(e, 'revoke', a):\n    status = 429\n"
           "if _quota_refused(e, 'verify', a):\n    status = 429\n"
           "_METRICS_VERIFICATIONS.labels(disclosure_level=d).inc()\n")
    RULES = ("- alert: PolarisIssuanceVelocity\n  expr: x offset 1h\n- alert: PolarisRevocationVelocity\n"
             "- alert: PolarisVerificationVelocity\n- alert: PolarisQuotaRefusals\n")
    DRILL = ("promtool test rules polaris-alerts.test.yml\n--login operator --method POST\n"
             "polaris_quota_refusals_total polaris_agency_events_total polaris_verifications_total 429\n")
    CI = ("run: bash scripts/polaris-abuse-drill.sh\nPOLARIS_TEST_REDIS_URL: redis://localhost:6379/0\n"
          '--health-cmd "redis-cli ping"\nPOLARIS_RATE_LIMIT_BACKEND: redis\n')
    good = {
        "polaris_sql/01_schema.sql": "DROP TABLE IF EXISTS AgencyQuota CASCADE;\nCREATE TABLE AgencyQuota (x int);\n",
        "polaris_sql/06_triggers.sql": TRG,
        "polaris_sql/02_indexes.sql": "idx_token_agency_issued\nidx_verification_agency_time\n",
        "polaris_sql/migrations/2026-09-01-002-agency-quota.up.sql":
            "CREATE TABLE IF NOT EXISTS AgencyQuota (x int);\nidx_token_agency_issued idx_verification_agency_time\n" + TRG,
        "polaris_sql/migrations/2026-09-01-002-agency-quota.down.sql": "DROP TABLE IF EXISTS AgencyQuota;\n",
        "polaris_web/app.py": APP,
        "deploy/observability/polaris-alerts.yml": RULES,
        "deploy/observability/polaris-alerts.test.yml": "alert_rule_test:\n  alertname: PolarisQuotaRefusals\n",
        "scripts/polaris-abuse-drill.sh": DRILL,
        ".github/workflows/ci.yml": CI,
        "scripts/polaris_load_gen.py": "--login --form --csrf-from\nclass _NoRedirect: pass\n",
        "polaris_web/requirements.txt": "redis==8.1.0\n",
        "polaris_web/Dockerfile.prod": "RUN pip install -r requirements.txt\n",
        ".github/dependabot.yml": 'ignore:\n  - dependency-name: "postgres"\n',
        "polaris_web/security.py": "retry=Retry(NoBackoff(), 0)\n",
        "polaris_cli/polaris.py": "'quota-set': cmd_quota_set\n",
        "polaris_web/test_app.py": "class AgencyQuotaTests: ...\n",
        "docs/operator/RUNBOOKS.md": "## PolarisQuotaRefusals\n",
        "docs/operator/OPERATIONS.md": "polaris_quota_refusals_total\n",
        "docs/operator/SLOS.md": "polaris_agency_events_total\n",
        "docs/reference/DATA-MODEL.md": "AgencyQuota\n",
        "docs/operator/SECURITY-CONTROLS.md": "AgencyQuota\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_abuse_controls(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    # The lock is gone: the cap races.
    write({"polaris_sql/06_triggers.sql": TRG.replace("    PERFORM pg_advisory_xact_lock(hashtext('polaris.quota.' || v_kind));\n", "")})
    assert checks.check_abuse_controls(tmp_path)[0].level == "FAIL", "must FAIL without the advisory lock"

    # The cheap exit moved after the lock (every uncapped write pays the lock).
    write({"polaris_sql/06_triggers.sql": TRG.replace(
        "    IF v_cap IS NULL THEN RETURN NEW; END IF;\n    PERFORM pg_advisory_xact_lock(hashtext('polaris.quota.' || v_kind));\n",
        "    PERFORM pg_advisory_xact_lock(hashtext('polaris.quota.' || v_kind));\n    IF v_cap IS NULL THEN RETURN NEW; END IF;\n")})
    assert checks.check_abuse_controls(tmp_path)[0].level == "FAIL", "must FAIL when the uncapped path takes the lock"

    # A sanctioned bypass crept in.
    write({"polaris_sql/06_triggers.sql": TRG.replace("BEGIN\n", "BEGIN\n    IF current_setting('polaris.revoke_check_done', true) = '1' THEN RETURN NEW; END IF;\n")})
    assert checks.check_abuse_controls(tmp_path)[0].level == "FAIL", "must FAIL when the quota honours the opt-out GUC"

    # One route stopped answering 429.
    write({"polaris_web/app.py": APP.replace("if _quota_refused(e, 'verify', a):\n    status = 429\n", "if _quota_refused(e, 'verify', a):\n    pass\n")})
    assert checks.check_abuse_controls(tmp_path)[0].level == "FAIL", "must FAIL when a route drops the 429"

    # The velocity baseline includes the burst.
    write({"deploy/observability/polaris-alerts.yml": RULES.replace(" offset 1h", "")})
    assert checks.check_abuse_controls(tmp_path)[0].level == "FAIL", "must FAIL without the offset baseline"

    # CI lost the Redis service.
    write({".github/workflows/ci.yml": CI.replace('--health-cmd "redis-cli ping"\n', "")})
    assert checks.check_abuse_controls(tmp_path)[0].level == "FAIL", "must FAIL without a Redis in CI"

    # The retry contract was dropped.
    write({"polaris_web/security.py": "retry=None\n"})
    assert checks.check_abuse_controls(tmp_path)[0].level == "FAIL", "must FAIL without the one-attempt retry contract"


def test_performance_baseline_check_discriminates(tmp_path):
    BLOCK = ("**Measured v9.191 @ abc1234, 2026-09-01T20:00Z (full run, 60s per stage).** Apple M3, 8 cores, 16 GB, "
             "macOS 26.3; PostgreSQL 16.14; Python 3.12.13; gunicorn x4 sync workers; signing: ML-DSA-65 (liboqs).\n\n"
             "| Stage |\n| Issuance (`POST /uc1/issue`) |\n| Verification |\n| Atlas zoomed bbox, warm |\n"
             "| Atlas zoomed bbox, cold |\n| Atlas whole-world stats, warm |\n")
    DOC = "# baseline\n<!-- baseline:begin -->\n" + BLOCK + "<!-- baseline:end -->\n"
    SCRIPT = ("--smoke --update-doc\n/uc1/issue /verifications/new /api/atlas/clusters /api/atlas/stats\n"
              "gunicorn POLARIS_RATE_LIMIT_WRITE_MAX=10000000\nFLOOR VIOLATIONS\n"
              'check_stage("issue", 2)\ncheck_stage("verify", 5)\nif lat.get("p95_ms", 1e9) > 2000:\n')
    SEC = ("RATE_LIMIT_LOGIN_MAX      = _env_int('POLARIS_RATE_LIMIT_LOGIN_MAX', 10)\n"
           "RATE_LIMIT_WRITE_MAX      = _env_int('POLARIS_RATE_LIMIT_WRITE_MAX', 60)\n"
           "RATE_LIMIT_WRITE_WINDOW   = _env_int('POLARIS_RATE_LIMIT_WRITE_WINDOW', 60)\n")
    good = {
        "docs/reference/PERFORMANCE-BASELINE.md": DOC,
        "scripts/polaris-perf-baseline.sh": SCRIPT,
        "scripts/polaris_load_gen.py": "value.replace('{seq}', str(seq))\n'achieved_rps': 1\n",
        ".github/workflows/ci.yml": "run: bash scripts/polaris-perf-baseline.sh --smoke\nname: perf-baseline-smoke\n",
        "polaris_web/security.py": SEC,
        "docs/reference/README.md": "| PERFORMANCE-BASELINE.md |\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_performance_baseline(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    write({"docs/reference/PERFORMANCE-BASELINE.md": DOC.replace("**Measured v9.191 @ abc1234, 2026-09-01T20:00Z", "**Measured")})
    assert checks.check_performance_baseline(tmp_path)[0].level == "FAIL", "must FAIL without the version/commit/date stamp"

    write({"polaris_web/security.py": SEC.replace("'POLARIS_RATE_LIMIT_WRITE_MAX', 60", "'POLARIS_RATE_LIMIT_WRITE_MAX', 6000")})
    assert checks.check_performance_baseline(tmp_path)[0].level == "FAIL", "must FAIL when the F-03 default moves"

    write({"scripts/polaris-perf-baseline.sh": SCRIPT.replace('check_stage("verify", 5)\n', "")})
    assert checks.check_performance_baseline(tmp_path)[0].level == "FAIL", "must FAIL without the verification floor"

    write({".github/workflows/ci.yml": "run: echo skip\n"})
    assert checks.check_performance_baseline(tmp_path)[0].level == "FAIL", "must FAIL when CI does not re-run the baseline"


def test_dr_drill_scheduled_check_discriminates(tmp_path):
    DRILL = ("RPO_TARGET=300; RTO_TARGET=14400\ndr_marker\ndocker kill -s KILL x\n"
             "pgbackrest --stanza=polaris restore\npg_is_in_recovery\n--record\nrecord_row FAIL\n"
             "tokens_after sv_after\n/api/health\n")
    WF = ('on:\n  schedule:\n    - cron: "17 5 1 * *"\npermissions:\n  contents: write\n'
          "run: bash scripts/polaris-dr-drill.sh --record\ngit add docs/operator/DR-DRILLS.md\ngit push\n")
    CI = "on:\n  push:\n    paths-ignore:\n      - docs/operator/DR-DRILLS.md\njobs:\n  x:\n    run: bash scripts/polaris-dr-drill.sh\n"
    good = {
        "polaris_web/docker-init.sh": "ALTER SYSTEM SET archive_timeout = '60s';\n",
        "scripts/polaris-dr-drill.sh": DRILL,
        "docs/operator/DR-DRILLS.md": "| Date | RPO s | RTO s | Status |\n",
        ".github/workflows/dr-drill.yml": WF,
        ".github/workflows/ci.yml": CI,
        "deploy/linux/polaris-dr-drill.timer": "OnCalendar=*-*-01 05:00:00 UTC\n",
        "deploy/linux/polaris-dr-drill.service": "ExecStart=x\n",
        "deploy/linux/install.sh": "polaris-dr-drill.timer\n",
        "docs/operator/DR.md": "polaris-dr-drill.sh DR-DRILLS.md\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_dr_drill_scheduled(tmp_path)[0].level == "OK", "must PASS on the good fixture"

    write({"polaris_web/docker-init.sh": "ALTER SYSTEM SET archive_mode = on;\n"})
    assert checks.check_dr_drill_scheduled(tmp_path)[0].level == "FAIL", "must FAIL without archive_timeout (unbounded RPO)"

    write({"scripts/polaris-dr-drill.sh": DRILL.replace("docker kill -s KILL x\n", "")})
    assert checks.check_dr_drill_scheduled(tmp_path)[0].level == "FAIL", "must FAIL when the drill no longer kills the primary"

    write({".github/workflows/dr-drill.yml": WF.replace('cron: "17 5 1 * *"', 'cron: "17 5 * * 1"')})
    assert checks.check_dr_drill_scheduled(tmp_path)[0].level == "FAIL", "must FAIL when the schedule is not monthly"

    write({".github/workflows/dr-drill.yml": WF.replace("git push\n", "")})
    assert checks.check_dr_drill_scheduled(tmp_path)[0].level == "FAIL", "must FAIL when the row is not committed"

    write({".github/workflows/ci.yml": "on:\n  push:\njobs:\n  x:\n    run: bash scripts/polaris-dr-drill.sh\n"})
    assert checks.check_dr_drill_scheduled(tmp_path)[0].level == "FAIL", "must FAIL without the ledger path filter"

    write({"deploy/linux/install.sh": "polaris-backup.timer\n"})
    assert checks.check_dr_drill_scheduled(tmp_path)[0].level == "FAIL", "must FAIL when the host timer is not installed"


def test_table_count_check_guards_every_document_and_the_migrated_total(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
    write({
        "polaris_sql/01_schema.sql": "CREATE TABLE A (id SERIAL);\nCREATE TABLE B (id SERIAL);\n",
        "polaris_sql/migrations/2026-01-01-001-x.up.sql": "CREATE TABLE IF NOT EXISTS C (id SERIAL);\n",
        "README.md": "a working reference implementation: 2 schema tables.\n",
        "docs/ARCHITECTURE-OVERVIEW.md": "PostgreSQL 16. 2 tables.\nKey tables (3 total, partial list):\n",
        "docs/reference/DATA-MODEL.md": "The schema is **2 tables** (a migrated deployment holds 3 tables).\n",
        "polaris_sql/README.md": "implements **2 tables**\n",
        "site/index.html": "<p><strong>2</strong> schema tables</p>\n",
    })
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "OK", \
        "schema count and migrated total are both legitimate"

    write({"docs/reference/DATA-MODEL.md": "The schema is **26 tables**.\n"})
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "FAIL", \
        "must FAIL when DATA-MODEL.md drifts (it was unguarded through v9.193)"
    write({"docs/reference/DATA-MODEL.md": "The schema is **2 tables**.\n"})

    write({"site/index.html": "<p><strong>28</strong> schema tables</p>\n"})
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "FAIL", \
        "must FAIL when the demo site strip drifts (HTML tags must not hide the number)"
    write({"site/index.html": "<p><strong>2</strong> schema tables</p>\n"})

    write({"docs/ARCHITECTURE-OVERVIEW.md": "PostgreSQL 16. 2 tables.\nKey tables (28 total, partial list):\n"})
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "FAIL", \
        "must FAIL on the '(N total' phrasing that slipped past the old regex"

    write({"docs/ARCHITECTURE-OVERVIEW.md": "PostgreSQL 16. 2 tables.\n"})
    (tmp_path / "docs/reference/DATA-MODEL.md").unlink()
    assert checks.check_table_count_matches_doc(tmp_path)[0].level == "FAIL", \
        "must FAIL when a required document is missing"


def test_stated_counts_check_measures_the_artifacts(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
    n_checks = len(checks.CHECKS)
    ci = "name: CI\non:\n  push:\njobs:\n  test:\n    runs-on: ubuntu\n  build:\n    runs-on: ubuntu\n"
    app = "@app.route('/a')\ndef a(): pass\n@app.route('/b')\ndef b(): pass\n@app.route('/c')\ndef c(): pass\n"
    procs = "CREATE OR REPLACE FUNCTION uc1() RETURNS void AS $$ $$;\n"
    readme = (f"{n_checks} plain `check_*` functions; Flask, 3 routes; 1 stored procedure.\n"
              "| CI jobs | 2 |\n")
    write({".github/workflows/ci.yml": ci, "polaris_web/app.py": app,
           "polaris_sql/05_procedures.sql": procs, "README.md": readme,
           "site/index.html": f"<b>{n_checks}</b><span>invariant checks</span> <b>2</b><span>CI jobs</span>\n"})
    assert checks.check_stated_counts(tmp_path)[0].level == "OK", "must PASS when every count is measured"

    write({"site/index.html": "<b>7</b><span>CI jobs</span>\n"})
    assert checks.check_stated_counts(tmp_path)[0].level == "FAIL", "must FAIL when the site's CI-job count drifts"
    write({"site/index.html": "<b>2</b><span>CI jobs</span>\n"})

    write({"README.md": readme.replace("3 routes", "72 routes")})
    assert checks.check_stated_counts(tmp_path)[0].level == "FAIL", "must FAIL when the route count drifts"

    write({"README.md": readme.replace(f"{n_checks} plain", "77 plain")})
    assert checks.check_stated_counts(tmp_path)[0].level == "FAIL", "must FAIL when the check count drifts"

    write({"README.md": "no numbers here\n"})
    assert checks.check_stated_counts(tmp_path)[0].level == "FAIL", "must FAIL when the README stops stating the counts"

    # The CI count comes from the jobs: keys, not from job-shaped words elsewhere in the file.
    write({"README.md": readme, ".github/workflows/ci.yml": ci + "  deploy:\n    needs: [test, build]\n"})
    assert checks.check_stated_counts(tmp_path)[0].level == "FAIL", "must FAIL when a CI job is added and no doc follows"


def test_c1c10_objects_check_resolves_names_against_the_code(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
    rows = "\n".join(
        f"| C{i} | text | `06_triggers.sql::reject_audit_modification()` |" for i in range(1, 11))
    mission = "| # | Constraint | Where enforced |\n|---|---|---|\n" + rows + "\n"
    write({
        "MISSION.md": mission,
        "polaris_sql/06_triggers.sql": "CREATE OR REPLACE FUNCTION reject_audit_modification() RETURNS trigger AS $$ $$;\n",
        "polaris_web/security.py": "def apply_security_headers(response):\n    return response\n",
        "docs/operator/PRIVACY.md": "The `apply_security_headers()` hook and the `uq_one` index.\n",
        "polaris_sql/01_schema.sql": "CREATE UNIQUE INDEX uq_one ON t (a);\n",
    })
    assert checks.check_c1c10_objects_resolve(tmp_path)[0].level == "OK", "must PASS when every name resolves"

    write({"MISSION.md": mission.replace("reject_audit_modification", "reject_update_delete", 1)})
    assert checks.check_c1c10_objects_resolve(tmp_path)[0].level == "FAIL", \
        "must FAIL when MISSION.md names an enforcement object that does not exist"
    write({"MISSION.md": mission})

    write({"docs/operator/PRIVACY.md": "The `enforce_zk_typing` trigger rejects writes.\n"})
    assert checks.check_c1c10_objects_resolve(tmp_path)[0].level == "FAIL", \
        "must FAIL when a sibling summary cites a phantom trigger"
    write({"docs/operator/PRIVACY.md": "plain prose\n"})

    write({"MISSION.md": mission.replace("`06_triggers.sql::reject_audit_modification()`", "a trigger", 5)})
    assert checks.check_c1c10_objects_resolve(tmp_path)[0].level == "FAIL", \
        "must FAIL when the table stops naming concrete file::object anchors"


def test_helm_chart_version_check_fails_on_stale_app_version(tmp_path):
    (tmp_path / "polaris_web").mkdir(); (tmp_path / "deploy/helm/polaris").mkdir(parents=True)
    (tmp_path / "polaris_web/__version__.py").write_text('__version__ = "9.194"\n')
    (tmp_path / "deploy/helm/polaris/Chart.yaml").write_text('apiVersion: v2\nname: polaris\nappVersion: "9.194"\n')
    assert checks.check_helm_chart_version_current(tmp_path)[0].level == "OK", "must PASS when the chart tracks the version"
    (tmp_path / "deploy/helm/polaris/Chart.yaml").write_text('apiVersion: v2\nname: polaris\nappVersion: "9.186"\n')
    assert checks.check_helm_chart_version_current(tmp_path)[0].level == "FAIL", "must FAIL when the chart lags the version"


def test_api_routes_documented_check_fails_in_both_directions(tmp_path):
    (tmp_path / "polaris_web").mkdir(); (tmp_path / "docs/reference").mkdir(parents=True)
    app = "@app.route('/api/health')\ndef h(): pass\n@app.route('/api/anchor/<int:token_id>')\ndef a(t): pass\n"
    doc = "## Health\n\n### `GET /api/health`\n\n### `GET /api/anchor/<token_id>`\n"
    (tmp_path / "polaris_web/app.py").write_text(app)
    (tmp_path / "docs/reference/API.md").write_text(doc)
    assert checks.check_api_routes_documented(tmp_path)[0].level == "OK", "converters and parameter names must not matter"

    (tmp_path / "polaris_web/app.py").write_text(app + "@app.route('/api/metrics')\ndef m(): pass\n")
    assert checks.check_api_routes_documented(tmp_path)[0].level == "FAIL", "must FAIL when a route is undocumented"

    (tmp_path / "polaris_web/app.py").write_text(app)
    (tmp_path / "docs/reference/API.md").write_text(doc + "\n### `POST /api/tokens/new`\n")
    assert checks.check_api_routes_documented(tmp_path)[0].level == "FAIL", "must FAIL when the doc names a route that does not exist"


def test_compose_trusts_edge_check_fails_without_trust_proxy(tmp_path):
    (tmp_path / "polaris_web").mkdir()
    caddy = "reverse_proxy app:8000 {\n        header_up X-Forwarded-For {remote_host}\n}\n"
    compose = "services:\n  caddy:\n    image: x\n  app:\n    environment:\n      POLARIS_ENV: production\n      POLARIS_TRUST_PROXY: \"1\"\n  redis:\n    image: y\n"
    (tmp_path / "polaris_web/Caddyfile").write_text(caddy)
    (tmp_path / "polaris_web/docker-compose.prod.yml").write_text(compose)
    assert checks.check_prod_compose_trusts_edge(tmp_path)[0].level == "OK", "must PASS with the edge trusted"
    (tmp_path / "polaris_web/docker-compose.prod.yml").write_text(compose.replace('      POLARIS_TRUST_PROXY: "1"\n', ""))
    assert checks.check_prod_compose_trusts_edge(tmp_path)[0].level == "FAIL", "must FAIL when the app service does not trust the edge"
    (tmp_path / "polaris_web/docker-compose.prod.yml").write_text(compose)
    (tmp_path / "polaris_web/Caddyfile").write_text("reverse_proxy app:8000\n")
    assert checks.check_prod_compose_trusts_edge(tmp_path)[0].level == "FAIL", "must FAIL when the edge does not rewrite X-Forwarded-For"


def test_docs_index_coverage_check_fails_on_an_unlisted_document(tmp_path):
    (tmp_path / "docs/operator").mkdir(parents=True)
    (tmp_path / "docs/README.md").write_text("[A](A.md)\n[operator](operator/README.md)\n")
    (tmp_path / "docs/A.md").write_text("a\n")
    (tmp_path / "docs/operator/README.md").write_text("[INSTALL](INSTALL.md)\n")
    (tmp_path / "docs/operator/INSTALL.md").write_text("i\n")
    assert checks.check_docs_index_coverage(tmp_path)[0].level == "OK", "must PASS when every document is indexed"
    (tmp_path / "docs/operator/DR.md").write_text("d\n")
    assert checks.check_docs_index_coverage(tmp_path)[0].level == "FAIL", "must FAIL when a runbook is not in its directory index"
    (tmp_path / "docs/operator/DR.md").unlink()
    (tmp_path / "docs/reference").mkdir(); (tmp_path / "docs/reference/API.md").write_text("x\n")
    assert checks.check_docs_index_coverage(tmp_path)[0].level == "FAIL", "must FAIL when a sub-directory has no index or is not delegated"


def test_version_check_pins_the_citation_file(tmp_path):
    (tmp_path / "polaris_web").mkdir(); (tmp_path / "deploy/helm/polaris").mkdir(parents=True)
    (tmp_path / "polaris_web/__version__.py").write_text('__version__ = "9.203"\n')
    (tmp_path / "deploy/helm/polaris/Chart.yaml").write_text('apiVersion: v2\nname: polaris\nappVersion: "9.203"\n')
    (tmp_path / "CITATION.cff").write_text('cff-version: 1.2.0\nversion: "9.203"\n')
    assert checks.check_helm_chart_version_current(tmp_path)[0].level == "OK", "must PASS when the citation matches"
    (tmp_path / "CITATION.cff").write_text('cff-version: 1.2.0\nversion: "9.200"\n')
    assert checks.check_helm_chart_version_current(tmp_path)[0].level == "FAIL", "must FAIL when CITATION.cff lags the version"


def test_presentation_surface_check_fails_on_a_missing_file_or_stale_policy(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)
    good = {
        "CODE_OF_CONDUCT.md": "x\n", "CITATION.cff": "version: \"9.205\"\n",
        "SECURITY.md": "Report a vulnerability through GitHub, which creates a private advisory.\n`gh attestation verify`\n*Last updated: 2026-09-03 (v9.205)*\n",
        "CONTRIBUTING.md": "*Last updated: 2026-09-03 (v9.205)*\n",
        ".github/ISSUE_TEMPLATE/config.yml": "blank_issues_enabled: false\ncontact_links:\n  - url: https://github.com/x/y/security/advisories/new\n",
        ".github/PULL_REQUEST_TEMPLATE.md": "## Motivation\n", "scripts/polaris-release-notes.sh": "#!/bin/bash\n",
        "polaris_web/__version__.py": "__version__ = \"9.205\"\n",
        "docs/PRODUCTION-READINESS.md": "**Status (v9.205): not production-ready for real identity data.**\n",
    }
    write(good)
    assert checks.check_presentation_surface(tmp_path)[0].level == "OK", "must PASS on the complete surface"
    # the readiness ledger's own cover drifts from the tree
    write({"docs/PRODUCTION-READINESS.md": "**Status (v9.56): not production-ready.**\n"})
    assert checks.check_presentation_surface(tmp_path)[0].level == "FAIL", "must FAIL when the readiness ledger stamp is stale"
    write({"docs/PRODUCTION-READINESS.md": good["docs/PRODUCTION-READINESS.md"]})
    (tmp_path / "CODE_OF_CONDUCT.md").unlink()
    assert checks.check_presentation_surface(tmp_path)[0].level == "FAIL", "must FAIL when a community file is missing"
    write({"CODE_OF_CONDUCT.md": "x\n", "CONTRIBUTING.md": "*Last updated: 2026-06-03 (v9.56)*\n"})
    assert checks.check_presentation_surface(tmp_path)[0].level == "FAIL", "must FAIL when a policy stamp is stale"
    write({"CONTRIBUTING.md": "*Last updated: 2026-09-03 (v9.205)*\n", ".github/ISSUE_TEMPLATE/config.yml": "blank_issues_enabled: true\n"})
    assert checks.check_presentation_surface(tmp_path)[0].level == "FAIL", "must FAIL when blank issues are allowed"


def test_cli_help_check_fails_when_a_command_is_undocumented(tmp_path):
    (tmp_path / "polaris_cli").mkdir()
    cli = tmp_path / "polaris_cli/polaris.py"
    good = ('#!/usr/bin/env python3\n'
            '"""polaris-id: the CLI.\n\n'
            '    health   Schema statistics\n'
            '    revoke   Revoke a token\n\n"""\n'
            'p.add_argument("--version")\n'
            'EPILOG = "exit codes:\\n  0 ok"\n'
            "HANDLERS = {\n    'health': cmd_health,\n    'revoke': cmd_revoke,\n}\n")
    cli.write_text(good)
    assert checks.check_cli_help_lists_every_command(tmp_path)[0].level == "OK", "must PASS when every command is listed"

    cli.write_text(good.replace("    revoke   Revoke a token\n", ""))
    assert checks.check_cli_help_lists_every_command(tmp_path)[0].level == "FAIL", "must FAIL when a command is missing from the docstring"

    cli.write_text(good.replace("    'revoke': cmd_revoke,\n", ""))
    assert checks.check_cli_help_lists_every_command(tmp_path)[0].level == "FAIL", "must FAIL when the docstring lists a command that does not exist"

    cli.write_text(good.replace('EPILOG = "exit codes:\\n  0 ok"\n', ""))
    assert checks.check_cli_help_lists_every_command(tmp_path)[0].level == "FAIL", "must FAIL when the exit codes are undocumented"


def test_metrics_edge_acl_check_fails_when_an_edge_leaves_metrics_open(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)
    matcher = ("@metrics_from_outside {\n    path /metrics /api/metrics\n"
               "    not remote_ip {$POLARIS_METRICS_ALLOW:private_ranges}\n}\n"
               "respond @metrics_from_outside 404\n")
    helm = matcher.replace("{$POLARIS_METRICS_ALLOW:private_ranges}", '{{ .Values.edge.metricsAllow }}')
    good = {
        "polaris_web/Caddyfile": "site {\n" + matcher + "reverse_proxy app:8000\n}\n",
        "deploy/helm/polaris/templates/configmap-caddy.yaml": "data:\n  Caddyfile: |\n" + helm,
        ".github/workflows/ci.yml": "jobs:\n  caddy-edge:\n    steps:\n      - name: The metrics surfaces are refused from outside the monitoring network\n",
    }
    write(good)
    assert checks.check_metrics_edge_acl(tmp_path)[0].level == "OK", "must PASS when both edges refuse and CI proves it"

    write({"polaris_web/Caddyfile": "site {\nreverse_proxy app:8000\n}\n"})
    assert checks.check_metrics_edge_acl(tmp_path)[0].level == "FAIL", "must FAIL when the compose edge leaves metrics open"

    write({"polaris_web/Caddyfile": good["polaris_web/Caddyfile"],
           "deploy/helm/polaris/templates/configmap-caddy.yaml": "data:\n  Caddyfile: |\n    reverse_proxy app:8000\n"})
    assert checks.check_metrics_edge_acl(tmp_path)[0].level == "FAIL", "must FAIL when the chart leaves metrics open"

    write({"deploy/helm/polaris/templates/configmap-caddy.yaml": good["deploy/helm/polaris/templates/configmap-caddy.yaml"],
           ".github/workflows/ci.yml": "jobs:\n  caddy-edge:\n    steps: []\n"})
    assert checks.check_metrics_edge_acl(tmp_path)[0].level == "FAIL", "must FAIL when CI does not exercise the ACL"


def test_image_builds_are_retried_check_fails_when_a_build_bypasses_the_helper(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)

    helper = ("POLARIS_BUILD_ATTEMPTS\n"
              "version() { sed -n 's/x/y/p' polaris_web/__version__.py; }\n"
              "docker build --build-arg POLARIS_VERSION=$(version) -f \"$1\" -t \"$2\" \"$3\"\n")
    labels = ('ARG POLARIS_VERSION=0.0-unstamped\n'
              'LABEL org.opencontainers.image.version="${POLARIS_VERSION}"\n'
              'LABEL org.opencontainers.image.source="https://github.com/EgorKhaklin/polaris-id"\n')
    good = {
        "scripts/polaris-image-build.sh": helper,
        "polaris_web/Dockerfile.prod": labels + "RUN apt-get -o Acquire::Retries=3 update\n",
        "polaris_web/Dockerfile.caddy": labels + "RUN apk upgrade\n",
        ".github/workflows/ci.yml": (
            "jobs:\n  build:\n    steps:\n"
            "      - run: bash scripts/polaris-image-build.sh --stack prod\n"
            "      - uses: docker/build-push-action@v7\n"
            "        with:\n          build-args: POLARIS_VERSION=1\n"
            "      - name: Build the prod image, second attempt (registry flake)\n"
            "        with:\n          build-args: POLARIS_VERSION=1\n"),
    }
    write(good)
    assert checks.check_image_builds_are_retried(tmp_path)[0].level == "OK", \
        "must PASS when every build goes through the helper and every image is stamped"

    write({".github/workflows/ci.yml": good[".github/workflows/ci.yml"]
           + "      - run: docker build -f polaris_web/Dockerfile.prod -t polaris-app:x .\n"})
    assert checks.check_image_builds_are_retried(tmp_path)[0].level == "FAIL", \
        "must FAIL when a workflow builds an image directly"

    write({".github/workflows/ci.yml": good[".github/workflows/ci.yml"],
           "polaris_web/Dockerfile.prod": 'LABEL org.opencontainers.image.version="8.77"\n'})
    assert checks.check_image_builds_are_retried(tmp_path)[0].level == "FAIL", \
        "must FAIL when an image labels a frozen version literal"

    write({"polaris_web/Dockerfile.prod": labels + "RUN apt-get update\n"})
    assert checks.check_image_builds_are_retried(tmp_path)[0].level == "FAIL", \
        "must FAIL when apt-get runs without a mirror retry"

    write({"polaris_web/Dockerfile.prod": labels + "RUN apt-get -o Acquire::Retries=3 update\n",
           ".github/workflows/ci.yml": good[".github/workflows/ci.yml"].replace(
               "      - name: Build the prod image, second attempt (registry flake)\n"
               "        with:\n          build-args: POLARIS_VERSION=1\n", "")})
    assert checks.check_image_builds_are_retried(tmp_path)[0].level == "FAIL", \
        "must FAIL when the buildx build has no second attempt"

    (tmp_path / "scripts/polaris-image-build.sh").unlink()
    assert checks.check_image_builds_are_retried(tmp_path)[0].level == "FAIL", \
        "must FAIL when the helper is missing"


def test_site_tokens_match_app_check_fails_when_the_palette_forks(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)

    app = ":root {\n  --ink: #dce9f6;\n  --ink-dim: #9db1c7;\n  --gold: #c9a352;\n}\n"
    good = {
        "polaris_web/static/polaris.css": app,
        "site/tokens.css": ":root {\n  --ink: #DCE9F6;\n  --ink-dim: #9db1c7;\n}\n",
        "site/index.html": "<style>\nbody{color:var(--ink)}\n</style>\n",
    }
    write(good)
    assert checks.check_site_tokens_match_app(tmp_path)[0].level == "OK", \
        "must PASS when the site uses the application's names and values"

    write({"site/tokens.css": ":root {\n  --ink: #dce9f6;\n  --dim: #9db1c7;\n}\n"})
    assert checks.check_site_tokens_match_app(tmp_path)[0].level == "FAIL", \
        "must FAIL when the site invents a token name the application does not have"

    write({"site/tokens.css": ":root {\n  --ink: #ffffff;\n}\n"})
    assert checks.check_site_tokens_match_app(tmp_path)[0].level == "FAIL", \
        "must FAIL when a shared token has drifted in value"

    write({"site/tokens.css": good["site/tokens.css"],
           "site/index.html": "<style>\n:root{--ink:#000}\nbody{color:var(--ink)}\n</style>\n"})
    assert checks.check_site_tokens_match_app(tmp_path)[0].level == "FAIL", \
        "must FAIL when the page redeclares the palette inline"

    write({"site/index.html": good["site/index.html"]})
    (tmp_path / "site/tokens.css").unlink()
    assert checks.check_site_tokens_match_app(tmp_path)[0].level == "FAIL", \
        "must FAIL when the token file is missing"


def test_css_animations_resolve_check_fails_on_an_orphaned_animation(tmp_path):
    css = tmp_path / "polaris_web/static"
    css.mkdir(parents=True)
    good = """
@keyframes fade-in { from { opacity: 0 } to { opacity: 1 } }
.panel { opacity: 0; animation: fade-in 0.6s ease-out forwards; }
.spinner { animation-name: fade-in; animation-duration: 2s; }
"""
    (css / "polaris.css").write_text(good)
    assert checks.check_css_animations_resolve(tmp_path)[0].level == "OK", \
        "must PASS when every animation name has a @keyframes"

    (css / "polaris.css").write_text(
        ".panel { opacity: 0; animation: reveal-fade 0.6s ease-out forwards; }\n")
    assert checks.check_css_animations_resolve(tmp_path)[0].level == "FAIL", \
        "must FAIL when an animation names keyframes that were deleted"

    (css / "polaris.css").write_text(
        "@keyframes fade-in { from { opacity: 0 } }\n"
        ".a { animation: fade-in 1s linear infinite alternate both; }\n"
        ".b { animation: none; }\n")
    assert checks.check_css_animations_resolve(tmp_path)[0].level == "OK", \
        "must not mistake timing, direction or fill keywords for an animation name"

    for f in css.glob("*.css"):
        f.unlink()
    assert checks.check_css_animations_resolve(tmp_path)[0].level == "FAIL", \
        "must FAIL when there is no stylesheet to check"


def test_system_map_covers_the_tree_check_fails_both_ways(tmp_path):
    def write(files):
        for rel, body in files.items():
            p = tmp_path / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(body)

    tree = ("```\n"
            "polaris/\n"
            "├── README.md                     the front page\n"
            "├── polaris_web/        the application\n"
            "└── docs/               the documentation\n"
            "```\n")
    jobs = ("- `test`: the product suite.\n"
            "- `docker-image`: the images.\n")
    ci = ("on:\n  push:\n    branches: [main]\n\njobs:\n  test:\n    runs-on: x\n"
          "  docker-image:\n    runs-on: x\n")
    write({"docs/reference/SYSTEM-MAP.md": "# map\n\n" + tree + "\n" + jobs,
           ".github/workflows/ci.yml": ci,
           "README.md": "front page\n",
           "polaris_web/app.py": "app\n",
           "docs/README.md": "docs\n"})
    assert checks.check_system_map_covers_the_tree(tmp_path)[0].level == "OK", \
        "must PASS when the tree and the job list both match"

    write({"polaris_cli/cli.py": "cli\n"})
    assert checks.check_system_map_covers_the_tree(tmp_path)[0].level == "FAIL", \
        "must FAIL when a tracked top-level path is missing from the tree"

    (tmp_path / "polaris_cli/cli.py").unlink()
    (tmp_path / "polaris_cli").rmdir()
    write({"docs/reference/SYSTEM-MAP.md": "# map\n\n" + tree.replace(
        "└── docs/               the documentation", "└── polaris_gone/       a directory that was deleted") + "\n" + jobs})
    assert checks.check_system_map_covers_the_tree(tmp_path)[0].level == "FAIL", \
        "must FAIL when the tree lists a path that does not exist"

    write({"docs/reference/SYSTEM-MAP.md": "# map\n\n" + tree + "\n- `test`: only one job listed.\n"})
    assert checks.check_system_map_covers_the_tree(tmp_path)[0].level == "FAIL", \
        "must FAIL when the CI job list omits a job the workflow defines"

    write({"docs/reference/SYSTEM-MAP.md": "# map\n\n" + tree + "\n" + jobs
           + "- `retired-job`: no longer in the workflow.\n"})
    assert checks.check_system_map_covers_the_tree(tmp_path)[0].level == "FAIL", \
        "must FAIL when the CI job list names a job that no longer exists"


def test_paper_pdf_is_current_check_fails_when_the_source_moves(tmp_path):
    import hashlib
    paper = tmp_path / "docs/paper"
    paper.mkdir(parents=True)
    tex = paper / "report.tex"
    tex.write_text("\\documentclass{article}\n")
    (paper / "report.pdf").write_bytes(b"%PDF-1.4\n")
    digest = hashlib.sha256(tex.read_bytes()).hexdigest()
    (paper / "rendered-from.txt").write_text(f"{digest}  report.tex\n")
    assert checks.check_paper_pdf_is_current(tmp_path)[0].level == "OK", \
        "must PASS when the stamp matches the source"

    tex.write_text("\\documentclass{article}\n% one more line\n")
    assert checks.check_paper_pdf_is_current(tmp_path)[0].level == "FAIL", \
        "must FAIL when the source changed after the PDF was rendered"

    (paper / "rendered-from.txt").unlink()
    assert checks.check_paper_pdf_is_current(tmp_path)[0].level == "FAIL", \
        "must FAIL when there is no stamp at all"

    (paper / "rendered-from.txt").write_text(
        hashlib.sha256(tex.read_bytes()).hexdigest() + "  report.tex\n")
    (paper / "report.pdf").unlink()
    assert checks.check_paper_pdf_is_current(tmp_path)[0].level == "FAIL", \
        "must FAIL when the source ships without its rendered output"


def test_retention_engine_check_fails_when_the_floor_or_the_guard_goes(tmp_path):
    sql = tmp_path / "polaris_sql"
    sql.mkdir(parents=True)
    schema = """
CREATE TABLE RetentionPolicy (
    policy_id      BIGSERIAL PRIMARY KEY,
    retention_days INTEGER NOT NULL,
    CONSTRAINT retention_floor CHECK (retention_days >= 365)
);
"""
    (sql / "01_schema.sql").write_text(schema)
    (sql / "09_grants.sql").write_text("REVOKE UPDATE, DELETE ON RetentionPolicy FROM polaris_app;\n")
    (sql / "06_triggers.sql").write_text(
        "CREATE TRIGGER trg_retention_policy_immutable BEFORE UPDATE OR DELETE ON RetentionPolicy\n"
        "  FOR EACH ROW EXECUTE FUNCTION enforce_retention_policy_immutability();\n")
    (sql / "02_indexes.sql").write_text(
        "CREATE UNIQUE INDEX uq_effective_retention_policy ON RetentionPolicy (table_class);\n")
    good_proc = """
CREATE OR REPLACE FUNCTION retention_days_for(p_c VARCHAR) RETURNS INTEGER
LANGUAGE sql STABLE AS $$ SELECT 365; $$;
CREATE OR REPLACE FUNCTION retention_cutoff(p_c VARCHAR) RETURNS TIMESTAMPTZ
LANGUAGE sql STABLE AS $$ SELECT now(); $$;
CREATE OR REPLACE PROCEDURE uc_archive_purge(p_cutoff TIMESTAMPTZ, p_class_cutoffs TIMESTAMPTZ[])
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF p_cutoff > now() - make_interval(days => retention_days_for('VERIFICATION')) THEN
        RAISE EXCEPTION 'cutoff is inside the retention window';
    END IF;
END;
$$;
"""
    (sql / "05_procedures.sql").write_text(good_proc)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (scripts / "polaris-archive.sh").write_text(
        "# --from-policy resolves a cutoff per class\n"
        'MANIFEST=\'{"cutoff_by_class": {}}\'\n')
    (scripts / "polaris-purge.sh").write_text(
        "# reads cutoff_by_class from MANIFEST.json and passes p_class_cutoffs\n"
        "import hashlib  # component verification\n")
    (scripts / "polaris-retention-drill.sh").write_text("# the chain, end to end\n")
    (scripts / "polaris-rotate-logs.sh").write_text("polaris-archive.sh --from-policy\n")
    (scripts / "polaris-cron-install.sh").write_text(
        "0 2 1 1 *   ${SCRIPTS_DIR}/polaris-rotate-logs.sh --dest ${BACKUP_DEST} --actor-user-id ${ROTATE_ACTOR}\n")
    wf = tmp_path / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("      - run: bash scripts/polaris-retention-drill.sh\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "OK", \
        "must PASS when the floor, the boundary, the trigger and the guard are all present"

    (sql / "01_schema.sql").write_text(
        schema.replace("retention_days >= 365", "retention_days >= 7"))
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the floor is lowered below a year"

    (sql / "01_schema.sql").write_text(
        schema.replace("    CONSTRAINT retention_floor CHECK (retention_days >= 365)\n", ""))
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the floor is removed entirely"

    (sql / "01_schema.sql").write_text(schema)
    (sql / "05_procedures.sql").write_text(
        good_proc.replace("now() - make_interval(days => retention_days_for('VERIFICATION'))",
                          "'2020-01-01'::timestamptz"))
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the purge stops consulting the policy and hardcodes a window"

    (sql / "05_procedures.sql").write_text(
        good_proc.replace("RAISE EXCEPTION 'cutoff is inside the retention window';",
                          "p_cutoff := now() - interval '1825 days';"))
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the purge reads the policy but silently narrows instead of refusing"

    (sql / "05_procedures.sql").write_text(good_proc)
    (sql / "06_triggers.sql").write_text("-- no immutability trigger\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when a retention decision can be edited in place"

    (sql / "06_triggers.sql").write_text(
        "CREATE TRIGGER trg_retention_policy_immutable BEFORE UPDATE OR DELETE ON RetentionPolicy\n"
        "  FOR EACH ROW EXECUTE FUNCTION enforce_retention_policy_immutability();\n")
    (sql / "09_grants.sql").write_text("GRANT SELECT ON SomethingElse TO polaris_app;\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when RetentionPolicy is outside the append-only privilege boundary"

    (sql / "09_grants.sql").write_text("REVOKE UPDATE, DELETE ON RetentionPolicy FROM polaris_app;\n")
    (sql / "02_indexes.sql").write_text("-- no uniqueness on the effective policy\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when two effective policies could disagree for one table class"


def test_retention_engine_check_fails_when_the_per_class_chain_breaks(tmp_path):
    """v9.235: the engine is only half useful if the schedule cannot reach the purge."""
    sql = tmp_path / "polaris_sql"
    sql.mkdir(parents=True)
    (sql / "01_schema.sql").write_text(
        "CREATE TABLE RetentionPolicy (retention_days INTEGER NOT NULL,\n"
        "  CONSTRAINT retention_floor CHECK (retention_days >= 365));\n")
    (sql / "09_grants.sql").write_text("REVOKE UPDATE, DELETE ON RetentionPolicy FROM polaris_app;\n")
    (sql / "06_triggers.sql").write_text(
        "CREATE TRIGGER trg_retention_policy_immutable BEFORE UPDATE OR DELETE ON RetentionPolicy\n"
        "  FOR EACH ROW EXECUTE FUNCTION enforce_retention_policy_immutability();\n")
    (sql / "02_indexes.sql").write_text(
        "CREATE UNIQUE INDEX uq_effective_retention_policy ON RetentionPolicy (table_class);\n")
    (sql / "05_procedures.sql").write_text("""
CREATE OR REPLACE FUNCTION retention_days_for(p_c VARCHAR) RETURNS INTEGER
LANGUAGE sql STABLE AS $$ SELECT 365; $$;
CREATE OR REPLACE FUNCTION retention_cutoff(p_c VARCHAR) RETURNS TIMESTAMPTZ
LANGUAGE sql STABLE AS $$ SELECT now(); $$;
CREATE OR REPLACE PROCEDURE uc_archive_purge(p_cutoff TIMESTAMPTZ, p_class_cutoffs TIMESTAMPTZ[])
LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    IF p_cutoff > retention_cutoff('VERIFICATION') THEN
        RAISE EXCEPTION 'cutoff is inside the retention window';
    END IF;
END;
$$;
""")
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    archive_ok = "# --from-policy\ncutoff_by_class\n"
    purge_ok = "# cutoff_by_class from MANIFEST.json, passes p_class_cutoffs\nimport hashlib\n"
    (scripts / "polaris-archive.sh").write_text(archive_ok)
    (scripts / "polaris-purge.sh").write_text(purge_ok)
    (scripts / "polaris-retention-drill.sh").write_text("# drill\n")
    rotate_ok = "polaris-archive.sh --from-policy\n"
    cron_ok = "0 2 1 1 *   ${SCRIPTS_DIR}/polaris-rotate-logs.sh --dest ${BACKUP_DEST} --actor-user-id ${ROTATE_ACTOR}\n"
    (scripts / "polaris-rotate-logs.sh").write_text(rotate_ok)
    (scripts / "polaris-cron-install.sh").write_text(cron_ok)
    wf = tmp_path / ".github/workflows"
    wf.mkdir(parents=True)
    (wf / "ci.yml").write_text("      - run: bash scripts/polaris-retention-drill.sh\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "OK", \
        "must PASS when the per-class chain is complete"

    (scripts / "polaris-archive.sh").write_text("# one cutoff for everything\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the archive cannot be taken from the retention policy"

    (scripts / "polaris-archive.sh").write_text(archive_ok)
    (scripts / "polaris-purge.sh").write_text("# ignores cutoff_by_class\nimport hashlib\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the purge ignores the manifest's per-class cutoffs"

    (scripts / "polaris-purge.sh").write_text(
        "# cutoff_by_class from MANIFEST.json, passes p_class_cutoffs\n# no hashing\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the purge deletes without verifying the archive against its manifest"

    (scripts / "polaris-purge.sh").write_text(purge_ok)
    (scripts / "polaris-retention-drill.sh").unlink()
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when nothing exercises the chain end to end"

    (scripts / "polaris-retention-drill.sh").write_text("# drill\n")
    (wf / "ci.yml").write_text("      - run: echo nothing\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the drill exists but CI never runs it"

    (wf / "ci.yml").write_text("      - run: bash scripts/polaris-retention-drill.sh\n")
    (scripts / "polaris-rotate-logs.sh").write_text("polaris-archive.sh --cutoff-days=1825\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the yearly cron rotation archives at a fixed cutoff instead of the policy"

    (scripts / "polaris-rotate-logs.sh").write_text(rotate_ok)
    (scripts / "polaris-cron-install.sh").write_text(
        "0 2 1 1 *   ${SCRIPTS_DIR}/polaris-rotate-logs.sh 2>&1 | logger\n")
    assert checks.check_retention_engine(tmp_path)[0].level == "FAIL", \
        "must FAIL when the installed cron line omits the actor the purge requires"


# ===========================================================================
# Athena (v9.266) detection tests — each of the five invariant checks must turn
# red on the violation it exists to catch.
# ===========================================================================

def _athena_write(tmp_path, rel, body):
    f = tmp_path / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(body)
    return f


def test_athena_no_person_check_discriminates(tmp_path):
    # Person-legibility must be structurally impossible: no person table/column,
    # no stable per-person surrogate, and the v9.19 person views gone (ship #0).
    GOOD = ("CREATE OR REPLACE VIEW v_athena_agency AS\n"
            "  SELECT a.agency_id, a.name FROM Agency a;\n"
            "CREATE OR REPLACE FUNCTION athena_x() RETURNS TABLE(n INT)\n"
            "  LANGUAGE sql STABLE AS $b$ SELECT 1 LIMIT 1; $b$;\n")
    _athena_write(tmp_path, "polaris_sql/15_ontology.sql",
                  "CREATE OR REPLACE VIEW v_ontology_token AS SELECT 1;\n")
    _athena_write(tmp_path, "polaris_sql/16_athena.sql", GOOD)
    assert checks.check_athena_no_person(tmp_path)[0].level == "OK", "must PASS person-free"
    # a person-column reference in structural SQL
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("a.agency_id, a.name FROM Agency a",
                               "a.agency_id, t.individual_id FROM Agency a JOIN IdentityToken t ON true"))
    assert checks.check_athena_no_person(tmp_path)[0].level == "FAIL", "must FAIL on individual_id"
    # a stable per-person surrogate column
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD + "CREATE TABLE IF NOT EXISTS athena_x_t (subject_handle VARCHAR(16));\n")
    assert checks.check_athena_no_person(tmp_path)[0].level == "FAIL", "must FAIL on a subject handle"
    # the person-aggregating ontology view is back
    _athena_write(tmp_path, "polaris_sql/16_athena.sql", GOOD)
    _athena_write(tmp_path, "polaris_sql/15_ontology.sql",
                  "CREATE OR REPLACE VIEW v_ontology_individual AS SELECT 1;\n")
    assert checks.check_athena_no_person(tmp_path)[0].level == "FAIL", "must FAIL if the person view returns"


def test_athena_read_only_check_discriminates(tmp_path):
    # Athena cannot act: STABLE, non-mutating, never SECURITY DEFINER.
    GOOD = ("CREATE OR REPLACE FUNCTION athena_x(p INT) RETURNS TABLE(n INT)\n"
            "  LANGUAGE sql STABLE AS $b$ SELECT 1 LIMIT 1; $b$;\n")
    _athena_write(tmp_path, "polaris_sql/16_athena.sql", GOOD)
    assert checks.check_athena_read_only(tmp_path)[0].level == "OK", "must PASS read-only"
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("LANGUAGE sql STABLE AS", "LANGUAGE sql STABLE SECURITY DEFINER AS"))
    assert checks.check_athena_read_only(tmp_path)[0].level == "FAIL", "must FAIL on SECURITY DEFINER"
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("$b$ SELECT 1 LIMIT 1; $b$",
                               "$b$ INSERT INTO t VALUES (1); SELECT 1 LIMIT 1; $b$"))
    assert checks.check_athena_read_only(tmp_path)[0].level == "FAIL", "must FAIL on a write in a function body"
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("LANGUAGE sql STABLE", "LANGUAGE sql VOLATILE"))
    assert checks.check_athena_read_only(tmp_path)[0].level == "FAIL", "must FAIL on a VOLATILE function"


def test_athena_functions_bounded_check_discriminates(tmp_path):
    # Every Athena function bounds its output; an event-touching one needs a window.
    GOOD = ("CREATE OR REPLACE FUNCTION athena_x() RETURNS TABLE(n INT)\n"
            "  LANGUAGE sql STABLE AS $b$ SELECT 1 LIMIT 1; $b$;\n")
    _athena_write(tmp_path, "polaris_sql/16_athena.sql", GOOD)
    assert checks.check_athena_functions_bounded(tmp_path)[0].level == "OK", "must PASS bounded"
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("SELECT 1 LIMIT 1;", "SELECT 1;"))
    assert checks.check_athena_functions_bounded(tmp_path)[0].level == "FAIL", "must FAIL with no LIMIT"
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("$b$ SELECT 1 LIMIT 1; $b$",
                               "$b$ SELECT count(*) FROM VerificationEvent LIMIT 5; $b$"))
    assert checks.check_athena_functions_bounded(tmp_path)[0].level == "FAIL", "must FAIL on an unwindowed event read"


def test_athena_non_sovereign_check_discriminates(tmp_path):
    # Authority edges resolve to real tables; current views filter revoked
    # authority; Athena owns only allow-listed descriptive tables.
    GOOD = ("CREATE OR REPLACE VIEW v_athena_may_issue AS SELECT x FROM AgencyAlgorithmAuth;\n"
            "CREATE OR REPLACE VIEW v_athena_authorizes AS SELECT x FROM AgencyAlgorithmAuth;\n"
            "CREATE OR REPLACE VIEW v_athena_relies_on AS\n"
            "  SELECT x FROM AgencyTrustAttestation ata WHERE ata.revocation_date IS NULL;\n"
            "CREATE OR REPLACE VIEW v_athena_trust_agreement AS\n"
            "  SELECT x FROM AgencyTrustAttestation ata WHERE ata.revocation_date IS NULL;\n"
            "CREATE TABLE IF NOT EXISTS athena_constitutional_rule (rule_code VARCHAR(16));\n")
    _athena_write(tmp_path, "polaris_sql/16_athena.sql", GOOD)
    assert checks.check_athena_non_sovereign(tmp_path)[0].level == "OK", "must PASS non-sovereign"
    # relies_on stops filtering revoked authority
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("CREATE OR REPLACE VIEW v_athena_relies_on AS\n"
                               "  SELECT x FROM AgencyTrustAttestation ata WHERE ata.revocation_date IS NULL;",
                               "CREATE OR REPLACE VIEW v_athena_relies_on AS\n"
                               "  SELECT x FROM AgencyTrustAttestation ata;"))
    assert checks.check_athena_non_sovereign(tmp_path)[0].level == "FAIL", "must FAIL when revoked authority surfaces"
    # an independent authority store appears
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD + "CREATE TABLE athena_agency_grant (agency_id INT, algorithm_id INT);\n")
    assert checks.check_athena_non_sovereign(tmp_path)[0].level == "FAIL", "must FAIL on a rogue authority table"
    # an authority edge is repointed at a curated table (manufactures authority)
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("CREATE OR REPLACE VIEW v_athena_may_issue AS SELECT x FROM AgencyAlgorithmAuth;",
                               "CREATE OR REPLACE VIEW v_athena_may_issue AS SELECT x FROM athena_constitutional_rule;"))
    assert checks.check_athena_non_sovereign(tmp_path)[0].level == "FAIL", "must FAIL when an edge leaves its source table"


def test_athena_rule_enforcement_resolves_check_discriminates(tmp_path):
    # Every rule maps to a mechanism that exists; every rule is enforced.
    _athena_write(tmp_path, "polaris_checks/checks.py",
                  "def check_demo_mechanism(root):\n    return []\n")
    _athena_write(tmp_path, "polaris_sql/06_triggers.sql",
                  "CREATE TRIGGER trg_demo_append_only BEFORE UPDATE ON X\n"
                  "  FOR EACH ROW EXECUTE FUNCTION reject_audit_modification();\n")
    GOOD = ("INSERT INTO athena_constitutional_rule (rule_code, title, statement, kind, source_ref) VALUES\n"
            "  ('C1','Audit','append only','CONSTRAINT','MISSION.md C1')\n"
            "ON CONFLICT (rule_code) DO UPDATE SET title = EXCLUDED.title;\n"
            "INSERT INTO athena_rule_enforcement (rule_code, mechanism_kind, mechanism_name, note) VALUES\n"
            "  ('C1','CHECK_FUNCTION','check_demo_mechanism','note'),\n"
            "  ('C1','TRIGGER','trg_demo_append_only','note')\n"
            "ON CONFLICT (rule_code, mechanism_kind, mechanism_name) DO UPDATE SET note = EXCLUDED.note;\n")
    _athena_write(tmp_path, "polaris_sql/16_athena.sql", GOOD)
    assert checks.check_athena_rule_enforcement_resolves(tmp_path)[0].level == "OK", "must PASS when mechanisms resolve"
    # a rule points at a mechanism that does not exist
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("trg_demo_append_only','note')", "trg_nonexistent','note')"))
    assert checks.check_athena_rule_enforcement_resolves(tmp_path)[0].level == "FAIL", "must FAIL on a dangling mechanism"
    # a declared rule has no enforcement row
    _athena_write(tmp_path, "polaris_sql/16_athena.sql",
                  GOOD.replace("  ('C1','Audit','append only','CONSTRAINT','MISSION.md C1')\n",
                               "  ('C1','Audit','append only','CONSTRAINT','MISSION.md C1'),\n"
                               "  ('C2','ZK','zero knowledge','CONSTRAINT','MISSION.md C2')\n"))
    assert checks.check_athena_rule_enforcement_resolves(tmp_path)[0].level == "FAIL", "must FAIL on an unenforced rule"


def test_athena_console_check_discriminates(tmp_path):
    # The console must be login-gated, person-free, and render CSP-safe.
    APP = (
        "@app.route('/athena')\n@security.login_required\n@replica_reads\n"
        "def athena_console():\n"
        "    rules = query(\"SELECT rule_code FROM athena_constitutional_rule\")\n"
        "    return render_template('athena.html', rules=rules)\n\n"
        "@app.route('/api/athena/authority-chain')\n@security.login_required\n"
        "def api_athena_authority_chain():\n"
        "    return jsonify(steps=query(\"SELECT step FROM athena_authority_chain(%s,%s)\", (1, 1)))\n\n"
        "@app.route('/api/athena/affected-by-algorithm')\n@security.login_required\n"
        "def api_athena_affected_by_algorithm():\n"
        "    return jsonify(impacts=query(\"SELECT impact_kind FROM athena_affected_by_algorithm(%s)\", (1,)))\n\n"
        "@app.route('/api/athena/explain-proof')\n@security.login_required\n"
        "def api_athena_explain_proof():\n"
        "    return jsonify(rows=query(\"SELECT disclosure_level FROM athena_explain_proof(%s)\", (1,)))\n"
    )
    JS = "function el(){ var n = document.createElement('div'); n.textContent = 'x'; return n; }\n"
    TPL = "".join(
        '<button data-athena-tab="%s"></button><section data-athena-panel="%s"></section>\n' % (t, t)
        for t in ("constitution", "authority", "proof", "trust")
    ) + '<script src="/static/athena-console.js"></script>\n'

    def write(app=APP, js=JS, tpl=TPL):
        _athena_write(tmp_path, "polaris_web/app.py", app)
        _athena_write(tmp_path, "polaris_web/static/athena-console.js", js)
        _athena_write(tmp_path, "polaris_web/templates/athena.html", tpl)

    write()
    assert checks.check_athena_console(tmp_path)[0].level == "OK", "must PASS the good console"
    # login gate removed from the page route
    write(app=APP.replace("@app.route('/athena')\n@security.login_required\n", "@app.route('/athena')\n"))
    assert checks.check_athena_console(tmp_path)[0].level == "FAIL", "must FAIL when a route is not login-gated"
    # a person table reaches the console
    write(app=APP.replace("FROM athena_constitutional_rule",
                          "FROM athena_constitutional_rule JOIN Individual USING (individual_id)"))
    assert checks.check_athena_console(tmp_path)[0].level == "FAIL", "must FAIL on a person query"
    # unsafe innerHTML rendering
    write(js="function r(m, s){ m.innerHTML = '<b>' + s + '</b>'; }\n")
    assert checks.check_athena_console(tmp_path)[0].level == "FAIL", "must FAIL on innerHTML rendering"
    # a tab mount is dropped
    write(tpl=TPL.replace('<button data-athena-tab="trust"></button><section data-athena-panel="trust"></section>\n', ""))
    assert checks.check_athena_console(tmp_path)[0].level == "FAIL", "must FAIL when a tab mount is missing"


def test_zk_claim_precise_check_discriminates(tmp_path):
    # The public ZK claim must stay precise: no umbrella tagline, boundary stated.
    GOOD = ("# POLARIS\n\n"
            "**A post-quantum, unlinkable-by-default, compulsion-resistant identity system.**\n\n"
            "The default is unlinkable. Polaris is not a general selective-disclosure or "
            "anonymous-credential system, and does not claim to be.\n")
    (tmp_path / "README.md").write_text(GOOD)
    assert checks.check_zk_claim_precise(tmp_path)[0].level == "OK", "must PASS the precise claim"
    # the umbrella tagline is back
    (tmp_path / "README.md").write_text(
        GOOD.replace("post-quantum, unlinkable-by-default,", "post-quantum, zero-knowledge,"))
    assert checks.check_zk_claim_precise(tmp_path)[0].level == "FAIL", "must FAIL on the umbrella tagline"
    # the boundary disclaimer is gone
    (tmp_path / "README.md").write_text(
        "# POLARIS\n\n**A post-quantum, unlinkable-by-default identity system.**\n\nNo boundary stated.\n")
    assert checks.check_zk_claim_precise(tmp_path)[0].level == "FAIL", "must FAIL without the boundary sentence"


def test_no_scifi_schema_check_discriminates(tmp_path):
    # The deprecated science-fiction scaffold tables must stay out of the live schema.
    (tmp_path / "polaris_sql").mkdir()
    good = "CREATE TABLE IdentityToken (token_id SERIAL PRIMARY KEY);\nCREATE TABLE Agency (agency_id SERIAL);\n"
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(good)
    assert checks.check_no_scifi_schema(tmp_path)[0].level == "OK", "must PASS a clean schema"
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(
        good + "CREATE TABLE GenomicAnchor (anchor_id SERIAL, anchor_hash VARCHAR(128));\n")
    assert checks.check_no_scifi_schema(tmp_path)[0].level == "FAIL", "must FAIL if GenomicAnchor returns"
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(
        good + "CREATE TABLE QuantumObserverBinding (binding_id SERIAL);\n")
    assert checks.check_no_scifi_schema(tmp_path)[0].level == "FAIL", "must FAIL if QuantumObserverBinding returns"
    (tmp_path / "polaris_sql" / "01_schema.sql").write_text(
        good + "-- a wavefunction collapse record and the no-cloning theorem\n")
    assert checks.check_no_scifi_schema(tmp_path)[0].level == "FAIL", "must FAIL on sci-fi vocabulary"


def test_constitution_layered_check_discriminates(tmp_path):
    # MISSION.md's Tier column and Athena's layer must agree, with the expected split.
    tiers = {'C1':'Constitutional','C2':'Constitutional','C3':'Constitutional','C4':'Engineering',
             'C5':'Engineering','C6':'Constitutional','C7':'Engineering','C8':'Engineering',
             'C9':'Engineering','C10':'Constitutional'}
    def mission(t):
        rows = "".join(f"| {c} | desc | {t[c]} | where |\n" for c in
                       ['C1','C2','C3','C4','C5','C6','C7','C8','C9','C10'])
        return "| # | Constraint | Tier | Where enforced |\n|---|---|---|---|\n" + rows
    def athena(t):
        rows = "".join(
            f"  ('{c}','Title','stmt','CONSTRAINT','{t[c].upper()}','MISSION.md {c}'),\n"
            for c in ['C1','C2','C3','C4','C5','C6','C7','C8','C9','C10'])
        return ("INSERT INTO athena_constitutional_rule (rule_code, title, statement, kind, layer, source_ref) VALUES\n"
                + rows +
                "  ('VOCATION','Anti','stmt','VOCATION','VOCATION','MISSION.md Vocation')\nON CONFLICT DO NOTHING;\n")
    def write(mt, at):
        (tmp_path / "MISSION.md").write_text(mission(mt))
        (tmp_path / "polaris_sql").mkdir(exist_ok=True)
        (tmp_path / "polaris_sql" / "16_athena.sql").write_text(athena(at))

    write(tiers, tiers)
    assert checks.check_constitution_layered(tmp_path)[0].level == "OK", "must PASS when both agree"
    # MISSION flips C6 to Engineering, Athena keeps it Constitutional -> disagreement
    m2 = dict(tiers); m2['C6'] = 'Engineering'
    write(m2, tiers)
    assert checks.check_constitution_layered(tmp_path)[0].level == "FAIL", "must FAIL on a MISSION/Athena mismatch"
    # both reclassify C4 to Constitutional (agree, but wrong expected set)
    both = dict(tiers); both['C4'] = 'Constitutional'
    write(both, both)
    assert checks.check_constitution_layered(tmp_path)[0].level == "FAIL", "must FAIL when the constitutional set changes"


def test_verify_witness_sampling_check_discriminates(tmp_path):
    # The two-witness availability clause: sampling, paging, witness-naming, prod floor.
    APP = (
        "def _verify_sample_rate():\n"
        "    rate = 0.02\n"
        "    if _PRODUCTION:\n"
        "        rate = max(rate, 0.005)\n"
        "    return rate\n"
        "def api_token_verify(tok_id):\n"
        "    all_valid = True\n"
        "    sampled = False\n"
        "    if _VERIFY_SAMPLE_RATE > 0:\n"
        "        both_valid = pqc_signing.verify_stored_signature(tv, sig, pk, witnesses='both')\n"
        "        sampled = True\n"
        "        if both_valid != all_valid:\n"
        "            observability.record_witness_disagreement(token_id=tok_id)\n"
        "            _METRICS_VERIFY_DISAGREEMENT.inc()\n"
        "    return jsonify(witnesses=('both' if sampled else 'single'), sampled=sampled)\n")
    OBS = "def record_witness_disagreement(**kw):\n    structured_log('verify.witness_disagreement', **kw)\n"
    ALERTS = ("groups:\n  - name: polaris\n    rules:\n"
              "      - alert: PolarisWitnessDisagreement\n"
              "        expr: increase(polaris_verify_witness_disagreements_total[5m]) > 0\n")
    def write(app=APP, obs=OBS, alerts=ALERTS):
        (tmp_path / "polaris_web").mkdir(exist_ok=True)
        (tmp_path / "polaris_web" / "app.py").write_text(app)
        (tmp_path / "polaris_web" / "observability.py").write_text(obs)
        (tmp_path / "deploy" / "observability").mkdir(parents=True, exist_ok=True)
        (tmp_path / "deploy" / "observability" / "polaris-alerts.yml").write_text(alerts)

    write()
    assert checks.check_verify_witness_sampling(tmp_path)[0].level == "OK", "must PASS the full clause"
    # no second-witness sampling
    write(app=APP.replace("witnesses='both'", "witnesses='single'"))
    assert checks.check_verify_witness_sampling(tmp_path)[0].level == "FAIL", "must FAIL without second-witness sampling"
    # the disagreement no longer pages
    write(app=APP.replace("_METRICS_VERIFY_DISAGREEMENT.inc()", "pass"))
    assert checks.check_verify_witness_sampling(tmp_path)[0].level == "FAIL", "must FAIL when a disagreement does not page"
    # the response no longer names the witness set
    write(app=APP.replace("witnesses=('both' if sampled else 'single'), sampled=sampled", "ok=True"))
    assert checks.check_verify_witness_sampling(tmp_path)[0].level == "FAIL", "must FAIL without witness-set naming"
    # sampling is not mandatory in production
    write(app=APP.replace("    if _PRODUCTION:\n        rate = max(rate, 0.005)\n", ""))
    assert checks.check_verify_witness_sampling(tmp_path)[0].level == "FAIL", "must FAIL when prod sampling is not floored"
    # the alert is gone
    write(alerts="groups: []\n")
    assert checks.check_verify_witness_sampling(tmp_path)[0].level == "FAIL", "must FAIL without the PolarisWitnessDisagreement alert"


def test_public_claims_honest_check_discriminates(tmp_path):
    # The outward surfaces must not overstate what exists now: understate to reality.
    README = ("# POLARIS\n\nA reference implementation on notional data.\n\n"
              "**Relying-party linkability, stated positively.** A full-credential presentation carries a stable "
              "token_value that colluding verifiers can correlate.\n\n"
              "| System | Deployed to a real population | National-scope issuance | PQ |\n"
              "| **Polaris** | **✗** | **✗** | ✓ |\n")
    SITE = ('<title>Polaris: a reference implementation of an identity-token system</title>\n'
            '<meta property="og:title" content="Polaris: a reference implementation of a system">\n')
    def write(readme=README, site=SITE):
        (tmp_path / "README.md").write_text(readme)
        (tmp_path / "site").mkdir(exist_ok=True)
        (tmp_path / "site" / "index.html").write_text(site)
    write()
    assert checks.check_public_claims_honest(tmp_path)[0].level == "OK", "must PASS the honest surfaces"
    # bare title (Polaris presented AS a system, not a reference implementation)
    write(site=SITE.replace("a reference implementation of an identity-token system",
                            "an identity-token system"))
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL on a bare title"
    # the 'national' category leaks back into the shareable title
    write(site=SITE.replace("a reference implementation of an identity-token system",
                            "a reference implementation of a national identity-token system"))
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL if the title calls it 'national'"
    # a bare 'unlinkable' on the shareable surface, without the issuer qualifier
    write(site=SITE.replace("a reference implementation of an identity-token system",
                            "a reference implementation of an unlinkable-by-default identity-token system"))
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL on bare 'unlinkable' without the issuer qualifier"
    # the qualified form passes
    write(site=SITE.replace("a reference implementation of an identity-token system",
                            "a reference implementation of an issuer-unlinkable identity-token system"))
    assert checks.check_public_claims_honest(tmp_path)[0].level == "OK", "must PASS when unlinkability is qualified as issuer-side"
    # an overclaim returns to the README
    write(readme=README + "Polaris consolidates them into one physical token per person.\n")
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL on a retired overclaim"
    # the comparison loses its 'not deployed' column
    write(readme=README.replace("Deployed to a real population", "Some other column"))
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL without the not-deployed column"
    # the comparison awards Polaris a deployment/national-scope tick
    write(readme=README.replace("| **Polaris** | **✗** | **✗** | ✓ |", "| **Polaris** | **✗** | ✓ | ✓ |"))
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL if Polaris is awarded national-scope issuance"
    # the relying-party linkability statement is missing
    write(readme=README.replace("**Relying-party linkability, stated positively.**", "**A different note.**"))
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL without the linkability statement"
    # the two-witness overclaim returns
    write(readme=README + "Two independent witnesses for every cryptographic verdict.\n")
    assert checks.check_public_claims_honest(tmp_path)[0].level == "FAIL", "must FAIL on the two-witness overclaim"


def test_detached_verifier_check_discriminates(tmp_path):
    import json as _json
    # P-E1 (v9.274): the detached verifier must be STANDALONE (no Polaris/DB
    # imports), do real ML-DSA-65 crypto, be fed by a pack route that EXPORTS the
    # signature, backed by published vectors, and RUN in CI. The good fixture has
    # every leg; each perturbation removes exactly one.
    VERIFIER = (
        "import argparse, hashlib, json, os, sys\n"
        "def _digest(t): return hashlib.sha3_256(t.encode('utf-8')).digest()\n"
        "def v(digest, sig, pk):\n"
        "    import oqs\n"
        "    with oqs.Signature('ML-DSA-65') as s: return s.verify(digest, sig, pk)\n"
        "def w(digest, sig, pk):\n"
        "    from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "    mldsa.MLDSA65PublicKey.from_public_bytes(pk).verify(sig, digest)\n"
    )
    APP = (
        "@app.route('/api/tokens/<int:tok_id>/authenticity-pack')\n"
        "def token_authenticity_pack(tok_id):\n"
        "    rows = query('SELECT ts.signature_bytes, ts.signing_public_key_hex FROM TokenSignature ts')\n"
        "    pack = {'signature_hex': sig_hex, 'public_key_hex': pk,\n"
        "            'digest_construction': 'SHA3-256(token_value.encode(\"utf-8\"))'}\n"
        "    return jsonify(pack)\n"
        "\n\n"
        "# next route\n"
    )
    CI = ("jobs:\n  pqc-real:\n    steps:\n"
          "      - run: python scripts/polaris-verify.py --selftest\n"
          "      - run: python scripts/polaris-verify.py --verify-dir vectors\n")

    def vec(name, expect, alg, pk):
        return _json.dumps({"format": "polaris-authenticity-pack/1", "algorithm": alg,
                            "public_key_hex": pk, "signature_hex": "ab", "token_value": "T",
                            "_vector": {"name": name, "expect": expect}})

    good = {
        "scripts/polaris-verify.py": VERIFIER,
        "polaris_web/app.py": APP,
        ".github/workflows/ci.yml": CI,
        "vectors/ml-dsa-65-valid.json": vec("valid", "valid", "ML-DSA-65", "dead"),
        "vectors/ml-dsa-65-tampered.json": vec("tampered", "invalid", "ML-DSA-65", "dead"),
        "vectors/placeholder.json": vec("placeholder", "invalid", "DETERMINISTIC-PLACEHOLDER-SHA3-256", None),
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            if body is None:
                if f.exists(): f.unlink()
            else:
                f.write_text(body)

    write()
    assert checks.check_detached_verifier(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. not standalone — imports a DB driver
    write({"scripts/polaris-verify.py": "import psycopg2\n" + VERIFIER})
    assert checks.check_detached_verifier(tmp_path)[0].level == "FAIL", "must FAIL when the verifier imports psycopg2"
    # 2. drops the independent second witness
    write({"scripts/polaris-verify.py": VERIFIER.replace("MLDSA65PublicKey", "SomethingElse")})
    assert checks.check_detached_verifier(tmp_path)[0].level == "FAIL", "must FAIL without the cryptography second witness"
    # 3. the pack route stops exporting the signature (a decal again) — signature_hex
    #    is unique to the export (signing_public_key_hex would still match public_key_hex)
    write({"polaris_web/app.py": APP.replace("'signature_hex': sig_hex, ", "")})
    assert checks.check_detached_verifier(tmp_path)[0].level == "FAIL", "must FAIL when the pack route omits signature_hex"
    # 4. no tampered vector — cannot prove the verifier FAILS a forgery
    write({"vectors/ml-dsa-65-tampered.json": None})
    assert checks.check_detached_verifier(tmp_path)[0].level == "FAIL", "must FAIL without a tampered vector"
    # 5. CI does not re-verify the published vectors
    write({".github/workflows/ci.yml": CI.replace("--verify-dir vectors", "echo skip")})
    assert checks.check_detached_verifier(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run --verify-dir"


def test_attacks_run_check_discriminates(tmp_path):
    # PE.5 (v9.275): the attack suite must be wired into CI (both suites) AND the
    # runner must be fail-closed — red when an attack SUCCEEDS. The good fixture has
    # a contract-correct minimal runner; each perturbation removes exactly one leg.
    RUNNER = (
        "import argparse, importlib, sys\n"
        "_SUITES = ('crypto','db')\n"
        "def main(argv=None):\n"
        "    ap = argparse.ArgumentParser()\n"
        "    ap.add_argument('--suite', choices=_SUITES+('all',), default='all')\n"
        "    a = ap.parse_args(argv)\n"
        "    suites = _SUITES if a.suite=='all' else (a.suite,)\n"
        "    broken = False; hard = False\n"
        "    for s in suites:\n"
        "        m = importlib.import_module('attack_%s' % s)\n"
        "        ok, _ = m.available()\n"
        "        if not ok:\n"
        "            hard = True; continue\n"
        "        for name, fn in m.ATTACKS:\n"
        "            succeeded, _ = fn()\n"
        "            if succeeded: broken = True\n"
        "    if broken: return 1\n"
        "    if hard: return 3\n"
        "    return 0\n"
        "if __name__ == '__main__':\n"
        "    sys.exit(main())\n"
    )
    CRYPTO = ("def available(): return (True, 'x')\n"
              "def _forge(): return (False, 'held')\n"
              "def _tamper(): return (False, 'held')\n"
              "ATTACKS = [('forge_with_key', _forge), ('tamper_signature', _tamper)]\n")
    DB = ("def available(): return (True, 'x')\n"
          "def _revoked(): return (False, 'held')\n"
          "ATTACKS = [('revoked_token_treated_as_authoritative', _revoked)]\n")
    CI = ("jobs:\n  pqc-real:\n    steps:\n"
          "      - run: python attacks/run_attacks.py --suite crypto\n"
          "  test:\n    steps:\n"
          "      - run: python3 attacks/run_attacks.py --suite db\n")
    good = {
        "attacks/run_attacks.py": RUNNER,
        "attacks/attack_crypto.py": CRYPTO,
        "attacks/attack_db.py": DB,
        ".github/workflows/ci.yml": CI,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            if body is None:
                if f.exists(): f.unlink()
            else:
                f.write_text(body)

    write()
    assert checks.check_attacks_run(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the runner is NOT fail-closed — it never returns 1 on a successful attack
    write({"attacks/run_attacks.py": RUNNER.replace("    if broken: return 1\n", "")})
    assert checks.check_attacks_run(tmp_path)[0].level == "FAIL", "must FAIL when the runner is not red-on-break"
    # 2. CI does not run the db suite
    write({".github/workflows/ci.yml": CI.replace("      - run: python3 attacks/run_attacks.py --suite db\n", "")})
    assert checks.check_attacks_run(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run both suites"
    # 3. the crypto suite is gutted of its forge adversary (every 'forge' removed)
    write({"attacks/attack_crypto.py": CRYPTO.replace("forge", "noop")})
    assert checks.check_attacks_run(tmp_path)[0].level == "FAIL", "must FAIL when a required adversary is gone"
    # 4. an attack module is missing
    write({"attacks/attack_db.py": None})
    assert checks.check_attacks_run(tmp_path)[0].level == "FAIL", "must FAIL when an attack module is missing"


def test_federation_real_check_discriminates(tmp_path):
    # PE.3 (v9.276): federation must be cryptographic — the drill mints distinct
    # roots, decides trust via the detached verifier's anchor (issuer_trusted),
    # tests REJECTION not only acceptance, is fail-closed, and runs in CI; the
    # boundary also lives in attacks/. Each perturbation removes one leg.
    DRILL = (
        "import pqc_signing\n"
        "def _mk(): return pqc_signing.generate_keypair()\n"
        "def main():\n"
        "    a = _mk(); b = _mk()\n"
        "    pack_a = {'public_key_hex': a['public_key_hex']}\n"
        "    expect = [(pack_a, [a['public_key_hex']], True), (pack_a, [b['public_key_hex']], False)]\n"
        "    for pack, anchor_keys, want in expect:\n"
        "        v = verify_pack(pack, anchor_keys=anchor_keys)\n"
        "        if (v.get('issuer_trusted') is True) != want:\n"
        "            print('FAIL'); return 1\n"
        "    return 0\n"
    )
    CI = ("jobs:\n  pqc-real:\n    steps:\n"
          "      - run: python scripts/polaris-federation-drill.py\n")
    CRYPTO = ("def available(): return (True, 'x')\n"
              "def _forge(): return (False, 'held')\n"
              "def _tamper(): return (False, 'held')\n"
              "def _outsider(): return (False, 'federation set rejected the outsider')\n"
              "ATTACKS = [('forge', _forge), ('tamper', _tamper), ('outsider', _outsider)]\n")
    good = {
        "scripts/polaris-federation-drill.py": DRILL,
        ".github/workflows/ci.yml": CI,
        "attacks/attack_crypto.py": CRYPTO,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            if body is None:
                if f.exists(): f.unlink()
            else:
                f.write_text(body)

    write()
    assert checks.check_federation_real(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the drill no longer tests a cross-issuer REJECT (only acceptance)
    write({"scripts/polaris-federation-drill.py": DRILL.replace(", False)", ", True)")})
    assert checks.check_federation_real(tmp_path)[0].level == "FAIL", "must FAIL when no rejection is tested"
    # 2. trust is no longer decided via the detached verifier's anchor
    write({"scripts/polaris-federation-drill.py": DRILL.replace("anchor_keys", "agency_id")})
    assert checks.check_federation_real(tmp_path)[0].level == "FAIL", "must FAIL without the detached issuer anchor"
    # 3. CI does not run the drill
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    steps: []\n"})
    assert checks.check_federation_real(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the drill"
    # 4. the federation adversary is gone from attacks/
    write({"attacks/attack_crypto.py": CRYPTO.replace("federation", "noop")})
    assert checks.check_federation_real(tmp_path)[0].level == "FAIL", "must FAIL without a federation adversary"


def test_key_rotation_drilled_check_discriminates(tmp_path):
    # PE.4 (v9.277): HSM key rotation must be DRILLED in-token — a test mints two
    # distinct in-token keys, proves the old token still verifies after rotation
    # and the new key signs, and CI runs the PKCS#11 drill. Each perturbation
    # removes one leg.
    ROT = (
        "    def test_in_token_rotation_old_token_still_verifies_new_key_signs(self):\n"
        "        new_pk = custody.pkcs11_generate_key(self.module, self.token, self.pin, self.label + '-v2')\n"
        "        self.assertNotEqual(new_pk, self.pk)\n"
        "        sig_old, alg, _ = pqc_signing.signature_with_key_for_token('token-ROT-1')\n"
        "        self.assertTrue(pqc_signing.verify_token_signature('token-ROT-1', sig_old, alg))\n"
        "        self.assertTrue(pqc_signing.verify_token_signature('token-ROT-2', sig_old, alg))\n"
        "        self.assertFalse(pqc_signing.verify_token_signature('token-ROT-1', sig_old, alg))\n"
        "    def _z(self):\n        pass\n"
    )
    TC = "class Pkcs11CustodyTests(unittest.TestCase):\n" + ROT
    DRILL = "#!/usr/bin/env bash\npython3 -m unittest test_custody.Pkcs11CustodyTests -v\n"
    CI = "jobs:\n  custody-pkcs11:\n    steps:\n      - run: bash scripts/polaris-custody-pkcs11-drill.sh\n"
    good = {
        "polaris_web/test_custody.py": TC,
        "scripts/polaris-custody-pkcs11-drill.sh": DRILL,
        ".github/workflows/ci.yml": CI,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_key_rotation_drilled(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the in-token rotation test is gone
    write({"polaris_web/test_custody.py": "class Pkcs11CustodyTests(unittest.TestCase):\n    def _z(self):\n        pass\n"})
    assert checks.check_key_rotation_drilled(tmp_path)[0].level == "FAIL", "must FAIL without the in-token rotation test"
    # 2. it no longer proves retirement (old token fails once the anchor is dropped)
    write({"polaris_web/test_custody.py": TC.replace(
        "        self.assertFalse(pqc_signing.verify_token_signature('token-ROT-1', sig_old, alg))\n", "")})
    assert checks.check_key_rotation_drilled(tmp_path)[0].level == "FAIL", "must FAIL without the retirement assertion"
    # 3. the drill no longer runs the in-token suite
    write({"scripts/polaris-custody-pkcs11-drill.sh": "#!/usr/bin/env bash\necho skip\n"})
    assert checks.check_key_rotation_drilled(tmp_path)[0].level == "FAIL", "must FAIL when the drill does not run Pkcs11CustodyTests"
    # 4. CI does not run the custody drill
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    steps: []\n"})
    assert checks.check_key_rotation_drilled(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the drill"


def test_holder_wallet_check_discriminates(tmp_path):
    # PE.7 (v9.278): the holder wallet must be standalone (no server/DB), offer the
    # four holder commands, derive the epoch leaf with the issuer's recipe, verify
    # offline via the detached verifier, and have its deniability + ZK round-trip
    # exercised by a test the coverage suite runs. Each perturbation removes one leg.
    WALLET = (
        "import argparse, hashlib, json\n"
        "def _seed(tid, tv, ctx):\n"
        "    return hashlib.sha3_256(('%s|%s|%s' % (tid, tv, ctx)).encode()).hexdigest()\n"
        "def use_verifier():\n"
        "    return verify_pack  # offline verification via the detached verifier\n"
        "COMMANDS = ['enroll', 'show', 'verify', 'present', 'prove-membership']\n"
        "# derives the leaf from token_id\n"
    )
    TEST = (
        "def test_present_and_duress_are_indistinguishable(self):\n    pass\n"
        "def test_prove_membership_roundtrips_through_polaris_zk(self):\n"
        "    assert bundle['verified']\n"
    )
    COV = "run scripts unittest test_verify_load test_wallet\n"
    good = {
        "scripts/polaris-wallet.py": WALLET,
        "scripts/test_wallet.py": TEST,
        "scripts/polaris-coverage.sh": COV,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_holder_wallet(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. not holder-side — imports server code
    write({"scripts/polaris-wallet.py": WALLET.replace("import argparse, hashlib, json\n",
                                                       "import argparse, hashlib, json\nimport pqc_signing\n")})
    assert checks.check_holder_wallet(tmp_path)[0].level == "FAIL", "must FAIL when the wallet imports server code"
    # 2. a holder command is missing
    write({"scripts/polaris-wallet.py": WALLET.replace("'prove-membership'", "'noop'")})
    assert checks.check_holder_wallet(tmp_path)[0].level == "FAIL", "must FAIL when a holder command is missing"
    # 3. the deniability property is no longer tested
    write({"scripts/test_wallet.py": TEST.replace("test_present_and_duress_are_indistinguishable", "test_noop")})
    assert checks.check_holder_wallet(tmp_path)[0].level == "FAIL", "must FAIL without the deniability test"
    # 4. the coverage suite does not run the wallet test
    write({"scripts/polaris-coverage.sh": COV.replace("test_wallet", "test_other")})
    assert checks.check_holder_wallet(tmp_path)[0].level == "FAIL", "must FAIL when coverage does not run test_wallet"


def test_dyno_published_check_discriminates(tmp_path):
    # PE.8 (v9.279): the dyno must measure the real primitives (ML-DSA sign/verify
    # single+both, ZK prove/verify at a stated depth) with the box spec and version,
    # keep the measured/not-extrapolated honesty, publish a run in DYNO.md, and be
    # re-measured by CI. Each perturbation removes one leg.
    DYNO = (
        "import platform, os\n"
        "def _version(): return '9.279'\n"
        "def box(): return {'platform': platform.platform(), 'cpu_count': os.cpu_count()}\n"
        "MEASURES = ['sign_per_sec', 'verify_single_per_sec', 'verify_both_per_sec']\n"
        "ZK = ['prove_ms', 'verify_ms', 'tree_depth']\n"
        "DISCLAIMER = 'measured on this box, single core; NOT extrapolated'\n"
    )
    MD = ("# Dyno\n\n- Box: 8 cores, Apple Silicon\n- Version v9.279\n\n"
          "Reproduce: `python3 scripts/polaris-dyno.py`\n\nMeasured, not extrapolated.\n")
    CI = "jobs:\n  pqc-real:\n    steps:\n      - run: python scripts/polaris-dyno.py --ml-dsa-samples 500\n"
    good = {
        "scripts/polaris-dyno.py": DYNO,
        "docs/reference/DYNO.md": MD,
        ".github/workflows/ci.yml": CI,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_dyno_published(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the ZK measurement is gone
    write({"scripts/polaris-dyno.py": DYNO.replace("prove_ms", "noop")})
    assert checks.check_dyno_published(tmp_path)[0].level == "FAIL", "must FAIL without the ZK measurement"
    # 2. the not-extrapolated honesty is gone from the dyno
    write({"scripts/polaris-dyno.py": DYNO.replace("NOT extrapolated", "faster")})
    assert checks.check_dyno_published(tmp_path)[0].level == "FAIL", "must FAIL without the not-extrapolated honesty"
    # 3. DYNO.md loses its box spec
    write({"docs/reference/DYNO.md": MD.replace("cores", "CPUs")})
    assert checks.check_dyno_published(tmp_path)[0].level == "FAIL", "must FAIL when DYNO.md does not name the box"
    # 4. CI does not re-measure
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    steps: []\n"})
    assert checks.check_dyno_published(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the dyno"


def test_real_pqc_default_boot_check_discriminates(tmp_path):
    # PE.1 (v9.280): the default boot is the real motor — production fails closed at
    # boot when real PQC is unavailable, and the placeholder is a NAMED dev profile
    # the canonical paths declare and that warns when unnamed. Each perturbation
    # removes one leg.
    APP = (
        "_pqc_real = pqc_signing.is_enabled()\n"
        "if _PRODUCTION and not _pqc_real:\n"
        "    sys.stderr.write('real ML-DSA-65 signing is not available')\n"
        "    sys.exit(2)\n"
        "if not _pqc_real and os.environ.get('POLARIS_PQC_PROFILE') != 'placeholder':\n"
        "    sys.stderr.write('WARNING: DEVELOPMENT PLACEHOLDER')\n"
        "observability.structured_log('boot.pqc_profile', profile='real')\n"
    )
    CI = "jobs:\n  test:\n    env:\n      POLARIS_PQC_PROFILE: placeholder\n"
    RUNNER = "#!/usr/bin/env bash\nPOLARIS_PQC_PROFILE=placeholder \"$PYVENV\" -m unittest\n"
    TEST = "def test_production_refuses_boot_without_real_pqc(self):\n    pass\n"
    good = {
        "polaris_web/app.py": APP,
        ".github/workflows/ci.yml": CI,
        "scripts/polaris-test.sh": RUNNER,
        "polaris_web/test_app.py": TEST,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_real_pqc_default_boot(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. production no longer fails closed (the sys.exit guard is gone)
    write({"polaris_web/app.py": APP.replace("    sys.exit(2)\n", "")})
    assert checks.check_real_pqc_default_boot(tmp_path)[0].level == "FAIL", "must FAIL without the prod boot guard"
    # 2. the placeholder is no longer a named profile that warns
    write({"polaris_web/app.py": APP.replace("DEVELOPMENT PLACEHOLDER", "quiet")})
    assert checks.check_real_pqc_default_boot(tmp_path)[0].level == "FAIL", "must FAIL without the named-profile warning"
    # 3. the CI test job does not name the placeholder profile
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    env:\n      POLARIS_OTHER: x\n"})
    assert checks.check_real_pqc_default_boot(tmp_path)[0].level == "FAIL", "must FAIL when CI does not name the profile"
    # 4. the production boot refusal is not exercised
    write({"polaris_web/test_app.py": TEST.replace("test_production_refuses_boot_without_real_pqc", "test_noop")})
    assert checks.check_real_pqc_default_boot(tmp_path)[0].level == "FAIL", "must FAIL without the boot-refusal test"


def test_witness_fuzz_check_discriminates(tmp_path):
    # (v9.281) the two witnesses must be differentially fuzzed: the fuzzer verifies
    # each case under liboqs AND cryptography independently and flags a disagreement,
    # registered so the runner (and CI) exercises it. Each perturbation removes a leg.
    CRYPTO = (
        "def attack_witnesses_disagree_under_fuzz():\n"
        "    liboqs_v = pqc_signing.verify(m, s, p)\n"
        "    crypto_v = pqc_signing._verify_second_witness(m, s, p)\n"
        "    if bool(liboqs_v) != bool(crypto_v):\n"
        "        return True, 'WITNESS DISAGREEMENT'\n"
        "    return False, 'agreed'\n"
        "ATTACKS = [('witnesses_disagree_under_fuzz', attack_witnesses_disagree_under_fuzz)]\n"
    )
    CI = "jobs:\n  pqc-real:\n    steps:\n      - run: python attacks/run_attacks.py --suite crypto\n"
    good = {"attacks/attack_crypto.py": CRYPTO, ".github/workflows/ci.yml": CI}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_witness_fuzz(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the second witness is dropped (only one verifier -> no disagreement possible)
    write({"attacks/attack_crypto.py": CRYPTO.replace("_verify_second_witness", "verify")})
    assert checks.check_witness_fuzz(tmp_path)[0].level == "FAIL", "must FAIL without the independent second witness"
    # 2. the disagreement comparison is gone
    write({"attacks/attack_crypto.py": CRYPTO.replace("!=", "==")})
    assert checks.check_witness_fuzz(tmp_path)[0].level == "FAIL", "must FAIL without the disagreement comparison"
    # 3. the fuzzer is unregistered (the runner would never call it)
    write({"attacks/attack_crypto.py": CRYPTO.replace("('witnesses_disagree_under_fuzz'", "('noop'")})
    assert checks.check_witness_fuzz(tmp_path)[0].level == "FAIL", "must FAIL when the fuzzer is not registered"
    # 4. CI does not run the crypto suite
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    steps: []\n"})
    assert checks.check_witness_fuzz(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the crypto suite"


def test_kat_conformance_check_discriminates(tmp_path):
    import json as _json
    # (v9.282) ML-DSA-65 must be checked against an independent authority's known
    # answers (Wycheproof): committed vectors with provenance + BOTH valid and
    # invalid cases, a verifier that checks under both witnesses vs the expected
    # result, and CI wiring. Each perturbation removes one leg.
    def vectors(results, prov=True, with_ctx=True):
        tests = [{"tcId": i, "result": r, "msg": "00", "sig": "00"} for i, r in enumerate(results)]
        if with_ctx:  # a context-string vector (exercises ML-DSA's context domain separation)
            tests.append({"tcId": 9999, "result": "valid", "msg": "00", "sig": "00", "ctx": "436f6e74657874"})
        obj = {"algorithm": "ML-DSA-65", "testGroups": [{"publicKey": "ab", "tests": tests}]}
        if prov:
            obj["provenance"] = {"source": "C2SP/wycheproof testvectors_v1/mldsa_65_verify_test.json",
                                 "commit": "613a2e44cb645a9890e49f8d8798cd59ef38379b", "license": "Apache-2.0"}
        return _json.dumps(obj)
    VERIFIER = (
        "import oqs\n"
        "from cryptography.hazmat.primitives.asymmetric import mldsa\n"
        "def check(pk, msg, sig, ctx, expect):\n"
        "    a = mldsa.MLDSA65PublicKey.from_public_bytes(pk)\n"
        "    if ctx:\n"
        "        oqs.Signature('ML-DSA-65').verify_with_ctx_str(msg, sig, ctx, pk)\n"
        "        a.verify(sig, msg, context=ctx)\n"
        "    return (result == 'valid') == expect\n"
    )
    FETCH = "#!/usr/bin/env python3\n# regenerates the KAT vectors from a pinned Wycheproof commit\n"
    CI = "jobs:\n  pqc-real:\n    steps:\n      - run: python scripts/polaris-kat-verify.py\n"
    good = {
        "vectors/kat/mldsa_65_verify.json": vectors(["valid"] * 10 + ["invalid"] * 15),
        "scripts/polaris-kat-verify.py": VERIFIER,
        "scripts/polaris-fetch-kat.py": FETCH,
        ".github/workflows/ci.yml": CI,
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_kat_conformance(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the vectors lose their provenance (unauditable)
    write({"vectors/kat/mldsa_65_verify.json": vectors(["valid"] * 10 + ["invalid"] * 15, prov=False)})
    assert checks.check_kat_conformance(tmp_path)[0].level == "FAIL", "must FAIL without provenance"
    # 2. the verifier checks only one witness
    write({"scripts/polaris-kat-verify.py": VERIFIER.replace("MLDSA65", "SomethingElse")})
    assert checks.check_kat_conformance(tmp_path)[0].level == "FAIL", "must FAIL without the second witness"
    # 3. no invalid vectors (would not catch a forgery-accepting verifier)
    write({"vectors/kat/mldsa_65_verify.json": vectors(["valid"] * 25)})
    assert checks.check_kat_conformance(tmp_path)[0].level == "FAIL", "must FAIL without invalid vectors"
    # 4. CI does not run the KAT
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    steps: []\n"})
    assert checks.check_kat_conformance(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the KAT"
    # 5. no context-string vectors (the ctx-domain-separation path is untested)
    write({"vectors/kat/mldsa_65_verify.json": vectors(["valid"] * 10 + ["invalid"] * 15, with_ctx=False)})
    assert checks.check_kat_conformance(tmp_path)[0].level == "FAIL", "must FAIL without a context-string vector"
    # 6. the verifier is not context-aware (context vectors verified without their context)
    write({"scripts/polaris-kat-verify.py": VERIFIER.replace("verify_with_ctx_str", "verify")})
    assert checks.check_kat_conformance(tmp_path)[0].level == "FAIL", "must FAIL when the verifier is not context-aware"


def test_controls_as_attacks_check_discriminates(tmp_path):
    # (v9.284/v9.285) NIST 800-53 AC/AU/IA/SC controls must be enforced by RUNNING
    # adversaries against the real system: AC-3 (route access), AU-9 (audit-of-record
    # immutability, safely rolled back), AC-7 (lockout), IA-5/IA-2 (password hashing,
    # forged session), SC-5/SC-23 (rate limit, CSRF). Each perturbation removes a leg.
    CTRL = (
        "def attack_ac3_unauth():\n"
        "    r = client.get('/api/tokens/2/authenticity-pack')\n"
        "    return r.status_code == 200, 'ac3'\n"
        "def attack_au9_delete():\n"
        "    cur.execute('DELETE FROM TokenLifecycleEvent WHERE event_id=%s', (eid,))\n"
        "    conn.rollback()\n"
        "def attack_ac7_lock():\n"
        "    pass  # five failed logins lock the account\n"
        "def attack_ia5_hash():\n"
        "    cur.execute('SELECT password_hash FROM AppUser'); return stored == plaintext, 'ia5'\n"
        "def attack_ia2_session():\n"
        "    client.set_cookie('polaris_session', 'forged'); return client.get('/x').status_code == 200, 'ia2'\n"
        "def attack_sc5_rate():\n"
        "    codes = [client.post('/login').status_code]; return 429 not in codes, 'sc5'\n"
        "def attack_sc23_csrf():\n"
        "    return client.post('/individuals/new').status_code != 403, 'sc23'\n"
        "ATTACKS = [('ac3', attack_ac3_unauth), ('au9', attack_au9_delete), ('ac7', attack_ac7_lock),\n"
        "           ('ia5', attack_ia5_hash), ('ia2', attack_ia2_session), ('sc5', attack_sc5_rate),\n"
        "           ('sc23', attack_sc23_csrf)]\n"
    )
    CI = "jobs:\n  test:\n    steps:\n      - run: python3 attacks/run_attacks.py --suite controls\n"
    good = {"attacks/attack_controls.py": CTRL, ".github/workflows/ci.yml": CI}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_controls_as_attacks(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the AU-9 adversary no longer attacks the real audit-of-record table
    write({"attacks/attack_controls.py": CTRL.replace("TokenLifecycleEvent", "SomeScratchTable")})
    assert checks.check_controls_as_attacks(tmp_path)[0].level == "FAIL", "must FAIL when AU-9 does not attack the audit table"
    # 2. a control adversary is missing (AC-7)
    write({"attacks/attack_controls.py": CTRL.replace("ac7", "noop")})
    assert checks.check_controls_as_attacks(tmp_path)[0].level == "FAIL", "must FAIL when the AC-7 adversary is gone"
    # 3. the audit mutation is not rolled back (would actually mutate the audit table)
    write({"attacks/attack_controls.py": CTRL.replace("    conn.rollback()\n", "")})
    assert checks.check_controls_as_attacks(tmp_path)[0].level == "FAIL", "must FAIL when the mutation is not rolled back"
    # 4. CI does not run the controls suite
    write({".github/workflows/ci.yml": "jobs:\n  test:\n    steps: []\n"})
    assert checks.check_controls_as_attacks(tmp_path)[0].level == "FAIL", "must FAIL when CI does not run the controls suite"
    # 5. the IA adversaries no longer attack the real mechanism (the stored hash)
    write({"attacks/attack_controls.py": CTRL.replace("password_hash", "some_other_col")})
    assert checks.check_controls_as_attacks(tmp_path)[0].level == "FAIL", "must FAIL when IA-5 does not read the real password hash"
    # 6. the SC adversaries no longer check rate limiting (no 429)
    write({"attacks/attack_controls.py": CTRL.replace("429", "200")})
    assert checks.check_controls_as_attacks(tmp_path)[0].level == "FAIL", "must FAIL when SC-5 does not check the rate-limit 429"


def test_inter_authority_protocol_check_discriminates(tmp_path):
    # v9.296 (P3.2): a signed federation manifest, verified offline (standalone), with
    # self-consistency + freshness + per-context key-bound attestation, run in CI. Each
    # perturbation removes one leg.
    good = {'polaris_web/app.py': "@app.route('/api/v1/federation-manifest/<int:agency_id>')\ndef api_v1_federation_manifest(agency_id):\n    _manifest_statement(body)\n    pqc_signing.signature_over_message(stmt)\n    return jsonify(anchors=[], attestations=[])\n", 'scripts/polaris-verify.py': "import json, hashlib\n# polaris-federation-manifest/1\ndef _manifest_canonical(m):\n    return b''\ndef verify_manifest(m, now=None, max_window_seconds=None, trusted_anchors=None):\n    fresh = True  # declared active anchors self-consistency\n    return {'fresh': fresh}\ndef verify_cross_authority(pack, context_id, trusted_manifests, now=None, max_window_seconds=None, trusted_anchors=None):\n    x = ('attested_public_key_hex', context_id)\n    return {'decision': 'accept'}\n", 'scripts/polaris-federation-manifest-drill.py': 'def main():\n    verify_cross_authority(p, 1, [m])\n', '.github/workflows/ci.yml': '      - run: python scripts/polaris-federation-manifest-drill.py\n', 'docs/design/inter-authority-protocol.md': '# inter-authority protocol v1\nthe federation manifest.\n', 'polaris_web/test_app.py': 'class FederationManifestTests:\n    def t(self): pass\n'}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the manifest is not issuer-signed
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("pqc_signing.signature_over_message(stmt)", "pass")})
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "FAIL", "must FAIL if the manifest is not signed"
    # 2. verify_manifest drops the self-consistency (signed by own anchor)
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("declared active anchors", "anything")})
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "FAIL", "must FAIL without self-consistency"
    # 3. verify_cross_authority drops the per-context key binding
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("attested_public_key_hex", "trust_me")})
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "FAIL", "must FAIL without key+context binding"
    # 4. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 5. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"
    # 6. the spec is missing
    (tmp_path / "docs" / "design" / "inter-authority-protocol.md").unlink()
    for rel, body in {k: v for k, v in good.items() if k != "docs/design/inter-authority-protocol.md"}.items():
        f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "FAIL", "must FAIL without the protocol spec"
    write()
    # 7. the endpoint test is gone
    write({"polaris_web/test_app.py": "class Other:\n    pass\n"})
    assert checks.check_inter_authority_protocol(tmp_path)[0].level == "FAIL", "must FAIL without FederationManifestTests"


def test_epoch_revocation_propagation_check_discriminates(tmp_path):
    # v9.298 (P3.2b): a signed epoch checkpoint + revocation feed, verified offline
    # (standalone), with FORK + ROLLBACK detection and fail-closed cross-authority
    # revocation, run in CI and tested. Each perturbation removes one leg.
    good = {
        'polaris_web/app.py': (
            "@app.route('/api/v1/epoch-checkpoint/<int:agency_id>')\n"
            "def api_v1_epoch_checkpoint(agency_id):\n"
            "    _epoch_checkpoint_statement(body)  # over TokenStateEpoch\n"
            "    pqc_signing.signature_over_message(stmt)\n"
            "@app.route('/api/v1/revocation-feed/<int:agency_id>')\n"
            "def api_v1_revocation_feed(agency_id):\n"
            "    _revocation_feed_statement(body)  # over RevocationList\n"
        ),
        'scripts/polaris-verify.py': (
            "import json, hashlib\n"
            "# polaris-epoch-checkpoint/1 polaris-revocation-feed/1\n"
            "def _epoch_checkpoint_canonical(cp): return b''\n"
            "def _revocation_feed_canonical(f): return b''\n"
            "def verify_epoch_checkpoint(cp, now=None, max_window_seconds=None, issuer_key=None): return {}\n"
            "def check_epoch_chain(a, b): return {'fork': False}\n"
            "def verify_revocation_feed(f, now=None, max_window_seconds=None, issuer_key=None): return {}\n"
            "def check_revocation_progression(a, b): return {'rolled_back': False}\n"
            "def is_revoked(f, tv): return False\n"
            "def verify_cross_authority(pack, ctx, tm, revocation_feed=None):\n"
            "    revocation_checked = revocation_feed is not None\n"
            "    return {'decision': 'accept', 'revocation_checked': revocation_checked}\n"
        ),
        'scripts/polaris-epoch-revocation-drill.py': (
            "def main():\n    check_epoch_chain(a, b)\n    verify_cross_authority(p, 1, [m], revocation_feed=f)\n"
        ),
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-epoch-revocation-drill.py\n',
        'polaris_web/test_app.py': 'class EpochRevocationTests:\n    def t(self): pass\n',
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. an endpoint is missing
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("/api/v1/revocation-feed", "/api/v1/nope")})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL without the revocation-feed endpoint"
    # 2. not derived from the append-only tables
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("RevocationList", "SomeMutableCache")})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL if not built over the append-only tables"
    # 3. fork detection is gone
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("'fork'", "'nope'")})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL without fork detection"
    # 4. rollback detection is gone
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("rolled_back", "whatever")})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL without rollback detection"
    # 5. the cross-authority revocation fold-in is gone
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("revocation_checked", "unused")})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL without fail-closed revocation in cross-authority"
    # 6. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 7. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"
    # 8. the endpoint test is gone
    write({"polaris_web/test_app.py": "class Other:\n    pass\n"})
    assert checks.check_epoch_revocation_propagation(tmp_path)[0].level == "FAIL", "must FAIL without EpochRevocationTests"


def test_status_bundle_check_discriminates(tmp_path):
    # v9.308 (P3.2c): an aggregate mirrored status feed. A publisher mirrors many
    # authorities' signed feeds into one short-lived bundle; the publisher is untrusted for
    # correctness (each member feed embedded under the member's own signature, the set
    # committed, an omitted authority fail-closed), verified offline (standalone), pinned by
    # the oracle, run in CI, and tested. Each perturbation removes one leg.
    good = {
        'polaris_web/app.py': (
            "_STATUS_BUNDLE_FORMAT = 'polaris-federation-status-bundle/1'\n"
            "def _revocation_feed_body(ag, now): return {}\n"
            "def _epoch_checkpoint_body(ag, now): return {}\n"
            "def _status_bundle_statement(body): return b''\n"
            "def _bundle_members_root(members): return ''\n"
            "@app.route('/api/v1/federation-status-bundle/<int:agency_id>')\n"
            "def api_v1_federation_status_bundle(agency_id):\n"
            "    _revocation_feed_body(ag, now); _epoch_checkpoint_body(ag, now)\n"
            "    _status_bundle_statement(body); _bundle_members_root(members)\n"
            "    pqc_signing.signature_over_message(stmt)\n"
        ),
        'scripts/polaris-verify.py': (
            "import json, hashlib\n"
            "# polaris-federation-status-bundle/1\n"
            "def _status_bundle_canonical(b): return b''\n"
            "def bundle_members_root(members): return ''\n"
            "def verify_status_bundle(b, now=None, max_window_seconds=None, publisher_key=None):\n"
            "    commitment_ok = True  # members_root recomputed and checked\n"
            "    return {'commitment_ok': commitment_ok, 'members': []}\n"
            "def verify_cross_authority(pack, ctx, tm, revocation_feed=None): return {'decision': 'accept'}\n"
            "def verify_cross_authority_via_bundle(pack, ctx, tm, bundle, **kw):\n"
            "    in_bundle = False  # 'not present in the status bundle' is fail-closed\n"
            "    return verify_cross_authority(pack, ctx, tm, revocation_feed=None)\n"
        ),
        'polaris_web/test_canonical_equivalence.py': "# polaris-federation-status-bundle/1\n",
        'scripts/polaris-federation-status-bundle-drill.py': (
            "def main():\n    verify_cross_authority_via_bundle(p, 1, [m], b)  # aggregator cannot forge\n"
        ),
        'scripts/polaris-federation-instances-drill.py': (
            "def main():\n    b = hub_bundle(members); _status_bundle_canonical(b)\n"
            "    verify_cross_authority_via_bundle(pack, ctx, [m], b)  # hub holds no peer key\n"
        ),
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-federation-status-bundle-drill.py\n',
        'polaris_web/test_app.py': 'class StatusBundleTests:\n    def t(self): pass\n',
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the endpoint is missing
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("/api/v1/federation-status-bundle", "/api/v1/nope")})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL without the bundle endpoint"
    # 2. the bundle is not a view over the per-authority feeds (no member-feed builder)
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("_revocation_feed_body", "_something_else")})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL if it does not mirror each member's own feed"
    # 3. the trust+revocation decision does not delegate to verify_cross_authority
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("verify_cross_authority(", "nope(")})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL without delegation to the member's own feed"
    # 4. an omitted authority is not fail-closed
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("not present in the status bundle", "whatever")})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL without fail-closed omission"
    # 5. the member set is not committed
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("commitment_ok", "unused")})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL without the set commitment"
    # 6. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 7. the bundle is not in the canonical-equivalence oracle
    write({"polaris_web/test_canonical_equivalence.py": "# nothing here\n"})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL if not pinned by the oracle"
    # 8. the drill does not prove the aggregator-cannot-forge property
    write({"scripts/polaris-federation-status-bundle-drill.py": "def main():\n    verify_cross_authority_via_bundle(p, 1, [m], b)\n"})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL without the forge-resistance case"
    # 9. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"
    # 10. the endpoint test is gone
    write({"polaris_web/test_app.py": "class Other:\n    pass\n"})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL without StatusBundleTests"
    # 11. the two-instance drill does not prove correct aggregation (hub holds no peer key)
    write({"scripts/polaris-federation-instances-drill.py": "def main():\n    pass\n"})
    assert checks.check_federation_status_bundle(tmp_path)[0].level == "FAIL", "must FAIL without cross-instance aggregation"


def test_verifier_fuzz_check_discriminates(tmp_path):
    # v9.309: a metamorphic fuzzer holds the detached verifier TOTAL -- every signed type's
    # decision function under a mutation battery, deterministic, run in CI against a
    # standalone verifier. Each perturbation removes one leg.
    good = {
        'scripts/polaris-verifier-fuzz.py': (
            "_SEED = 20260908\n"
            "def main():\n"
            "    verify_manifest(x); verify_epoch_checkpoint(x); verify_revocation_feed(x)\n"
            "    verify_status_assertion(x); verify_sth(x); verify_status_bundle(x)\n"
            "    verify_cross_authority(x); verify_cross_authority_via_bundle(x)\n"
            "    verify_cross_authority_zk(x)\n"
            "    # classes: bitflip, mutate:field, cross-type, adv-object\n"
            "    # asserts a wrongly-ACCEPTED case and any raised exception is a break\n"
        ),
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-verifier-fuzz.py\n',
        'scripts/polaris-verify.py': 'import json, hashlib\n',
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. a decision function is not exercised
    write({"scripts/polaris-verifier-fuzz.py": good["scripts/polaris-verifier-fuzz.py"].replace("verify_status_bundle", "nope")})
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "FAIL", "must FAIL if a verify fn is not fuzzed"
    # 2. a mutation class is missing
    write({"scripts/polaris-verifier-fuzz.py": good["scripts/polaris-verifier-fuzz.py"].replace("cross-type", "xxx")})
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "FAIL", "must FAIL without cross-type confusion"
    # 3. it does not assert the crash failure mode
    write({"scripts/polaris-verifier-fuzz.py": good["scripts/polaris-verifier-fuzz.py"].replace("raised", "swallowed")})
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "FAIL", "must FAIL if a crash is not a break"
    # 4. it is not deterministic
    write({"scripts/polaris-verifier-fuzz.py": good["scripts/polaris-verifier-fuzz.py"].replace("_SEED", "_NOPE")})
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "FAIL", "must FAIL without a fixed seed"
    # 5. it does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "FAIL", "must FAIL if the fuzzer does not run in CI"
    # 6. the fuzzed verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n"})
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 7. the fuzzer is missing entirely
    (tmp_path / "scripts/polaris-verifier-fuzz.py").unlink()
    assert checks.check_verifier_fuzz(tmp_path)[0].level == "FAIL", "must FAIL without the fuzzer"


def test_cross_authority_zk_check_discriminates(tmp_path):
    # v9.312 (P3.2d): a holder's ZK inclusion proof decided against a FOREIGN authority's epoch
    # offline -- trust the signed checkpoint in-context, bind the proof to its root, verify via
    # the local polaris-zk binary (abstain when absent), standalone, with a CLI, a committed
    # fixture, a drill, and CI. Each perturbation removes one leg.
    good = {
        'scripts/polaris-verify.py': (
            "import json, hashlib, subprocess\n"
            "# the polaris-zk binary is invoked as a subprocess; --zk-proof CLI mode\n"
            "def _zk_verify_proof(b, zk_binary=None): return None  # abstain when no binary\n"
            "def verify_zk_against_root(b, r, e, c):\n"
            "    pi = b.get('public_inputs'); pi.get('epoch_root_hex')  # bind to the trusted root\n"
            "def verify_epoch_checkpoint(cp): return {}\n"
            "def verify_manifest(m): return {}\n"
            "def verify_cross_authority_zk(p, cp, ctx, tm):\n"
            "    verify_epoch_checkpoint(cp); verify_manifest(tm[0])  # attested_public_key_hex, in-context\n"
            "    return {'decision': 'abstain'}\n"
        ),
        'scripts/polaris-cross-authority-zk-drill.py': (
            "def main():\n    verify_cross_authority_zk(p, cp, 1, [m])  # accept/reject/abstain matrix\n"
        ),
        'polaris_zk/fixtures/cross-authority-zk.json': '{"proof": {}}\n',
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-cross-authority-zk-drill.py\n',
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the decision function is missing
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("def verify_cross_authority_zk", "def nope")})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL without the decision function"
    # 2. trust is not rooted in the signed checkpoint
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("verify_epoch_checkpoint(cp)", "pass")})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL without checkpoint trust"
    # 3. the proof is not bound to the epoch root
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("epoch_root_hex", "nope_hex")})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL without root binding"
    # 4. the proof is not checked via the local binary
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("subprocess", "notproc")})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL without the binary subprocess"
    # 5. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 6. no CLI mode
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("--zk-proof", "--nope")})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL without the --zk-proof CLI"
    # 7. the drill does not prove the abstain case
    write({"scripts/polaris-cross-authority-zk-drill.py": "def main():\n    verify_cross_authority_zk(p, cp, 1, [m])\n"})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL without the abstain case"
    # 8. the committed fixture is missing
    (tmp_path / "polaris_zk/fixtures/cross-authority-zk.json").unlink()
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL without the fixture"
    # 9. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_cross_authority_zk(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"


def test_wire_spec_check_discriminates(tmp_path):
    # v9.313 (P8.1): a normative wire spec pinned to the signer -- every protocol format string
    # and every signed-field list in the doc must match the code's canonical builders. Each
    # perturbation removes one leg.
    verify_src = (
        "import json\n"
        "def _manifest_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'authority')}\n"
        "def _epoch_checkpoint_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'epoch')}\n"
        "def _revocation_feed_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'as_of')}\n"
        "def _status_assertion_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'status')}\n"
        "def _sth_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'tree_size')}\n"
        "def _status_bundle_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'publisher')}\n"
        "def _exchange_receipt_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'requester')}\n"
        "def _exchange_mint_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'responder_agency_id')}\n"
        "def _timestamp_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'digest_hex')}\n"
        "def _registry_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'publisher')}\n"
        "def _exchange_request_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'nonce')}\n"
        "def _signed_document_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'document')}\n"
        "def _id_token_canonical(m):\n    x = {k: m.get(k) for k in ('format', 'aud')}\n"
    )
    spec = (
        "# Polaris wire spec\nA verifier MUST check the signature.\n"
        "Artifacts: polaris-federation-manifest/1 polaris-epoch-checkpoint/1 polaris-revocation-feed/1 "
        "polaris-status-assertion/1 polaris-transparency-sth/1 polaris-federation-status-bundle/1 "
        "polaris-authenticity-pack/1 polaris-transparency-cosignature/1 polaris-transparency-publication/1 "
        "polaris-published-head/1 polaris-exchange-receipt/1 polaris-exchange-mint/1 polaris-timestamp/1 polaris-registry/1 polaris-exchange-request/1 polaris-signed-document/1 polaris-id-token/1\n"
        "manifest signed fields: format, authority\n"
        "receipt signed fields: format, requester\n"
        "mint signed fields: format, responder_agency_id\n"
        "timestamp signed fields: format, digest_hex\n"
        "registry signed fields: format, publisher\n"
        "envelope signed fields: format, nonce\n"
        "container signed fields: format, document\n"
        "id token signed fields: format, aud\n"
        "checkpoint signed fields: format, epoch\n"
        "feed signed fields: format, as_of\n"
        "assertion signed fields: format, status\n"
        "sth signed fields: format, tree_size\n"
        "bundle signed fields: format, publisher\n"
        "The pack signs SHA3-256(token_value), not a JSON statement.\n"
        "canonical = json.dumps(s, sort_keys=True, separators=(',',':')).\n"
        "Trust is non-transitive and in-context.\n"
    )
    good = {
        'docs/reference/WIRE-SPEC.md': spec,
        'scripts/polaris-verify.py': verify_src,
        'docs/reference/README.md': "[WIRE-SPEC.md](WIRE-SPEC.md)\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the spec is missing
    (tmp_path / "docs/reference/WIRE-SPEC.md").unlink()
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL without the spec"
    write()
    # 2. no normative language
    write({"docs/reference/WIRE-SPEC.md": spec.replace("MUST", "should maybe")})
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL without RFC-2119 MUST"
    # 3. a format string is not covered
    write({"docs/reference/WIRE-SPEC.md": spec.replace("polaris-published-head/1", "nope/1")})
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL if an artifact is uncovered"
    # 4. a signed-field list diverges from the code
    write({"docs/reference/WIRE-SPEC.md": spec.replace("format, publisher", "format, WRONG")})
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL if a field list diverges from code"
    # 5. the pack construction is undocumented
    write({"docs/reference/WIRE-SPEC.md": spec.replace("SHA3-256(token_value)", "something")})
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL without the pack construction"
    # 6. the canonical discipline is undocumented
    write({"docs/reference/WIRE-SPEC.md": spec.replace("sort_keys", "nope")})
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL without the canonical construction"
    # 7. the trust decision is not stated non-transitive/in-context
    write({"docs/reference/WIRE-SPEC.md": spec.replace("non-transitive and in-context", "loose")})
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL without non-transitive/in-context trust"
    # 8. not linked from the reference index
    write({"docs/reference/README.md": "no link here\n"})
    assert checks.check_wire_spec_matches_code(tmp_path)[0].level == "FAIL", "must FAIL if not linked from the index"


def test_auth_broker_check_discriminates(tmp_path):
    # v9.326 (P8.4): the auth broker's protocol core with the vocation's guards; each
    # perturbation removes one leg.
    APP = (
        "@app.route('/api/v1/auth/authorize', methods=['POST'])\n"
        "def api_v1_auth_authorize():\n"
        "    rp_auth.SCOPE_AUTHENTICATE; row = _possession_authenticated(token_value, presented)\n"
        "    _check_and_record_duress(row['token_id'], c, a, code); _zk_verify_and_consume(1, 2, 3, b)\n"
        "    code = {'sub': hashlib.sha3_256(token_value.encode()).hexdigest()}\n"
        "@app.route('/api/v1/auth/token', methods=['POST'])\n"
        "def api_v1_auth_token():\n"
        "    _pkce_challenge(verifier); query('INSERT INTO AuthCodeConsumed (code_hash) VALUES (%s)')\n"
        "    _id_token_statement(tok)  # polaris-id-token/1\n"
    )
    good = {
        'polaris_web/app.py': APP,
        'polaris_sql/01_schema.sql': "CREATE TABLE AuthCodeConsumed (\n    code_hash CHAR(64) PRIMARY KEY,\n    consumed_at TIMESTAMP\n);\n",
        'polaris_sql/06_triggers.sql': "CREATE TRIGGER trg_auth_code_append_only BEFORE UPDATE OR DELETE ON AuthCodeConsumed EXECUTE FUNCTION f();\n",
        'polaris_sql/09_grants.sql': "'authcodeconsumed'\n",
        'polaris_web/rp_auth.py': "_CODE_SALT = 'x'\ndef issue_auth_code(k, p): pass\ndef validate_auth_code(k, c, max_age=60): pass\n",
        'scripts/polaris-verify.py': "import json\ndef _id_token_canonical(t): return b''\ndef verify_id_token(t, **k): return {}\n",
        'sdk/python/polaris_verify/__init__.py': "def verify_id_token(tok, audience=None, nonce=None, now=None): pass\n",
        'sdk/typescript/src/index.ts': "export function verifyIdToken(tok: any) {}\n",
        'polaris_web/test_canonical_equivalence.py': "flask_app._id_token_statement\n",
        'docs/reference/WIRE-SPEC.md': "polaris-id-token/1\n",
        'conformance/cases.json': '{"cases": [{"artifact": "id-token"}]}\n',
        'scripts/polaris-verifier-fuzz.py': "V.verify_id_token(o)\n",
        'attacks/attack_controls.py': "anon.post('/api/v1/auth/token', headers=bearer)\n",
        'scripts/polaris-auth-broker-drill.py': "V.verify_id_token(tok)\n",
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-auth-broker-drill.py\n',
        'scripts/polaris-federation-instances-drill.py': "'/api/v1/auth/authorize'; '/api/v1/auth/token'; 'code_verifier'; 'invalid_grant'\n",
        'polaris_web/test_app.py': "class AuthBrokerTests(PolarisTestCase):\n    def t(self): DuressEvent\n",
        'scripts/polaris-wallet.py': "def cmd_login(args): pass\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_auth_broker(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    write({'polaris_web/app.py': APP.replace("'sub': hashlib.sha3_256(token_value", "'sub': token_value")})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if the subject is the token rather than its hash"
    write({'polaris_web/app.py': APP.replace("def api_v1_auth_authorize():\n", "def api_v1_auth_authorize():\n    query('INSERT INTO LoginLog (sub, rp) VALUES (1, 2)')\n")})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if the authorize route records a login"
    write({'polaris_sql/01_schema.sql': "CREATE TABLE AuthCodeConsumed (\n    code_hash CHAR(64) PRIMARY KEY,\n    client_id TEXT,\n    sub TEXT\n);\n"})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if the consumed-code register links a subject or relying party"
    write({'polaris_web/app.py': APP.replace("_pkce_challenge(verifier)", "True")})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL without PKCE"
    write({'polaris_web/app.py': APP.replace("_check_and_record_duress(row['token_id']", "pass; x(")})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if duress is not served through the broker"
    write({'attacks/attack_controls.py': "# no probe\n"})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if the AC-6 adversary does not probe the broker"
    write({'sdk/typescript/src/index.ts': "// nothing\n"})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if the TS SDK cannot verify the ID token"
    write({'scripts/polaris-federation-instances-drill.py': "# no flow\n"})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if the flow is not proven over HTTP"
    write({'scripts/polaris-wallet.py': "# no login\n"})
    assert checks.check_auth_broker(tmp_path)[0].level == "FAIL", "must FAIL if the wallet cannot drive authorize"


def test_document_signing_check_discriminates(tmp_path):
    # v9.325 (P8.5): document signing with long-term validation; each perturbation removes one leg.
    APP = (
        "@app.route('/api/v1/sign/<int:agency_id>', methods=['POST'])\n"
        "@app.route('/api/v1/sign/<int:agency_id>/holder', methods=['POST'])\n"
        "def api_v1_sign_holder(agency_id):\n"
        "    _signed_document_statement(doc)  # polaris-signed-document/1 ; the document itself is never sent\n"
        "    row = _possession_authenticated(token_value, presented)\n"
        "    if row['status'] != 'ACTIVE': return 403\n"
        "    on_behalf_of = {'credential_hash': hashlib.sha3_256(token_value.encode()).hexdigest()}\n"
        "    doc['ltv'] = {'timestamp': _timestamp_body(a, i, sha3(_document_signature_material(doc)), None),\n"
        "                  'manifest': _federation_manifest_body(agency, now), 'revocation_feed': _revocation_feed_body(agency, now)}\n"
    )
    VER = ("import json\ndef _signed_document_canonical(d): return b''\ndef document_signature_material(d): return b''\n"
           "def attach_ltv(d, **k): return d\ndef is_revoked_leaf(f, l): return False\n"
           "def verify_signed_document(d, **k): return {'valid_long_term': False, 'ltv': {'signer_key_active_at_instant': None, 'credential_unrevoked_at_instant': None}}\n")
    good = {
        'polaris_web/app.py': APP,
        'scripts/polaris-verify.py': VER,
        'scripts/polaris-wallet.py': "def cmd_sign(args): pass\n",
        'polaris_web/test_canonical_equivalence.py': "flask_app._signed_document_statement\n",
        'docs/reference/WIRE-SPEC.md': "polaris-signed-document/1\n",
        'conformance/cases.json': '{"cases": [{"artifact": "signed-document"}]}\n',
        'sdk/python/polaris_verify/__init__.py': '"polaris-signed-document/1": ["format"]\n',
        'sdk/typescript/src/index.ts': '"polaris-signed-document/1": ["format"]\n',
        'scripts/polaris-verifier-fuzz.py': "V.verify_signed_document(o)\n",
        'scripts/polaris-document-signing-drill.py': "# KEY RETIREMENT\nV.attach_ltv(doc)\n",
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-document-signing-drill.py\n',
        'scripts/polaris-federation-instances-drill.py': "base_b + '/api/v1/sign/1/holder'; 'polaris-wallet.py'\n",
        'polaris_web/test_app.py': "class DocumentSigningTests(PolarisTestCase): pass\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_document_signing(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    write({'polaris_web/app.py': APP.replace("/api/v1/sign/<int:agency_id>/holder", "/api/v1/nope")})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL without the holder route"
    write({'polaris_web/app.py': APP.replace("'credential_hash': hashlib.sha3_256(token_value", "'token_value': token_value")})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL if the holder is recorded by token, not hash"
    write({'polaris_web/app.py': APP.replace("row['status'] != 'ACTIVE'", "True")})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL if an inactive credential could sign"
    write({'polaris_web/app.py': APP.replace("_document_signature_material", "_signed_document_statement")})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL if the timestamp does not bind the signature"
    write({'scripts/polaris-verify.py': VER.replace("valid_long_term", "valid")})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL without long-term validity in the verifier"
    write({'scripts/polaris-wallet.py': "# no sign\n"})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL if the wallet cannot sign"
    write({'scripts/polaris-document-signing-drill.py': "V.attach_ltv(doc)\n"})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL if key retirement is not drilled"
    write({'sdk/typescript/src/index.ts': "// nothing\n"})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL if the TS SDK cannot verify it"
    write({'scripts/polaris-federation-instances-drill.py': "# no signing\n"})
    assert checks.check_document_signing(tmp_path)[0].level == "FAIL", "must FAIL if not proven over HTTP"


def test_exchange_gateway_check_discriminates(tmp_path):
    # v9.324 (P8.2d): the gateway's order of operations IS the security argument; each
    # perturbation removes one leg.
    APP = (
        "@app.route('/api/v1/exchange/<int:target_agency_id>', methods=['POST'])\n"
        "def api_v1_exchange(target_agency_id):\n"
        "    # polaris-exchange-request/1 ; placeholder signature is not authentication\n"
        "    # the requester key is not a registered authority on this instance\n"
        "    ok = pqc_signing.verify_both(_exchange_request_statement(env), sig, key)\n"
        "    if not _exchange_attestation(req_key, context_id):\n        return jsonify(error='forbidden'), 403\n"
        "    _consume_exchange_nonce(k, n)  # INSERT INTO ExchangeNonce\n"
        "    up = _exchange_upstreams()[kind]  # POLARIS_EXCHANGE_UPSTREAMS; A URL never comes from a request\n"
        "    urllib.request.urlopen(up)\n"
        "    _build_exchange_receipt(target, target_agency_id, f, occurred_at=str(env.get('issued_at')))\n"
        "_REGISTRY_SERVICES = [{'kind': 'exchange'}]\n'exchange_kinds'\n"
    )
    good = {
        'polaris_web/app.py': APP,
        'polaris_sql/01_schema.sql': "CREATE TABLE ExchangeNonce (nonce VARCHAR(64));\n",
        'polaris_sql/06_triggers.sql': "CREATE TRIGGER trg_exchange_nonce_append_only BEFORE UPDATE OR DELETE ON ExchangeNonce EXECUTE FUNCTION f();\n",
        'polaris_sql/09_grants.sql': "'exchangenonce'\n",
        'scripts/polaris-verify.py': ("import json\ndef _exchange_request_canonical(e): return b''\ndef canonical_body_hash(o): return ''\n"
                                      "def verify_exchange_request(e, **k): return {}\ndef exchange_evidence(e, r): return True\n"),
        'polaris_web/test_canonical_equivalence.py': "flask_app._exchange_request_statement\n",
        'docs/reference/WIRE-SPEC.md': "polaris-exchange-request/1\n",
        'conformance/cases.json': '{"cases": [{"artifact": "exchange-request"}]}\n',
        'sdk/python/polaris_verify/__init__.py': '"polaris-exchange-request/1": ["format"]\n',
        'sdk/typescript/src/index.ts': '"polaris-exchange-request/1": ["format"]\n',
        'scripts/polaris-verifier-fuzz.py': "V.verify_exchange_request(o)\n",
        'scripts/polaris-federation-instances-drill.py': "base_b + '/api/v1/exchange/1'; V.exchange_evidence(env, rcpt); 'POLARIS_EXCHANGE_UPSTREAMS'; 409\n",
        'polaris_web/test_app.py': "class ExchangeGatewayTests(PolarisTestCase): pass\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_exchange_gateway(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    write({'polaris_web/app.py': APP.replace("/api/v1/exchange/", "/api/v1/nope/")})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL without the gateway route"
    # forward BEFORE authorize -> FAIL (swap the two lines)
    swapped = APP.replace("    if not _exchange_attestation(req_key, context_id):\n        return jsonify(error='forbidden'), 403\n", "").replace(
        "    urllib.request.urlopen(up)\n", "    urllib.request.urlopen(up)\n    if not _exchange_attestation(req_key, context_id):\n        return jsonify(error='forbidden'), 403\n")
    write({'polaris_web/app.py': swapped})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL if the upstream is called before authorization"
    write({'polaris_web/app.py': APP.replace("A URL never comes from a request", "url = payload['url']")})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL if a forwarding URL could come from the request"
    write({'polaris_web/app.py': APP + "    query('INSERT INTO ExchangeLog (body) VALUES (%s)', (body,))\n"})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL if a body is persisted"
    write({'polaris_web/app.py': APP.replace("occurred_at=str(env.get('issued_at'))", "occurred_at=None")})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL if the receipt does not carry the signed time"
    write({'polaris_sql/06_triggers.sql': "-- no trigger\n"})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL if the replay register is not append-only"
    write({'scripts/polaris-verify.py': good['scripts/polaris-verify.py'].replace("def exchange_evidence", "def nope")})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL without the offline evidence chain"
    write({'scripts/polaris-federation-instances-drill.py': "# no exchange\n"})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL if not driven across two instances"
    write({'polaris_web/test_app.py': "# nothing\n"})
    assert checks.check_exchange_gateway(tmp_path)[0].level == "FAIL", "must FAIL without the fail-closed test"


def test_registry_check_discriminates(tmp_path):
    # v9.323 (P8.3): the signed registry -- route over Athena views, formats pinned to the spec,
    # offline verify with self-consistency + discovery helpers, oracle/spec/conformance (both
    # SDKs)/fuzzer, drilled in CI, discovery-driven across two instances.
    APP = (
        "@app.route('/api/v1/registry/<int:agency_id>')\n"
        "def api_v1_registry(agency_id):\n"
        "    _registry_statement(body)  # polaris-registry/1\n"
        "    query('FROM v_athena_agency'); query('FROM v_athena_trust_agreement'); query('FROM v_athena_proof_policy')\n"
        "_REGISTRY_SERVICES = []\n"
        "_PROTOCOL_FORMATS = {\n    'polaris-federation-manifest': 1,\n    'polaris-epoch-checkpoint': 1,\n    'polaris-revocation-feed': 1,\n    'polaris-status-assertion': 1,\n    'polaris-transparency-sth': 1,\n    'polaris-federation-status-bundle': 1,\n    'polaris-exchange-receipt': 1,\n    'polaris-exchange-mint': 1,\n    'polaris-timestamp': 1,\n    'polaris-registry': 1,\n    'polaris-exchange-request': 1,\n    'polaris-signed-document': 1,\n    'polaris-id-token': 1,\n    'polaris-authenticity-pack': 1,\n    'polaris-transparency-cosignature': 1,\n    'polaris-transparency-publication': 1,\n    'polaris-published-head': 1,\n}\n"
    )
    good = {
        'polaris_web/app.py': APP,
        'scripts/polaris-verify.py': (
            "import json\n"
            "def _registry_canonical(r): return b''\n"
            "def verify_registry(r, **k):\n    # not signed by the key it lists for its own publisher\n    return {}\n"
            "def registry_service(r, kind): return None\n"
            "def registry_authority(r, k): return None\n"
            "def registry_trusts(r, k, c): return []\n"
        ),
        'polaris_web/test_canonical_equivalence.py': "flask_app._registry_statement\n",
        'docs/reference/WIRE-SPEC.md': "polaris-registry/1\n",
        'conformance/cases.json': '{"cases": [{"artifact": "registry"}]}\n',
        'sdk/python/polaris_verify/__init__.py': '"polaris-registry/1": ["format"]\n',
        'sdk/typescript/src/index.ts': '"polaris-registry/1": ["format"]\n',
        'scripts/polaris-verifier-fuzz.py': "V.verify_registry(o)\n",
        'scripts/polaris-registry-drill.py': "V.registry_service(reg, 'timestamp')\n",
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-registry-drill.py\n',
        'scripts/polaris-federation-instances-drill.py': "V.registry_service(reg, 'timestamp'); V.registry_trusts(reg, pub_a, CONTEXT_ID)\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_registry(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    write({'polaris_web/app.py': APP.replace("/api/v1/registry", "/api/v1/nope")})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL without the route"
    write({'polaris_web/app.py': APP.replace("    'polaris-timestamp': 1,\n", "")})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL if a spec format is not advertised"
    write({'polaris_web/app.py': APP.replace("    'polaris-registry': 1,\n", "    'polaris-registry': 1,\n    'polaris-made-up': 1,\n")})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL if a format the spec lacks is advertised"
    write({'polaris_web/app.py': APP.replace("v_athena_trust_agreement", "AgencyTrustAttestation")})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL if the trust graph does not come from Athena"
    write({'scripts/polaris-verify.py': good['scripts/polaris-verify.py'].replace("lists for its own publisher", "whatever")})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL without the publisher self-consistency rule"
    write({'scripts/polaris-verify.py': good['scripts/polaris-verify.py'].replace("def registry_trusts", "def nope")})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL without the discovery helpers"
    write({'conformance/cases.json': '{"cases": []}\n'})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL without conformance cases"
    write({'sdk/python/polaris_verify/__init__.py': "# nothing\n"})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL if the Python SDK cannot verify it"
    write({'scripts/polaris-federation-instances-drill.py': "# hardcoded paths only\n"})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL if discovery is not proven across two instances"
    write({'.github/workflows/ci.yml': "jobs: {}\n"})
    assert checks.check_registry(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"


def test_receipt_transparency_check_discriminates(tmp_path):
    # v9.322 (P8.2c): the receipt set as an append-only transparency log -- hash-only table,
    # strict trigger, privilege REVOKE, reversible migration, a second RFC-6962 log with
    # inclusion evidence, offline proof, monitor support, drilled over HTTP, unit-tested,
    # documented. Each perturbation removes one leg.
    good = {
        'polaris_sql/01_schema.sql': "CREATE TABLE ExchangeReceiptLog (receipt_hash CHAR(64) CONSTRAINT chk_receipt_log_hash CHECK (x));\n",
        'polaris_sql/06_triggers.sql': "CREATE TRIGGER trg_receipt_log_append_only BEFORE UPDATE OR DELETE ON ExchangeReceiptLog EXECUTE FUNCTION reject_receipt_log_modification();\n",
        'polaris_sql/09_grants.sql': "'exchangereceiptlog'\n",
        'polaris_sql/migrations/2026-09-09-001-exchange-receipt-log.up.sql': "CREATE TABLE IF NOT EXISTS ExchangeReceiptLog ();\n",
        'polaris_sql/migrations/2026-09-09-001-exchange-receipt-log.down.sql': "DROP TABLE IF EXISTS ExchangeReceiptLog;\n",
        'polaris_web/app.py': (
            "_RECEIPT_LOG_ID = 'polaris-exchange-receipt-log'\n"
            "@app.route('/api/v1/transparency/receipts/sth')\n"
            "@app.route('/api/v1/transparency/receipts/consistency/<int:m>/<int:n>')\n"
            "@app.route('/api/v1/exchange-receipt/inclusion/<receipt_hash>')\n"
            "def _receipt_log_append(h): query('INSERT INTO ExchangeReceiptLog (receipt_hash) VALUES (%s)')\n"
        ),
        'scripts/polaris-verify.py': "import json\ndef receipt_hash(r): return ''\ndef verify_receipt_inclusion(r, p, s, log_key=None): return {}\n",
        'scripts/polaris-transparency-monitor.py': 'ap.add_argument("--log", choices=("anchors", "receipts"))\n',
        'scripts/polaris-federation-instances-drill.py': 'V.verify_receipt_inclusion(receipt, p, s)  # "--log", "receipts"\n',
        'polaris_web/test_app.py': "class ExchangeReceiptLogTests(PolarisTestCase): pass\n",
        'docs/reference/DATA-MODEL.md': "### `ExchangeReceiptLog`\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            if body is None:
                f.unlink(missing_ok=True)
            else:
                f.write_text(body)

    write()
    assert checks.check_receipt_transparency(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    write({'polaris_sql/01_schema.sql': "CREATE TABLE ExchangeReceiptLog (receipt_body TEXT);\n"})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL if the log is not hash-only"
    write({'polaris_sql/06_triggers.sql': "-- no trigger\n"})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL without the strict append-only trigger"
    write({'polaris_sql/09_grants.sql': "-- nothing revoked\n"})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL without the privilege REVOKE"
    write({'polaris_sql/migrations/2026-09-09-001-exchange-receipt-log.down.sql': None})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL without a reversible migration"
    write({'polaris_web/app.py': good['polaris_web/app.py'].replace("/api/v1/exchange-receipt/inclusion/", "/nope/")})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL without per-receipt inclusion evidence"
    write({'polaris_web/app.py': good['polaris_web/app.py'].replace("INSERT INTO ExchangeReceiptLog", "SELECT 1")})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL if minting does not append to the log"
    write({'scripts/polaris-verify.py': "import psycopg2\n" + good['scripts/polaris-verify.py']})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    write({'scripts/polaris-transparency-monitor.py': "# anchors only\n"})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL if the monitor cannot watch the receipt log"
    write({'scripts/polaris-federation-instances-drill.py': "# no inclusion here\n"})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL if not proven over HTTP"
    write({'docs/reference/DATA-MODEL.md': "# nothing\n"})
    assert checks.check_receipt_transparency(tmp_path)[0].level == "FAIL", "must FAIL if the table is undocumented"


def test_timestamp_authority_check_discriminates(tmp_path):
    # v9.321 (P8.7a): the timestamp authority -- digest-only at the door, verified offline with a
    # binding helper, standalone, in the oracle/spec/conformance (both SDKs)/fuzzer, drilled in CI.
    good = {
        'polaris_web/app.py': (
            "@app.route('/api/v1/timestamp/<int:agency_id>', methods=['POST'])\n"
            "def api_v1_timestamp(agency_id):\n"
            "    _timestamp_statement(ts)  # polaris-timestamp/1\n"
            "    # the content itself is never sent\n"
            "    security.rate_limiter.allow('tsa:%d' % agency_id, 600, 60)\n"
        ),
        'scripts/polaris-verify.py': (
            "import json, hashlib\n"
            "def _timestamp_canonical(t): return b''\n"
            "def verify_timestamp(t, **k): return {}\n"
            "def timestamp_binds(t, data): return True\n"
        ),
        'polaris_web/test_canonical_equivalence.py': "flask_app._timestamp_statement\n",
        'docs/reference/WIRE-SPEC.md': "polaris-timestamp/1\n",
        'conformance/cases.json': '{"cases": [{"artifact": "timestamp"}]}\n',
        'sdk/python/polaris_verify/__init__.py': '"polaris-timestamp/1": ["format"]\n',
        'sdk/typescript/src/index.ts': '"polaris-timestamp/1": ["format"]\n',
        'scripts/polaris-verifier-fuzz.py': "V.verify_timestamp(o)\n",
        'scripts/polaris-timestamp-drill.py': "V.timestamp_binds(ts, data)\n",
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-timestamp-drill.py\n',
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_timestamp_authority(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    write({'polaris_web/app.py': good['polaris_web/app.py'].replace("/api/v1/timestamp", "/api/v1/nope")})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL without the route"
    write({'polaris_web/app.py': good['polaris_web/app.py'].replace("the content itself is never sent", "we accept content")})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL without the digest-only rule"
    write({'scripts/polaris-verify.py': good['scripts/polaris-verify.py'].replace("def timestamp_binds", "def nope")})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL without the binding helper"
    write({'scripts/polaris-verify.py': "import psycopg2\n" + good['scripts/polaris-verify.py']})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    write({'polaris_web/test_canonical_equivalence.py': "# nothing\n"})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL if not oracle-pinned"
    write({'docs/reference/WIRE-SPEC.md': "# spec\n"})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL if not in the wire spec"
    write({'conformance/cases.json': '{"cases": []}\n'})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL without conformance cases"
    write({'sdk/typescript/src/index.ts': "// nothing\n"})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL if the TS SDK cannot verify it"
    write({'scripts/polaris-verifier-fuzz.py': "# nothing\n"})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL if the fuzzer does not cover it"
    write({'.github/workflows/ci.yml': "jobs: {}\n"})
    assert checks.check_timestamp_authority(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"


def test_exchange_mint_signed_auth_check_discriminates(tmp_path):
    # v9.320 (P8.2b): service-to-service minting authenticated by the responder's ML-DSA-65
    # signature under its registered key, fail-closed, freshness-bounded, rate-bounded,
    # oracle-pinned, specified, proven over HTTP, unit-tested for the refusal. Each
    # perturbation removes one leg.
    APP = (
        "@app.route('/api/v1/exchange-receipt/<int:agency_id>/signed', methods=['POST'])\n"
        "def api_v1_exchange_receipt_signed(agency_id):\n"
        "    if not pqc_signing.is_enabled(): return 'placeholder signature is not authentication', 503\n"
        "    if int(mint.get('responder_agency_id')) != agency_id: return 400\n"
        "    if abs(dt) > _EXCHANGE_MINT_WINDOW: return 401\n"
        "    security.rate_limiter.allow('exmint:%d' % agency_id, 120, 60)\n"
        "    ok = pqc_signing.verify_both(_exchange_mint_statement(mint), sig, key, require_witness=True)\n"
        "    # polaris-exchange-mint/1\n"
    )
    good = {
        'polaris_web/app.py': APP,
        'scripts/polaris-verify.py': "def _exchange_mint_canonical(m): return b''\n",
        'polaris_web/test_canonical_equivalence.py': "flask_app._exchange_mint_statement\n",
        'docs/reference/WIRE-SPEC.md': "polaris-exchange-mint/1\n",
        'scripts/polaris-federation-instances-drill.py': "base_b + '/api/v1/exchange-receipt/1/signed'  # NO session\n",
        'polaris_web/test_app.py': "self.client.post('/api/v1/exchange-receipt/1/signed'); assertEqual(r.status_code, 503)\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    write({'polaris_web/app.py': APP.replace("/signed", "/nope")})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL without the signed route"
    write({'polaris_web/app.py': APP.replace("require_witness=True", "require_witness=False")})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL if the second witness is optional for auth"
    write({'polaris_web/app.py': APP.replace("placeholder signature is not authentication", "ok anyway")})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL if it does not fail closed without real PQC"
    write({'polaris_web/app.py': APP.replace("_EXCHANGE_MINT_WINDOW", "forever")})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL without the freshness window"
    write({'polaris_web/app.py': APP.replace("exmint:", "nolimit:")})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL without the per-responder rate bound"
    write({'scripts/polaris-verify.py': "# nothing\n"})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL without the client-side canonical builder"
    write({'polaris_web/test_canonical_equivalence.py': "# nothing\n"})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL if the statement is not oracle-pinned"
    write({'docs/reference/WIRE-SPEC.md': "# spec\n"})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL if not in the wire spec"
    write({'scripts/polaris-federation-instances-drill.py': "# no minting here\n"})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not prove it over HTTP"
    write({'polaris_web/test_app.py': "# no refusal test\n"})
    assert checks.check_exchange_mint_signed_auth(tmp_path)[0].level == "FAIL", "must FAIL without the fail-closed unit test"


def test_no_named_reference_systems_check_discriminates(tmp_path):
    (tmp_path / "docs").mkdir()
    doc = tmp_path / "docs" / "a.md"
    doc.write_text("Polaris describes the class: a mature national digital-identity ecosystem.\n")
    assert checks.check_no_named_reference_systems(tmp_path)[0].level == "OK", "must PASS on a clean tree"
    doc.write_text("Polaris is the anti-surveillance inversion of X-Road.\n")
    assert checks.check_no_named_reference_systems(tmp_path)[0].level == "FAIL", "must FAIL on a named product"
    doc.write_text("clean\n")
    (tmp_path / "app.py").write_text("# modelled on Estonia's card\n")
    assert checks.check_no_named_reference_systems(tmp_path)[0].level == "FAIL", \
        "must FAIL on a named country in a code comment"
    (tmp_path / "app.py").write_text("# an acronym: the TARA broker\n")
    assert checks.check_no_named_reference_systems(tmp_path)[0].level == "FAIL", \
        "must FAIL on a whole-word product acronym"
    (tmp_path / "app.py").write_text("# tara is an ordinary lowercase word; sixteen findings at the crossroad; criteria too\n")
    assert checks.check_no_named_reference_systems(tmp_path)[0].level == "OK", \
        "lowercase ordinary words and embedded letters must NOT trip the acronym patterns"
    (tmp_path / "polaris_checks").mkdir()
    (tmp_path / "polaris_checks" / "checks.py").write_text("_PATTERNS = ('estonia', 'x-road')\n")
    assert checks.check_no_named_reference_systems(tmp_path)[0].level == "OK", \
        "the pattern list in the check module itself is exempt"
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "vendor.md").write_text("X-Road\n")
    assert checks.check_no_named_reference_systems(tmp_path)[0].level == "OK", \
        "vendored and build directories are skipped"


def test_preflight_ts_typecheck_discriminates(tmp_path):
    (tmp_path / "scripts").mkdir()
    good = (
        "#!/usr/bin/env bash\n"
        'TS="${ROOT}/sdk/typescript"\n'
        'if command -v node > /dev/null 2>&1 && [ -d "${TS}/node_modules" ]; then\n'
        '  ( cd "${TS}" && npx --no-install tsc --noEmit )\n'
        '  ( cd "${TS}" && node --test )\n'
        "fi\n"
    )
    sh = tmp_path / "scripts" / "polaris-preflight.sh"
    sh.write_text(good)
    assert checks.check_preflight_typechecks_ts_sdk(tmp_path)[0].level == "OK", \
        "must PASS when preflight type-checks the TS SDK, guarded on node"
    sh.write_text(good.replace("npx --no-install tsc --noEmit", "echo skip"))
    assert checks.check_preflight_typechecks_ts_sdk(tmp_path)[0].level == "FAIL", \
        "must FAIL when preflight does not run tsc --noEmit"
    sh.write_text(good.replace("command -v node > /dev/null 2>&1 && ", ""))
    assert checks.check_preflight_typechecks_ts_sdk(tmp_path)[0].level == "FAIL", \
        "must FAIL when the TS step is not guarded on node availability"
    sh.write_text("#!/usr/bin/env bash\necho no ts here\n")
    assert checks.check_preflight_typechecks_ts_sdk(tmp_path)[0].level == "FAIL", \
        "must FAIL when preflight does not exercise the sdk/typescript gate"
    sh.unlink()
    assert checks.check_preflight_typechecks_ts_sdk(tmp_path)[0].level == "FAIL", \
        "must FAIL when polaris-preflight.sh is missing"


def test_exchange_receipt_check_discriminates(tmp_path):
    # v9.317 (P8.2): the exchange receipt, evidence without retention -- commit to request/
    # response HASHES not bodies, verified offline (standalone), authorization via a trusted
    # attestation, minted at an endpoint that takes only hashes, in the oracle + wire spec, run
    # in CI. Each perturbation removes one leg.
    good = {
        'scripts/polaris-verify.py': (
            "import json, hashlib\n"
            "# polaris-exchange-receipt/1\n"
            "def _exchange_receipt_canonical(r): return b''\n"
            "def verify_exchange_receipt(r, **k):\n"
            "    r.get('request_hash'); r.get('response_hash')  # commit by hash, not content\n"
            "    # attested_public_key_hex in a trusted manifest -> requester_authorized\n"
            "    return {'requester_authorized': None}\n"
        ),
        'polaris_web/app.py': (
            "@app.route('/api/v1/exchange-receipt/<int:agency_id>', methods=['POST'])\n"
            "def api_v1_exchange_receipt(agency_id):\n"
            "    _exchange_receipt_statement(body)  # AgencyTrustAttestation authorizes the requester\n"
            "    pqc_signing.signature_over_message(stmt)\n"
            "    # hashes only: the payload is never sent\n"
        ),
        'polaris_web/test_canonical_equivalence.py': "# polaris-exchange-receipt/1\n",
        'docs/reference/WIRE-SPEC.md': "# spec\nMUST ... polaris-exchange-receipt/1\n",
        'scripts/polaris-exchange-receipt-drill.py': (
            "def main():\n    verify_exchange_receipt(r)  # evidence without retention\n"
        ),
        '.github/workflows/ci.yml': '      - run: python scripts/polaris-exchange-receipt-drill.py\n',
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_exchange_receipt(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the verify function is missing
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("def verify_exchange_receipt", "def nope")})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL without the verify function"
    # 2. the receipt does not commit by hash
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("request_hash", "request_body")})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL if it does not commit by hash"
    # 3. authorization is not confirmed
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("requester_authorized", "whatever")})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL without authorization"
    # 4. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 5. the mint endpoint is missing
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("/api/v1/exchange-receipt", "/api/v1/nope")})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL without the mint endpoint"
    # 6. the endpoint does not enforce hashes-only
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("the payload is never sent", "we keep the body")})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL if the payload could be retained"
    # 7. not in the oracle
    write({"polaris_web/test_canonical_equivalence.py": "# nothing\n"})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL if not pinned by the oracle"
    # 8. not in the wire spec
    write({"docs/reference/WIRE-SPEC.md": "# spec\nMUST\n"})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL if not in the wire spec"
    # 9. the drill does not prove evidence-without-retention
    write({"scripts/polaris-exchange-receipt-drill.py": "def main():\n    verify_exchange_receipt(r)\n"})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL without the without-retention property"
    # 10. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_exchange_receipt(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"


def test_federation_two_instances_check_discriminates(tmp_path):
    # v9.299 (P3.10): a drill that boots two real instances and drives the federation
    # endpoints over HTTP under real ML-DSA, run in its own CI job. Each perturbation
    # removes one leg.
    good = {
        'scripts/polaris-federation-instances-drill.py': (
            "import os\n"
            "os.environ['POLARIS_USE_REAL_PQC'] = '1'\n"
            "A = os.environ.get('POLARIS_FED_A_DB', 'polaris_fa')\n"
            "B = os.environ.get('POLARIS_FED_B_DB', 'polaris_fb')\n"
            "# boots each instance with gunicorn; AgencyTrustAttestation drives the\n"
            "# attestation revocation; base URL http://127.0.0.1:PORT ; endpoints:\n"
            "#   /api/v1/federation-manifest/ /api/v1/epoch-checkpoint/ /api/v1/revocation-feed/\n"
            "def main():\n"
            "    verify_cross_authority(pack, 1, [manifest])  # revocation flips the decision\n"
        ),
        '.github/workflows/ci.yml': (
            "jobs:\n  federation-two-instances:\n    steps:\n"
            "      - run: python scripts/polaris-federation-instances-drill.py\n"
        ),
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_federation_two_instances(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. an endpoint is not driven over HTTP
    write({"scripts/polaris-federation-instances-drill.py": good["scripts/polaris-federation-instances-drill.py"].replace("/api/v1/revocation-feed/", "/api/v1/nope/")})
    assert checks.check_federation_two_instances(tmp_path)[0].level == "FAIL", "must FAIL without the revocation-feed fetch"
    # 2. it does not boot real instances
    write({"scripts/polaris-federation-instances-drill.py": good["scripts/polaris-federation-instances-drill.py"].replace("gunicorn", "print")})
    assert checks.check_federation_two_instances(tmp_path)[0].level == "FAIL", "must FAIL if it does not boot instances (gunicorn)"
    # 3. not real ML-DSA
    write({"scripts/polaris-federation-instances-drill.py": good["scripts/polaris-federation-instances-drill.py"].replace("POLARIS_USE_REAL_PQC", "PLACEHOLDER")})
    assert checks.check_federation_two_instances(tmp_path)[0].level == "FAIL", "must FAIL if it does not run under real PQC"
    # 4. no attestation lifecycle
    write({"scripts/polaris-federation-instances-drill.py": good["scripts/polaris-federation-instances-drill.py"].replace("AgencyTrustAttestation", "SomeTable")})
    assert checks.check_federation_two_instances(tmp_path)[0].level == "FAIL", "must FAIL without the attestation lifecycle"
    # 5. the drill does not run in its own CI job
    write({".github/workflows/ci.yml": "jobs:\n  other:\n    steps:\n      - run: echo nothing\n"})
    assert checks.check_federation_two_instances(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"


def test_canonical_equivalence_check_discriminates(tmp_path):
    # v9.300: the app statement builder and the verify canonical builder for each signed
    # type must project the same ordered key list in the compact sorted-key form, with a
    # Hypothesis oracle wired into CI. Each perturbation breaks one leg.
    def _proj(keys, getter, q):
        inner = ", ".join("%s%s%s" % (q, k, q) for k in keys)
        return ("    return json.dumps({k: %s.get(k) for k in (%s)}, sort_keys=True, "
                "separators=(%s,%s, %s:%s)).encode()\n" % (getter, inner, q, q, q, q))

    app = (
        "import json\n"
        "def _manifest_statement(body):\n" + _proj(["format", "authority"], "body", "'") +
        "def _epoch_checkpoint_statement(body):\n" + _proj(["format", "epoch"], "body", "'") +
        "def _revocation_feed_statement(body):\n" + _proj(["format", "revoked_root_hex"], "body", "'") +
        "def _status_assertion_statement(token_value, status, issued_at, expires_at):\n"
        "    return json.dumps({'format': 'F', 'token_value': token_value, 'status': status}, "
        "sort_keys=True, separators=(',', ':')).encode()\n"
        "def _sth_statement(body):\n" + _proj(["format", "log_id"], "body", "'")
    )
    verify = (
        "import json\n"
        "def _manifest_canonical(m):\n" + _proj(["format", "authority"], "m", '"') +
        "def _epoch_checkpoint_canonical(cp):\n" + _proj(["format", "epoch"], "cp", '"') +
        "def _revocation_feed_canonical(f):\n" + _proj(["format", "revoked_root_hex"], "f", '"') +
        "def _status_assertion_canonical(a):\n"
        '    return json.dumps({"format": a.get("format"), "token_value": a.get("token_value"), '
        '"status": a.get("status")}, sort_keys=True, separators=(",", ":")).encode()\n'
        "def _sth_canonical(s):\n" + _proj(["format", "log_id"], "s", '"')
    )
    good = {
        "polaris_web/app.py": app,
        "scripts/polaris-verify.py": verify,
        "polaris_web/test_canonical_equivalence.py": "SIGNED_TYPES = {}\ndef cross_impl_equivalence(): pass\n",
        "scripts/polaris-coverage.sh": "run polaris_web unittest test_canonical_equivalence\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_canonical_equivalence(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. a key list drifts between the two sides
    write({"scripts/polaris-verify.py": verify.replace('"authority"', '"AUTHORITY_RENAMED"')})
    assert checks.check_canonical_equivalence(tmp_path)[0].level == "FAIL", "must FAIL if a signed key list differs"
    # 2. one side drops the sorted-key canonical form
    write({"polaris_web/app.py": app.replace("sort_keys=True", "sort_keys=False", 1)})
    assert checks.check_canonical_equivalence(tmp_path)[0].level == "FAIL", "must FAIL without sort_keys=True"
    # 3. the Hypothesis oracle is missing
    write({"polaris_web/test_canonical_equivalence.py": "# empty\n"})
    assert checks.check_canonical_equivalence(tmp_path)[0].level == "FAIL", "must FAIL without the oracle"
    # 4. the oracle is not wired into CI
    write({"scripts/polaris-coverage.sh": "run polaris_web unittest test_app\n"})
    assert checks.check_canonical_equivalence(tmp_path)[0].level == "FAIL", "must FAIL if the oracle does not run in CI"


def test_transparency_log_check_discriminates(tmp_path):
    # v9.301 (P3.3): a public append-only RFC-6962 log over AnchorBatch, verified offline
    # (standalone), with an independent monitor that alerts on tampering, run in CI, spec'd.
    good = {
        "scripts/polaris-verify.py": (
            "import json, hashlib\n"
            "# polaris-transparency-sth/1\n"
            "def merkle_tree_head(e): return b''\n"
            "def verify_consistency(m,n,r1,r2,p): return True\n"
            "def verify_inclusion(i,n,l,r,p): return True\n"
            "def _sth_canonical(s): return b''\n"
            "def verify_sth(s, issuer_key=None): return {}\n"
            "def verify_log_consistency(a,b,p,issuer_key=None): return {'fork': False}\n"
        ),
        "polaris_web/app.py": (
            "@app.route('/api/v1/transparency/sth')\ndef sth():\n"
            "    _sth_statement(body); pqc_signing.signature_over_message(x)  # AnchorBatch\n"
            "@app.route('/api/v1/transparency/consistency/<int:m>/<int:n>')\ndef cons(m,n): pass\n"
            "@app.route('/api/v1/transparency/proof/<int:i>')\ndef pf(i): pass\n"
            "@app.route('/api/v1/transparency/entries')\ndef ent(): pass\n"
        ),
        "polaris_web/anchoring.py": "def log_tree_head(e): pass\ndef log_consistency_proof(m,e): pass\n",
        "scripts/polaris-transparency-monitor.py": "verify_log_consistency\nprint('ALERT: x')\n",
        "scripts/polaris-transparency-drill.py": "verify_log_consistency\n# runs scripts/polaris-transparency-monitor.py\n",
        ".github/workflows/ci.yml": "      - run: python scripts/polaris-transparency-drill.py\n",
        "docs/design/transparency-log.md": "# transparency log\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_transparency_log(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the verifier loses append-only detection
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("def verify_log_consistency", "def gone")})
    assert checks.check_transparency_log(tmp_path)[0].level == "FAIL", "must FAIL without verify_log_consistency"
    # 2. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_transparency_log(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 3. an endpoint is missing
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("/api/v1/transparency/entries", "/api/v1/nope")})
    assert checks.check_transparency_log(tmp_path)[0].level == "FAIL", "must FAIL without the entries endpoint"
    # 4. the app-side log math is gone
    write({"polaris_web/anchoring.py": "def something_else(): pass\n"})
    assert checks.check_transparency_log(tmp_path)[0].level == "FAIL", "must FAIL without the RFC-6962 log math"
    # 5. the monitor does not alert
    write({"scripts/polaris-transparency-monitor.py": "verify_log_consistency\nprint('all good')\n"})
    assert checks.check_transparency_log(tmp_path)[0].level == "FAIL", "must FAIL if the monitor never ALERTs"
    # 6. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_transparency_log(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"
    # 7. the spec is missing
    write()
    (tmp_path / "docs" / "design" / "transparency-log.md").unlink()
    assert checks.check_transparency_log(tmp_path)[0].level == "FAIL", "must FAIL without the spec"


def test_transparency_gossip_check_discriminates(tmp_path):
    # v9.302 (P3.3b): the split-view defence -- witness cosignatures, a witnessed-checkpoint
    # threshold, and a non-repudiable equivocation proof, with a witness daemon and a gossip
    # drill run in CI. Each perturbation removes one leg.
    good = {
        "scripts/polaris-verify.py": (
            "import json, hashlib\n"
            "# polaris-transparency-cosignature/1\n"
            "def _cosignature_canonical(c): return b''\n"
            "def verify_cosignature(c, witness_key=None): return {}\n"
            "def verify_witnessed_checkpoint(s, cs, tw, threshold=1, issuer_key=None): return {}\n"
            "def verify_equivocation(a, b, k): return {'proven': False}\n"
        ),
        "scripts/polaris-transparency-witness.py": (
            "def cosign(head, key_file): pass\n"
            "# uses verify_equivocation on the gossip pool\n"
            "print('ALERT: equivocation')\n"
        ),
        "scripts/polaris-transparency-gossip-drill.py": (
            "verify_witnessed_checkpoint\nverify_equivocation\n"
            "# runs scripts/polaris-transparency-witness.py\n"
        ),
        ".github/workflows/ci.yml": "      - run: python scripts/polaris-transparency-gossip-drill.py\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_transparency_gossip(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the equivocation proof is gone
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("def verify_equivocation", "def gone")})
    assert checks.check_transparency_gossip(tmp_path)[0].level == "FAIL", "must FAIL without verify_equivocation"
    # 2. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_transparency_gossip(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 3. the witness never ALERTs
    write({"scripts/polaris-transparency-witness.py": "def cosign(head, key_file): pass\nprint('all good')\n"})
    assert checks.check_transparency_gossip(tmp_path)[0].level == "FAIL", "must FAIL if the witness never ALERTs"
    # 4. the drill does not run the witness daemon
    write({"scripts/polaris-transparency-gossip-drill.py": "verify_witnessed_checkpoint\nverify_equivocation\n"})
    assert checks.check_transparency_gossip(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run the witness"
    # 5. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_transparency_gossip(tmp_path)[0].level == "FAIL", "must FAIL if the gossip drill does not run in CI"


def test_transparency_publication_check_discriminates(tmp_path):
    # v9.303 (P3.3c): external-ledger publication -- a verifiable inclusion receipt, a
    # file-backed append-only ledger driver, and a drill, run in CI. Each perturbation
    # removes one leg.
    good = {
        "scripts/polaris-verify.py": (
            "import json, hashlib\n"
            "# polaris-transparency-publication/1\n"
            "def _publication_entry(a, b, c): return ''\n"
            "def verify_publication(log_sth, receipt, ledger_key): return {'published': False}\n"
        ),
        "scripts/polaris-transparency-ledger.py": (
            "import anchoring\n"
            "# POLARIS_LEDGER_BACKEND selects the driver (file default)\n"
            "anchoring.log_tree_head; anchoring.log_inclusion_proof\n"
        ),
        "scripts/polaris-transparency-publication-drill.py": (
            "verify_publication\n# runs scripts/polaris-transparency-ledger.py\n"
        ),
        ".github/workflows/ci.yml": "      - run: python scripts/polaris-transparency-publication-drill.py\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_transparency_publication(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the receipt verifier is gone
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("def verify_publication", "def gone")})
    assert checks.check_transparency_publication(tmp_path)[0].level == "FAIL", "must FAIL without verify_publication"
    # 2. the verifier is not standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_transparency_publication(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 3. the ledger has no backend driver
    write({"scripts/polaris-transparency-ledger.py": "import anchoring\nanchoring.log_tree_head; anchoring.log_inclusion_proof\n"})
    assert checks.check_transparency_publication(tmp_path)[0].level == "FAIL", "must FAIL without the backend driver"
    # 4. the drill does not run the ledger
    write({"scripts/polaris-transparency-publication-drill.py": "verify_publication\n"})
    assert checks.check_transparency_publication(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run the ledger"
    # 5. the drill does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_transparency_publication(tmp_path)[0].level == "FAIL", "must FAIL if the publication drill does not run in CI"


def test_lint_enforced_check_discriminates(tmp_path):
    # v9.306: ruff (pyflakes F rules) must be configured and actually run in pre-commit and
    # CI. Each perturbation removes one leg.
    good = {
        "ruff.toml": '[lint]\nselect = ["F"]\n',
        "polaris_web/requirements-dev.txt": "coverage>=7.6\nruff==0.16.6\n",
        ".pre-commit-config.yaml": "  - id: ruff\n    entry: ruff check\n",
        ".github/workflows/ci.yml": "      - run: ruff check .\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_lint_enforced(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the config is missing
    write({"ruff.toml": ""})
    assert checks.check_lint_enforced(tmp_path)[0].level == "FAIL", "must FAIL without ruff.toml"
    # 2. the config does not select the F rules
    write({"ruff.toml": '[lint]\nselect = ["E"]\n'})
    assert checks.check_lint_enforced(tmp_path)[0].level == "FAIL", "must FAIL if the F rules are not selected"
    # 3. ruff is not a dev dependency
    write({"polaris_web/requirements-dev.txt": "coverage>=7.6\n"})
    assert checks.check_lint_enforced(tmp_path)[0].level == "FAIL", "must FAIL without ruff in the dev deps"
    # 4. ruff is not wired into pre-commit
    write({".pre-commit-config.yaml": "  - id: other\n    entry: echo\n"})
    assert checks.check_lint_enforced(tmp_path)[0].level == "FAIL", "must FAIL without the pre-commit hook"
    # 5. ruff does not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_lint_enforced(tmp_path)[0].level == "FAIL", "must FAIL if ruff does not run in CI"


def test_federation_topology_check_discriminates(tmp_path):
    # v9.292 (P3.1): the topology ADR records federated-over-central + the threat-model
    # delta + the vocation grounding, and is kept honest against the code. Each
    # perturbation removes one leg.
    good = {'docs/design/federation-topology.md': '# Federation topology (ADR)\nStatus: Accepted 2026-09-08\nDecision: federated per-authority instances; no central instance/root/service.\nCross-authority trust is explicit and non-transitive.\n## Threat-model delta\ncentral vs federated; a central instance is a monopoly.\nGrounded: AgencyTrustAttestation, _federation_trust_holds, signing_public_key_hex, verify_pack.\n', 'polaris_sql/01_schema.sql': 'CREATE TABLE AgencyTrustAttestation (...);\nsigning_public_key_hex TEXT\n', 'polaris_web/app.py': 'def _federation_trust_holds(v, t, c):\n    return True\n', 'scripts/polaris-verify.py': 'def verify_pack(pack, anchor_keys=None):\n    return {}\n', 'docs/design/README.md': '| [federation-topology.md](federation-topology.md) | the ADR |\n'}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_federation_topology(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the ADR does not record the decision
    write({"docs/design/federation-topology.md": good["docs/design/federation-topology.md"].replace("federated per-authority", "some topology")})
    assert checks.check_federation_topology(tmp_path)[0].level == "FAIL", "must FAIL without the decision"
    # 2. the ADR drops the non-transitive property
    write({"docs/design/federation-topology.md": good["docs/design/federation-topology.md"].replace("non-transitive", "recursive")})
    assert checks.check_federation_topology(tmp_path)[0].level == "FAIL", "must FAIL without non-transitive trust"
    # 3. the ADR drops the threat-model delta
    write({"docs/design/federation-topology.md": good["docs/design/federation-topology.md"].replace("Threat-model delta", "Notes")})
    assert checks.check_federation_topology(tmp_path)[0].level == "FAIL", "must FAIL without the threat-model delta"
    # 4. the ADR drops the vocation grounding
    write({"docs/design/federation-topology.md": good["docs/design/federation-topology.md"].replace("monopoly", "preference")})
    assert checks.check_federation_topology(tmp_path)[0].level == "FAIL", "must FAIL without the anti-monopoly grounding"
    # 5. drift: the ADR claims the federated model but the schema lacks the attestation table
    write({"polaris_sql/01_schema.sql": "signing_public_key_hex TEXT only"})
    assert checks.check_federation_topology(tmp_path)[0].level == "FAIL", "must FAIL if the cited attestation table is absent (drift)"
    # 6. the ADR is not linked from the docs/design index
    write({"docs/design/README.md": "| other | doc |\n"})
    assert checks.check_federation_topology(tmp_path)[0].level == "FAIL", "must FAIL if the ADR is not indexed"


def test_offline_verification_check_discriminates(tmp_path):
    # v9.291 (P3.6): a short-lived signed status assertion + offline stapled verify.
    # Signed by the issuer, verified offline (standalone), freshness/window enforced,
    # run in CI. Each perturbation removes one leg.
    good = {'polaris_web/app.py': "@app.route('/api/v1/status-assertion', methods=['POST'])\ndef api_v1_status_assertion():\n    _status_assertion_statement(tv, st, ia, ea)\n    pqc_signing.signature_over_message(stmt)\n    return jsonify(expires_at=ea)\n", 'polaris_web/pqc_signing.py': "def signature_over_message(message, agency_id=None):\n    return b'', 'ML-DSA-65', None\n", 'scripts/polaris-verify.py': "import json, hashlib\ndef _status_assertion_canonical(a):\n    return b''\ndef verify_status_assertion(a, now=None, max_window_seconds=None, anchor_keys=None):\n    fresh = True\n    return {'fresh': fresh, 'format': 'polaris-status-assertion/1'}\ndef verify_stapled(pack, a, now=None, max_window_seconds=None, anchor_keys=None):\n    return {'decision': 'accept'}\n", 'scripts/polaris-offline-status-drill.py': 'def main():\n    verify_stapled(p, a)\n', '.github/workflows/ci.yml': '      - run: python scripts/polaris-offline-status-drill.py\n', 'polaris_web/test_app.py': 'class OfflineStatusAssertionTests:\n    def t(self): pass\n'}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_offline_verification(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the assertion is not issuer-signed
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("pqc_signing.signature_over_message(stmt)", "pass")})
    assert checks.check_offline_verification(tmp_path)[0].level == "FAIL", "must FAIL if the assertion is not signed"
    # 2. the offline verifier drops the freshness/window enforcement
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("max_window_seconds", "ignored")})
    assert checks.check_offline_verification(tmp_path)[0].level == "FAIL", "must FAIL without the window bound"
    # 3. the verifier is no longer standalone
    write({"scripts/polaris-verify.py": "import psycopg2\n" + good["scripts/polaris-verify.py"]})
    assert checks.check_offline_verification(tmp_path)[0].level == "FAIL", "must FAIL if the verifier is not standalone"
    # 4. the drill is not wired into CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_offline_verification(tmp_path)[0].level == "FAIL", "must FAIL if the drill does not run in CI"
    # 5. verify_stapled is gone
    write({"scripts/polaris-verify.py": good["scripts/polaris-verify.py"].replace("def verify_stapled", "def other")})
    assert checks.check_offline_verification(tmp_path)[0].level == "FAIL", "must FAIL without offline stapled verify"
    # 6. the endpoint test is gone
    write({"polaris_web/test_app.py": "class Other:\n    pass\n"})
    assert checks.check_offline_verification(tmp_path)[0].level == "FAIL", "must FAIL without OfflineStatusAssertionTests"


def test_typescript_sdk_check_discriminates(tmp_path):
    # v9.290 (P3.5b): the TypeScript verify SDK, same conformance contract, second
    # implementation, run in CI. Each perturbation removes one leg.
    good = {'sdk/typescript/src/index.ts': "import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js';\nimport { sha3_256 } from '@noble/hashes/sha3.js';\nexport function verifyAuthenticity(pack, anchors) {\n  const d = sha3_256(new TextEncoder().encode(pack.token_value));\n  return ml_dsa65.verify(pack.sig, d, pack.pk);\n}\nexport function verifyStatusAssertion(a, now) {\n  return { authentic: true, fresh: true, active: true };\n}\nexport function verifySignedArtifact(o, now) {\n  return { authentic: true, fresh: true };\n}\nexport function verifyCrossAuthority(p, ctx, ms, ta, rf, now) {\n  return { decision: 'accept', authentic: true, issuerTrusted: true };\n}\nexport class PolarisVerifier {\n  async status() { await fetch('/api/v1/oauth/token'); await fetch('/api/v1/verify'); }\n}\n", 'sdk/typescript/src/conformance.ts': "import { verifyAuthenticity, verifyStatusAssertion } from './index.ts';\nprocess.stdout.write(JSON.stringify({ authentic: true, issuer_trusted: null }));\n", 'sdk/typescript/package.json': '{"dependencies": {"@noble/post-quantum": "^0.7.1"}}\n', 'sdk/typescript/package-lock.json': '{"lockfileVersion": 3}\n', 'sdk/typescript/test/sdk.test.ts': "import { test } from 'node:test';\ntest('x', () => {});\n", '.github/workflows/ci.yml': 'jobs:\n  sdk-typescript:\n    steps:\n      - uses: actions/setup-node@v4\n      - run: python3 conformance/run_conformance.py --verifier "node sdk/typescript/src/conformance.ts"\n'}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_typescript_sdk(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the SDK no longer verifies real ML-DSA via @noble
    write({"sdk/typescript/src/index.ts": good["sdk/typescript/src/index.ts"].replace("ml_dsa65.verify", "trustMe")})
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL without real ML-DSA verification"
    # 2. the SDK reaches into the Polaris tree (not standalone)
    write({"sdk/typescript/src/index.ts": good["sdk/typescript/src/index.ts"] + "\nimport '../../polaris_web/app';\n"})
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL if the SDK is not standalone"
    # 3. the lockfile is missing (npm ci not reproducible)
    (tmp_path / "sdk" / "typescript" / "package-lock.json").unlink()
    write_index_only = dict(good); del write_index_only["sdk/typescript/package-lock.json"]
    for rel, body in write_index_only.items():
        f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(body)
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL without the committed lockfile"
    write()  # restore
    # 4. CI does not drive the conformance runner against the TS verifier
    write({".github/workflows/ci.yml": "jobs:\n  sdk-typescript:\n    steps:\n      - run: echo hi\n"})
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL if CI does not run the conformance suite against the TS SDK"
    # 5. the conformance CLI drops the issuer_trusted field
    write({"sdk/typescript/src/conformance.ts": good["sdk/typescript/src/conformance.ts"].replace("issuer_trusted", "trusted")})
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL if the CLI output does not match the contract"
    # 6. the SDK tests are gone
    (tmp_path / "sdk" / "typescript" / "test" / "sdk.test.ts").unlink()
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL without the SDK unit tests"
    # 7. the TS SDK no longer verifies the status assertion (P8.1b)
    write({"sdk/typescript/src/index.ts": good["sdk/typescript/src/index.ts"].replace("verifyStatusAssertion", "nope")})
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL without TS status-assertion verification"
    # 8. the TS SDK no longer decides the federation trust decision (P8.1)
    write({"sdk/typescript/src/index.ts": good["sdk/typescript/src/index.ts"].replace("verifyCrossAuthority", "gone")})
    assert checks.check_typescript_sdk(tmp_path)[0].level == "FAIL", "must FAIL without TS trust decision"


def test_conformance_suite_check_discriminates(tmp_path):
    # v9.289 (P3.5): the verification conformance suite + Python reference SDK.
    # Standalone SDK (real ML-DSA + OAuth online), a language-agnostic runner, cases
    # covering authentic/not/untrusted-issuer, run in CI. Each perturbation removes a leg.
    good = {'sdk/python/polaris_verify/__init__.py': "import hashlib, urllib.request\ndef verify_authenticity(pack, anchors=None):\n    hashlib.sha3_256(b'')\n    from cryptography.hazmat.primitives.asymmetric import mldsa\n    mldsa.MLDSA65PublicKey\ndef verify_status_assertion(a, now=None):\n    return None\ndef verify_signed_artifact(o, now=None):\n    return None\ndef verify_cross_authority(p, ctx, ms, trusted_anchors=None, revocation_feed=None, now=None):\n    return None\nclass PolarisVerifier:\n    def _t(self):\n        return ('/api/v1/oauth/token', '/api/v1/verify')\n", 'sdk/python/polaris_verify/conformance.py': 'from . import verify_authenticity, verify_status_assertion, verify_signed_artifact, verify_cross_authority\n# dispatch on the case artifact\n', 'conformance/run_conformance.py': "import argparse\nFLAGS = ('--verifier', '--self', 'issuer_trusted')\n", 'conformance/SPEC.md': '# contract\nstdin authentic issuer_trusted\n', 'conformance/cases.json': '{"format": "polaris-conformance/1", "cases": [{"name": "a", "expect": {"authentic": true, "issuer_trusted": null}}, {"name": "b", "expect": {"authentic": true, "issuer_trusted": false}}, {"name": "c", "expect": {"authentic": false, "issuer_trusted": null}}, {"name": "sa", "artifact": "status-assertion", "expect": {"authentic": true}}, {"name": "cp", "artifact": "epoch-checkpoint", "expect": {"authentic": true}}, {"name": "fd", "artifact": "revocation-feed", "expect": {"authentic": true}}, {"name": "mf", "artifact": "federation-manifest", "expect": {"authentic": true}}, {"name": "bn", "artifact": "federation-status-bundle", "expect": {"authentic": true}}, {"name": "ca", "artifact": "cross-authority", "expect": {"decision": "accept"}}]}', '.github/workflows/ci.yml': '      - run: python conformance/run_conformance.py --self\n', 'sdk/python/test_sdk.py': 'class ConformanceRunnerTest:\n    def t(self): pass\n'}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_conformance_suite(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the SDK is no longer standalone (imports Polaris code)
    write({"sdk/python/polaris_verify/__init__.py": "import app\n" + good["sdk/python/polaris_verify/__init__.py"]})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL if the SDK imports Polaris code"
    # 2. the SDK no longer verifies real ML-DSA
    write({"sdk/python/polaris_verify/__init__.py": good["sdk/python/polaris_verify/__init__.py"].replace("MLDSA65PublicKey", "TrustMe")})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without real ML-DSA verification"
    # 3. the cases drop the genuine-but-untrusted-issuer verdict
    import json as _json
    cases = _json.loads(good["conformance/cases.json"])
    cases["cases"] = [c for c in cases["cases"] if c["expect"].get("issuer_trusted") is not False]
    write({"conformance/cases.json": _json.dumps(cases)})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without the untrusted-issuer case"
    # 4. the runner is no longer language-agnostic
    write({"conformance/run_conformance.py": good["conformance/run_conformance.py"].replace("--verifier", "--only-self")})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL if the runner cannot drive any verifier"
    # 5. the suite is not run in CI
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL if the conformance suite does not run in CI"
    # 6. the SDK is not tested against the suite
    write({"sdk/python/test_sdk.py": "class Other:\n    pass\n"})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without the SDK conformance test"
    # 7. the SDK no longer verifies the status assertion (P8.1b)
    write({"sdk/python/polaris_verify/__init__.py": good["sdk/python/polaris_verify/__init__.py"].replace("def verify_status_assertion", "def _nope")})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without status-assertion verification"
    # 8. the cases no longer certify a second artifact
    cases2 = _json.loads(good["conformance/cases.json"])
    cases2["cases"] = [c for c in cases2["cases"] if c.get("artifact") != "status-assertion"]
    write({"conformance/cases.json": _json.dumps(cases2)})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without a status-assertion case"
    # 9. the SDK no longer verifies the signed artifacts (P8.1b generic verifier)
    write({"sdk/python/polaris_verify/__init__.py": good["sdk/python/polaris_verify/__init__.py"].replace("def verify_signed_artifact", "def _gone")})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without verify_signed_artifact"
    # 10. the cases certify too few distinct artifacts
    cases3 = _json.loads(good["conformance/cases.json"])
    cases3["cases"] = [c for c in cases3["cases"] if c.get("artifact") in (None, "status-assertion")]
    write({"conformance/cases.json": _json.dumps(cases3)})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL if too few artifact types are certified"
    # 11. the SDK no longer decides the federation trust decision (P8.1)
    write({"sdk/python/polaris_verify/__init__.py": good["sdk/python/polaris_verify/__init__.py"].replace("def verify_cross_authority", "def _absent")})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without verify_cross_authority"
    # 12. the cases no longer certify the trust decision
    cases4 = _json.loads(good["conformance/cases.json"])
    cases4["cases"] = [c for c in cases4["cases"] if c.get("artifact") != "cross-authority"]
    write({"conformance/cases.json": _json.dumps(cases4)})
    assert checks.check_conformance_suite(tmp_path)[0].level == "FAIL", "must FAIL without a cross-authority case"


def test_relying_party_api_check_discriminates(tmp_path):
    # v9.288 (P3.4): the relying-party verification API -- OAuth2 client-credentials,
    # scope CHECK-constrained to 'verify', a possession-proof + uniform 'not
    # verifiable' verdict (no enumeration), no personal data, and the bound run as
    # adversaries. Each perturbation removes one leg.
    good = {'polaris_sql/01_schema.sql': "CREATE TABLE RelyingParty (\n    rp_id SERIAL PRIMARY KEY,\n    client_id VARCHAR(64) NOT NULL UNIQUE,\n    client_secret_hash VARCHAR(255) NOT NULL,\n    scope VARCHAR(40) NOT NULL DEFAULT 'verify'\n        CONSTRAINT chk_rp_scope CHECK (scope IN ('verify', 'authenticate', 'verify authenticate'))\n);\n", 'polaris_web/rp_auth.py': "_SALT = 'polaris-rp-access-token-v1'\ndef issue_access_token(secret_key, rp_id, client_id, scope='verify'): return 't'\ndef validate_access_token(secret_key, token, max_age=300): return {}\ndef parse_bearer(h): return None\n", 'polaris_web/app.py': "import hmac\n@app.route('/api/v1/oauth/token', methods=['POST'])\ndef api_v1_oauth_token():\n    grant = 'client_credentials'\n    return jsonify(error='invalid_client'), 401\n@app.route('/api/v1/verify', methods=['POST'])\ndef api_v1_verify():\n    if not hmac.compare_digest(a, b): return _not\n    return jsonify(reason='not a verifiable presentation')\n", 'polaris_cli/polaris.py': 'def cmd_rp_register(args):\n    pass\n', 'scripts/polaris-relying-party.py': 'def _oauth_status_checker(u, i, s, c):\n    pass\n', 'polaris_web/test_app.py': 'class RelyingPartyApiTests:\n    def t(self): pass\n', 'attacks/attack_controls.py': 'def attack_ac6_rp_credential_reaches_operator_surface(): pass\ndef attack_ac6_rp_verdict_leaks_personal_data(): pass\n'}

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_relying_party_api(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. scope is no longer CHECK-constrained to 'verify' (could become a login product)
    write({"polaris_sql/01_schema.sql": good["polaris_sql/01_schema.sql"].replace("CHECK (scope IN ('verify', 'authenticate', 'verify authenticate'))", "CHECK (scope IN ('verify', 'authenticate', 'verify authenticate', 'login'))")})
    assert checks.check_relying_party_api(tmp_path)[0].level == "FAIL", "must FAIL if scope is not constrained to verify"
    # 2. the bearer is no longer salted distinctly from the session cookie
    write({"polaris_web/rp_auth.py": good["polaris_web/rp_auth.py"].replace("polaris-rp-access-token-v1", "polaris-session")})
    assert checks.check_relying_party_api(tmp_path)[0].level == "FAIL", "must FAIL without the distinct bearer salt"
    # 3. the verify endpoint drops the uniform not-verifiable verdict (existence oracle)
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("not a verifiable presentation", "no such token")})
    assert checks.check_relying_party_api(tmp_path)[0].level == "FAIL", "must FAIL without the uniform not-verifiable verdict"
    # 4. the verify endpoint drops the possession proof (constant-time signature match)
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("compare_digest", "equals")})
    assert checks.check_relying_party_api(tmp_path)[0].level == "FAIL", "must FAIL without the possession proof"
    # 5. the least-privilege bound is no longer a running adversary
    write({"attacks/attack_controls.py": good["attacks/attack_controls.py"].replace("ac6_rp_credential_reaches_operator_surface", "noop")})
    assert checks.check_relying_party_api(tmp_path)[0].level == "FAIL", "must FAIL without the bounded-authority adversary"
    # 6. the no-personal-data verdict is no longer a running adversary
    write({"attacks/attack_controls.py": good["attacks/attack_controls.py"].replace("ac6_rp_verdict_leaks_personal_data", "noop")})
    assert checks.check_relying_party_api(tmp_path)[0].level == "FAIL", "must FAIL without the no-PII adversary"
    # 7. the CLI can no longer register a relying party
    write({"polaris_cli/polaris.py": "def cmd_other(args):\n    pass\n"})
    assert checks.check_relying_party_api(tmp_path)[0].level == "FAIL", "must FAIL without rp-register"


def test_holder_verifier_flow_check_discriminates(tmp_path):
    # v9.287: the end-to-end holder<->verifier flow — a standalone relying party
    # decides ACCEPT/REJECT by combining offline authenticity (verify_pack) with
    # online status (currently_authoritative), the matrix runs in CI (the drill),
    # and both the decision logic and the DB-backed flow are tested. Each
    # perturbation removes one leg.
    rp_good = 'import urllib.request\ndef verify_presentation(presentation, anchor_keys=None, status_checker=None):\n    a = _load_verifier().verify_pack(presentation[\'credential\'], anchor_keys)\n    current = None\n    if status_checker is not None:\n        current = status_checker(1).get(\'currently_authoritative\')\n    if not a["signature_valid"]:\n        return {"decision": "reject"}\n    if status_checker is None:\n        return {"decision": "provisional"}\n    return {"decision": "accept" if current else "reject"}\n'
    good = {
        "scripts/polaris-relying-party.py": rp_good,
        "scripts/polaris-e2e-drill.py": "def main():\n    rp.verify_presentation(p, status_checker=s)\n",
        ".github/workflows/ci.yml": "      - run: python scripts/polaris-e2e-drill.py\n",
        "scripts/test_relying_party.py": "def test_x():\n    rp.verify_presentation(p)\n",
        "scripts/polaris-coverage.sh": "run scripts unittest test_verify_load test_wallet test_relying_party\n",
        "polaris_web/test_app.py": "class EndToEndFlowTests:\n    def t(self): pass\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_holder_verifier_flow(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. the relying party is no longer standalone (imports app)
    write({"scripts/polaris-relying-party.py": "import app\n" + rp_good})
    assert checks.check_holder_verifier_flow(tmp_path)[0].level == "FAIL", "must FAIL if the relying party imports Polaris code"
    # 2. it drops the online status check (authenticity alone is not authorization)
    write({"scripts/polaris-relying-party.py": rp_good.replace("status_checker", "unused").replace("currently_authoritative", "gone")})
    assert checks.check_holder_verifier_flow(tmp_path)[0].level == "FAIL", "must FAIL without an online status check"
    # 3. it can no longer decide provisional (the offline outcome)
    write({"scripts/polaris-relying-party.py": rp_good.replace('"provisional"', '"accept"')})
    assert checks.check_holder_verifier_flow(tmp_path)[0].level == "FAIL", "must FAIL if it cannot decide provisional"
    # 4. the drill is not wired into CI (a path that never runs)
    write({".github/workflows/ci.yml": "      - run: echo nothing\n"})
    assert checks.check_holder_verifier_flow(tmp_path)[0].level == "FAIL", "must FAIL if the e2e drill does not run in CI"
    # 5. the decision tests are not run under the coverage runner
    write({"scripts/polaris-coverage.sh": "run scripts unittest test_verify_load test_wallet\n"})
    assert checks.check_holder_verifier_flow(tmp_path)[0].level == "FAIL", "must FAIL if the decision logic is untested in coverage"
    # 6. the DB-backed flow test is gone
    write({"polaris_web/test_app.py": "class SomethingElse:\n    pass\n"})
    assert checks.check_holder_verifier_flow(tmp_path)[0].level == "FAIL", "must FAIL without the DB-backed EndToEndFlowTests"


def test_federation_in_app_check_discriminates(tmp_path):
    # PE.3b (v9.286): federation is in the running app — Agency registers a signing
    # key, custody selects it, issuance signs with the agency's key and refuses a
    # cross-key token, /verify reports issuer_authentic, both halves tested. Each
    # perturbation removes one leg.
    good = {
        "polaris_sql/01_schema.sql": "CREATE TABLE Agency (agency_id SERIAL, signing_public_key_hex TEXT);\n",
        "polaris_web/custody.py": "def get_custody_for_agency(agency_id):\n    d = os.environ.get('POLARIS_AGENCY_KEYS_DIR')\n    return None\n",
        "polaris_web/pqc_signing.py": "def signature_with_key_for_token(token_value, agency_id=None):\n    return b'', 'ML-DSA-65', None\n",
        "polaris_web/app.py": (
            "sig, alg, pk = pqc_signing.signature_with_key_for_token(tv, agency_id=aid)\n"
            "if registered and registered != pk:\n"
            "    raise pqc_signing.SigningError('PE.3b federation binding')\n"
            "return jsonify(issuer_authentic=(token_key == agency_key))\n"
        ),
        "polaris_web/test_custody.py": "class PerAgencyCustodyTests:\n    def t(self): custody.get_custody_for_agency(1)\n",
        "polaris_web/test_app.py": "class FederationInAppTests:\n    def t(self): assert v['issuer_authentic']\n",
    }

    def write(overrides=None):
        files = dict(good); files.update(overrides or {})
        for rel, body in files.items():
            f = tmp_path / rel; f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(body)

    write()
    assert checks.check_federation_in_app(tmp_path)[0].level == "OK", "must PASS on the full fixture"
    # 1. issuance no longer enforces the binding (a cross-key token could be issued)
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("federation binding", "note")})
    assert checks.check_federation_in_app(tmp_path)[0].level == "FAIL", "must FAIL without the issuance binding enforcement"
    # 2. /verify no longer reports issuer_authentic
    write({"polaris_web/app.py": good["polaris_web/app.py"].replace("issuer_authentic", "something_else")})
    assert checks.check_federation_in_app(tmp_path)[0].level == "FAIL", "must FAIL without the issuer_authentic field"
    # 3. custody no longer selects the agency's key
    write({"polaris_web/custody.py": "def get_custody():\n    return None\n"})
    assert checks.check_federation_in_app(tmp_path)[0].level == "FAIL", "must FAIL without per-agency custody selection"
    # 4. the Agency schema loses its signing key column
    write({"polaris_sql/01_schema.sql": "CREATE TABLE Agency (agency_id SERIAL);\n"})
    assert checks.check_federation_in_app(tmp_path)[0].level == "FAIL", "must FAIL without the Agency signing-key column"

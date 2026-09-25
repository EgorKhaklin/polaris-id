#!/usr/bin/env python3
"""polaris-app-role-suite.py - the web application's suite, with the APPLICATION connected as
the role it runs as in production.

WHY THIS EXISTS. test_app.py connects as the schema owner, and so does the application it
drives. The owner bypasses row-level security and holds every privilege, so a route that needs
something polaris_app does not have passes every test and fails in every deployment. Run on
2026-09-25, this found exactly one: the Atlas simulation tick streamed verifications with COPY
FROM, which PostgreSQL refuses on a table whose row-level security applies to the caller. The
feature failed on every tick in production and was green in 873 tests.

THE CLI TOO. polaris_cli connects as polaris_app by default, and its suite ran every command
against the owner. The same first run found `retention-set` superseding a decision with an UPDATE
the application role is refused on purpose: "permission denied" in every deployment, green in
the suite. The second phase runs test_cli with the CLI's subprocesses as polaris_app.

WHAT IT DOES. It imports test_app, gives the test module's own helpers (fixtures, reloads,
assertions against the database) a private copy of the owner's configuration, and switches the
APPLICATION's configuration to polaris_app. Then it runs the whole module. Every failure is
either a route that breaks for the real role, or a test that leaned on the owner's rights; both
are findings.

    POLARIS_DB_HOST=localhost POLARIS_DB_USER=<owner> python3 scripts/polaris-app-role-suite.py

Exit 0 when every test passes as the application role, 1 otherwise, 3 when polaris_app cannot
connect (outside CI; in CI that is a failure, since a skip is a pass nobody reads).
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(os.path.dirname(HERE), "polaris_web")


def main():
    os.chdir(WEB)
    sys.path.insert(0, WEB)
    import psycopg2
    import test_app as T

    app_role = dict(user="polaris_app",
                    password=os.environ.get("POLARIS_APP_TEST_PASSWORD", "polaris_dev_password"))
    try:
        psycopg2.connect(**dict(T.flask_app.DB_CONFIG, **app_role)).close()
    except psycopg2.OperationalError as exc:
        print("app-role suite: polaris_app cannot connect: %s" % exc)
        return 1 if os.environ.get("CI") else 3

    # The test module's helpers keep the owner; the application gets the application role.
    T.DB_CONFIG = dict(T.flask_app.DB_CONFIG)
    T.flask_app.DB_CONFIG.update(app_role)

    suite = unittest.defaultTestLoader.loadTestsFromModule(T)
    with open(os.devnull, "w") as sink:
        result = unittest.TextTestRunner(verbosity=0, stream=sink).run(suite)
    bad = result.failures + result.errors
    print("app-role suite: %d tests as polaris_app, %d failed, %d skipped"
          % (result.testsRun, len(bad), len(result.skipped)))
    if result.testsRun < 500:
        print("app-role suite: fewer tests ran than test_app holds; the loader found the wrong module")
        return 1
    for test, tb in bad:
        last = [line for line in tb.strip().splitlines() if line.strip()][-1]
        print("  FAIL %s\n       %s" % (test.id().split(".", 1)[-1], last[:200]))
    cli_bad, cli_ran = run_cli_phase(app_role)
    if bad or cli_bad:
        print("\nEach is a route or command that fails for the role production runs as, or a "
              "test that depends on the owner's rights.")
        return 1
    print("OK: every test_app test and every test_cli command passes with the application "
          "connected as polaris_app (%d + %d)." % (result.testsRun, cli_ran))
    return 0


def run_cli_phase(app_role):
    """test_cli, with each `polaris.py` subprocess connected as polaris_app and the suite's
    fixtures still the owner."""
    import subprocess
    cli_dir = os.path.join(os.path.dirname(HERE), "polaris_cli")
    sys.path.insert(0, cli_dir)
    os.chdir(cli_dir)
    import test_cli as C
    real_run = subprocess.run

    def run_as_app(cmd, *a, **kw):
        if isinstance(cmd, list) and len(cmd) > 1 and str(cmd[1]).endswith("polaris.py"):
            env = dict(kw.get("env") or os.environ)
            env.update(POLARIS_DB_USER=app_role["user"], POLARIS_DB_PASSWORD=app_role["password"])
            kw["env"] = env
        return real_run(cmd, *a, **kw)

    C.subprocess.run = run_as_app
    suite = unittest.defaultTestLoader.loadTestsFromModule(C)
    with open(os.devnull, "w") as sink:
        result = unittest.TextTestRunner(verbosity=0, stream=sink).run(suite)
    bad = result.failures + result.errors
    print("app-role suite: %d CLI tests as polaris_app, %d failed" % (result.testsRun, len(bad)))
    if result.testsRun < 50:
        print("app-role suite: fewer CLI tests ran than test_cli holds")
        return [("loader", "")], result.testsRun
    for test, tb in bad:
        why = [line for line in tb.splitlines() if "stderr" in line or "denied" in line.lower()]
        print("  FAIL %s\n       %s" % (test.id().split(".", 1)[-1],
                                         (why[-1] if why else tb.strip().splitlines()[-1])[:200]))
    return bad, result.testsRun


if __name__ == "__main__":
    sys.exit(main())

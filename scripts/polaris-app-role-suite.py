#!/usr/bin/env python3
"""polaris-app-role-suite.py - the web application's suite, with the APPLICATION connected as
the role it runs as in production.

WHY THIS EXISTS. test_app.py connects as the schema owner, and so does the application it
drives. The owner bypasses row-level security and holds every privilege, so a route that needs
something polaris_app does not have passes every test and fails in every deployment. Run on
2026-09-25, this found exactly one: the Atlas simulation tick streamed verifications with COPY
FROM, which PostgreSQL refuses on a table whose row-level security applies to the caller. The
feature failed on every tick in production and was green in 873 tests.

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
    if bad:
        print("\nEach is a route that fails for the role production runs as, or a test that "
              "depends on the owner's rights.")
        return 1
    print("OK: every test_app test passes with the application connected as polaris_app.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

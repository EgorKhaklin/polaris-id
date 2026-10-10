# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The database's security state, read the same way every time, and a read that proves nothing refused.

scripts/lib/polaris-db-state.sh prints the state as sorted fact lines so a drill can compare it
before and after an operator procedure. A comparison holds trivially for a kind of fact that was
never read, so a read that fails must fail and a kind that reads nothing must fail, unless it is
listed as one that may be empty, with its reason. These tests run the library under bash with a
stand-in `sql` that answers each read from canned rows, keyed by the marker the read carries
(polaris-db-state:<kind>), and its partition check on states built the same way. They need no
database.

    python3 -m unittest test_db_state      (from scripts/)
"""
import pathlib
import random
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LIB = ROOT / "scripts" / "lib" / "polaris-db-state.sh"

# The stand-in reader. The marker names the kind; $STUB_DIR/<kind> holds its rows; with
# $STUB_DIR/<kind>.fail beside it, it prints those rows and then fails, as a read cut off would.
STUB = r"""
sql() {
    local kind
    kind=$(printf '%s\n' "$1" | sed -n 's/.*polaris-db-state:\([a-z_]*\).*/\1/p' | sed -n 1p)
    [ -n "$kind" ] || { echo "stub: a read without a marker" >&2; return 9; }
    printf '%s\n' "$kind" >> "$STUB_DIR/reads"
    printf '%s\n' "$1" > "$STUB_DIR/$kind.sql"
    case "$1" in *"SET search_path = pg_catalog;"*) ;; *) echo "stub: the $kind read is not pinned" >&2; return 8 ;; esac
    [ -e "$STUB_DIR/$kind" ] || { echo "stub: no rows for $kind" >&2; return 4; }
    cat "$STUB_DIR/$kind"
    if [ -e "$STUB_DIR/$kind.fail" ]; then echo "stub: the $kind read fails" >&2; return 3; fi
}
"""

PART = "public.verificationevent_2026_10"
NEW = "public.verificationevent_2026_11"
DEF = "public.verificationevent_default"
TRIG = "def=4f1d2c0e9b7a6d5c4b3a291807f6e5d4"
ROWS = {
    "role": [
        "role polaris_app super=false inherit=true createrole=false createdb=false login=true replication=false bypassrls=false",
        "role postgres super=true inherit=true createrole=true createdb=true login=true replication=true bypassrls=true",
    ],
    "member": ["member polaris_reader polaris_app admin=false"],
    "table": [
        "table public.verificationevent polaris_app SELECT",
        "table public.verificationevent polaris_app INSERT",
        "table %s polaris_app SELECT" % PART,
        "table %s polaris_app SELECT" % DEF,
        "table public.enrollmentcode polaris_app SELECT",
        "table public.enrollmentcode polaris_app INSERT",
    ],
    "column": [
        "column public.verificationevent.outcome polaris_app SELECT",
        "column public.verificationevent.outcome polaris_app INSERT",
        "column %s.outcome polaris_app SELECT" % PART,
        "column %s.event_id polaris_app SELECT" % PART,
        "column %s.outcome polaris_app SELECT" % DEF,
        "column %s.event_id polaris_app SELECT" % DEF,
        "column public.enrollmentcode.code polaris_app SELECT",
    ],
    "sequence": ["sequence public.verificationevent_event_id_seq polaris_app USAGE",
                 "sequence public.verificationevent_event_id_seq polaris_app SELECT"],
    "execute": ["execute public.uc1_issue(integer,text) polaris_app",
                "execute public.reject_audit_modification() PUBLIC"],
    "schema": ["schema public polaris_app USAGE", "schema public PUBLIC USAGE"],
    "database": ["database this polaris_app CONNECT", "database this PUBLIC TEMPORARY"],
    "defacl": ["defacl postgres public r polaris_app=DELETE,polaris_app=INSERT,polaris_app=SELECT,polaris_app=UPDATE"],
    "dbsetting": ["dbsetting this - polaris.default_window_days=30",
                  "dbsetting this - polaris.default_max_revoke_percent=5.00",
                  "dbsetting all polaris_app search_path=public",
                  "dbsetting this polaris_app statement_timeout=30s"],
    "constraint": ["constraint public.disclosuretoken chk_disclosure_token_consistency c def=1f3870be274f6c49b3e31a0c6728957f",
                   "constraint public.verificationevent verificationevent_pkey p def=8fa14cdd754f91cc6554c9e71929cce7",
                   "constraint public.agency_code agency_code_check c def=45c48cce2e2d7fbdea1afc51c7c6ad26"],
    "index": ["index public.identitytoken uq_one_active_per_person unique=true valid=true def=6512bd43d9caa6e02c990b0a82652dca",
              "index public.verificationevent verificationevent_pkey unique=true valid=true def=c20ad4d76fe97759aa27a0c99bff6710"],
    "event_trigger": ["event_trigger polaris_ddl_audit event=ddl_command_end function=public.polaris_ddl_audit() "
                      "enabled=O owner=postgres tags=-"],
    "extension": ["extension plpgsql version=1.0 schema=pg_catalog owner=postgres"],
    "routine": ["routine public.uc1_issue(integer,text) def=0cc175b9c0f1b6a831c399e269772661 definer=true owner=postgres config=search_path=pg_catalog, public",
                "routine public.reject_audit_modification() def=92eb5ffee6ae2fec3ad71c777531578f definer=false owner=postgres config=-"],
    "trigger": [
        "trigger public.verificationevent trg_verification_append_only enabled=O " + TRIG,
        "trigger %s trg_verification_append_only enabled=O %s" % (PART, TRIG),
        "trigger %s trg_verification_append_only enabled=O %s" % (DEF, TRIG),
    ],
    "view": ["view public.activetokens kind=v def=8277e0910d750195b448797616e091ad options=security_invoker=true"],
    "rls": [
        "rls public.verificationevent enabled=true forced=false",
        "rls %s enabled=false forced=false" % PART,
        "rls %s enabled=false forced=false" % DEF,
        "rls public.enrollmentcode enabled=false forced=false",
    ],
    "policy": ["policy public.verificationevent verification_authority_isolation PERMISSIVE cmd=ALL roles=public "
               "qual=e1671797c52e15f763380b45e841ec32 check=-"],
    "owner": [
        "owner public.verificationevent p postgres",
        "owner %s r postgres" % PART,
        "owner %s r postgres" % DEF,
        "owner public.enrollmentcode r postgres",
        "owner public schema pg_database_owner",
        "owner this database postgres",
    ],
    "partition": [
        "partition %s of public.verificationevent bound=FOR VALUES FROM ('2026-10-01 00:00:00') TO ('2026-11-01 00:00:00')" % PART,
        "partition %s of public.verificationevent bound=DEFAULT" % DEF,
    ],
    "rows": ["rows public.verificationevent 3 d41d8cd98f00b204e9800998ecf8427e",
             "rows public.enrollmentcode 0 d41d8cd98f00b204e9800998ecf8427e"],
    "seq": ["seq public.verificationevent_event_id_seq 3", "seq public.enrollmentcode_id_seq unset"],
}
FULL_ONLY = ("rows", "seq")
EXEMPT = ("event_trigger", "member")


class _Base(unittest.TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="polaris-db-state-")
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.stub = self.tmp / "stub"
        self.stub.mkdir()
        self.write(ROWS)

    def write(self, rows):
        for kind, lines in rows.items():
            shuffled = list(lines)
            random.Random(kind).shuffle(shuffled)
            (self.stub / kind).write_text("".join(line + "\n" for line in shuffled))

    def bash(self, body):
        script = "set -euo pipefail\nsource %s\n%s\n%s\n" % (LIB, STUB, body)
        return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60,
                              env={"PATH": "/usr/bin:/bin", "STUB_DIR": str(self.stub), "LC_ALL": "C"})

    def state(self, mode="security"):
        # Called the way a drill calls it, under `|| fail`, where errexit is off inside the function:
        # every failure must be returned by the library itself.
        return self.bash('polaris_db_state %s || exit $?' % mode)

    def library_list(self, name):
        r = self.bash('printf "%%s\\n" "${%s[@]}"' % name)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.splitlines()


class StateTests(_Base):

    def test_the_kinds_and_the_exemptions_are_the_ones_reviewed(self):
        security = self.library_list("POLARIS_DB_STATE_SECURITY_KINDS")
        self.assertEqual(sorted(security + self.library_list("POLARIS_DB_STATE_FULL_KINDS")), sorted(ROWS))
        self.assertEqual(self.library_list("POLARIS_DB_STATE_FULL_KINDS"), list(FULL_ONLY))
        # Widening this list is how a comparison becomes vacuous for a kind: it is a reviewed change.
        exempt = self.library_list("POLARIS_DB_STATE_MAY_BE_EMPTY")
        self.assertEqual(sorted(e.split(":", 1)[0] for e in exempt), sorted(EXEMPT))
        self.assertTrue(all(len(e.split(":", 1)[1]) > 20 for e in exempt), "an exemption without its reason")

    def test_every_kind_is_read_once_and_every_fact_appears(self):
        for mode, kinds in (("security", [k for k in ROWS if k not in FULL_ONLY]), ("full", list(ROWS))):
            (self.stub / "reads").write_text("")
            r = self.state(mode)
            self.assertEqual(r.returncode, 0, r.stderr)
            got = r.stdout.splitlines()
            self.assertEqual(sorted((self.stub / "reads").read_text().split()), sorted(kinds), mode)
            for kind in kinds:
                self.assertTrue(any(line.startswith(kind + " ") for line in got), "%s: no %s facts" % (mode, kind))
            self.assertEqual(sorted(got), sorted(line for k in kinds for line in ROWS[k]), mode)

    def test_the_output_is_sorted_and_the_same_on_every_run(self):
        first, second = self.state("full"), self.state("full")
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(first.stdout, second.stdout)
        lines = first.stdout.splitlines()
        self.assertEqual(lines, sorted(lines, key=lambda s: s.encode()))
        self.assertGreater(len(lines), 40)

    def test_a_kind_that_reads_nothing_fails_naming_it_unless_it_is_exempt(self):
        for kind in ROWS:
            with self.subTest(kind=kind):
                self.write(dict(ROWS, **{kind: []}))
                r = self.state("full")
                if kind in EXEMPT:
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertFalse([x for x in r.stdout.splitlines() if x.startswith(kind + " ")])
                else:
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn("read no %s facts" % kind, r.stderr)
                    self.assertEqual(r.stdout, "", "a partial state was printed")
        self.write(ROWS)

    def test_a_read_that_fails_fails_even_after_printing_rows(self):
        for kind in ROWS:
            with self.subTest(kind=kind):
                fail = self.stub / (kind + ".fail")
                fail.write_text("")
                try:
                    r = self.state("full")
                finally:
                    fail.unlink()
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("the %s read failed" % kind, r.stderr)
                self.assertEqual(r.stdout, "")

    def test_a_line_that_is_not_a_fact_of_its_kind_fails(self):
        # A NULL fact (printed as NULL), a command tag from a reader without -q, an empty line (between
        # facts, or last), and a line of another kind: each is a read that went wrong, never a fact.
        for kind in ("table", "trigger", "seq", "constraint", "index", "event_trigger", "extension"):
            for stray in ("NULL", "SET", "", "role x super=false"):
                with self.subTest(kind=kind, stray=stray):
                    self.write(ROWS)
                    lines = ROWS[kind][:1] + [stray] + ROWS[kind][1:]
                    (self.stub / kind).write_text("".join(line + "\n" for line in lines))
                    r = self.state("full")
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn("not a %s fact (line 2:%s)" % (kind, stray), r.stderr)
        for kind in ("table", "extension"):
            with self.subTest(kind=kind, stray="a blank line last"):
                self.write(ROWS)
                (self.stub / kind).write_text("".join(line + "\n" for line in ROWS[kind]) + "\n")
                r = self.state("full")
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("not a %s fact (line %d:)" % (kind, len(ROWS[kind]) + 1), r.stderr)
        self.write(ROWS)

    def test_each_read_is_one_select_and_a_check_is_read_back_first(self):
        r = self.state("full")
        self.assertEqual(r.returncode, 0, r.stderr)
        for kind in ROWS:
            text = (self.stub / (kind + ".sql")).read_text()
            self.assertEqual(text.count("/* polaris-db-state:"), 1, kind)
            self.assertIn("SET extra_float_digits = 3;", text, kind)
            self.assertEqual("CREATE OR REPLACE FUNCTION" in text, kind == "constraint", kind)
        text = (self.stub / "constraint.sql").read_text()
        self.assertLess(text.index("FUNCTION pg_temp.polaris_db_state_read_back"),
                        text.index("SELECT coalesce(fact, 'NULL')"))
        self.assertIn("pg_temp.polaris_db_state_read_back(c.oid)", text)

    def test_a_sequence_the_reader_may_not_read_fails(self):
        self.write(dict(ROWS, seq=ROWS["seq"] + ["seq public.hidden_seq unreadable"]))
        r = self.state("full")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("public.hidden_seq", r.stderr)

    def test_it_is_called_rightly_or_not_at_all(self):
        r = self.state("everything")
        self.assertEqual(r.returncode, 2)
        self.assertIn("security or full", r.stderr)
        r = subprocess.run(["bash", "-c", "set -euo pipefail\nsource %s\npolaris_db_state security || exit $?" % LIB],
                           capture_output=True, text=True, timeout=60, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(r.returncode, 2)
        self.assertIn("define sql", r.stderr)


class PartitionsGrewTests(_Base):
    """polaris_db_state_partitions_grew on a state read before and after a new month was made."""

    def grown(self, extra=None, drop=None):
        """The rows after the manager made NEW: a copy of PART's own facts, as the schema makes it."""
        after = {k: list(v) for k, v in ROWS.items()}
        for kind, lines in ROWS.items():
            for line in lines:
                obj = line.split(" ")[1]
                if kind == "partition":
                    if obj == PART:
                        after[kind].append("partition %s of public.verificationevent bound=FOR VALUES FROM "
                                           "('2026-11-01 00:00:00') TO ('2026-12-01 00:00:00')" % NEW)
                elif obj == PART or obj.startswith(PART + "."):
                    after[kind].append(line.replace(PART, NEW, 1))
        for kind, line in extra or ():
            after[kind].append(line)
        for kind, line in drop or ():
            after[kind].remove(line)
        return after

    def check(self, after, role="polaris_app", before=ROWS):
        self.write(before)
        before = self.state()
        self.assertEqual(before.returncode, 0, before.stderr)
        (self.tmp / "before").write_text(before.stdout)
        self.write(after)
        got = self.state()
        self.assertEqual(got.returncode, 0, got.stderr)
        (self.tmp / "after").write_text(got.stdout)
        return self.bash('polaris_db_state_partitions_grew "%s/before" "%s/after" %s || exit $?'
                         % (self.tmp, self.tmp, role))

    def test_a_new_month_like_the_months_before_it_holds(self):
        r = self.check(self.grown())
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 new partition(s) ( %s )" % NEW, r.stdout)
        self.assertIn("(2 comparisons)", r.stdout)
        # SELECT on the table and on its two columns: the role's privileges were what was compared.
        self.assertIn("polaris_app holding 3 table and column privileges", r.stdout)

    def test_a_new_month_the_application_may_delete_from_is_named(self):
        # 1.0.0-rc.40: a new partition inherited the blanket grant, DELETE included.
        r = self.check(self.grown(extra=[("table", "table %s polaris_app DELETE" % NEW)]))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("%s has, and %s has not: table @public.verificationevent polaris_app DELETE" % (NEW, PART), r.stderr)
        self.assertIn("%s has, and %s has not: table @public.verificationevent polaris_app DELETE" % (NEW, DEF), r.stderr)

    def test_a_new_month_missing_a_privilege_or_a_trigger_is_named(self):
        for kind, line in (("table", "table %s polaris_app SELECT" % NEW),
                           ("trigger", "trigger %s trg_verification_append_only enabled=O %s" % (NEW, TRIG))):
            with self.subTest(kind=kind):
                r = self.check(self.grown(drop=[(kind, line)]))
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("%s has, and %s has not: %s @public.verificationevent" % (PART, NEW, kind), r.stderr)

    def test_a_change_beside_the_new_months_is_named(self):
        # The deploy's --sync-objects gave back a DELETE that migration 2026-09-11-017 revoked.
        r = self.check(self.grown(extra=[("table", "table public.enrollmentcode polaris_app DELETE")]))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("gained outside the new partitions: table public.enrollmentcode polaris_app DELETE", r.stderr)
        r = self.check(self.grown(drop=[("execute", "execute public.reject_audit_modification() PUBLIC")]))
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("lost: execute public.reject_audit_modification() PUBLIC", r.stderr)

    def test_a_run_that_made_no_month_proves_nothing(self):
        r = self.check(ROWS)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("created no partition", r.stderr)

    def test_a_role_whose_privileges_were_not_read_proves_nothing(self):
        for role in ("postgres", "polaris_nobody"):
            with self.subTest(role=role):
                r = self.check(self.grown(), role=role)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("its privileges were not read", r.stderr)

    def test_a_partition_no_fact_was_matched_to_proves_nothing(self):
        # Every relation has an owner fact; a partition without one means facts were not matched to it.
        owner = "owner %s r postgres" % DEF
        before = dict(ROWS, owner=[x for x in ROWS["owner"] if x != owner])
        after = self.grown(drop=[("owner", owner)])
        r = self.check(after, before=before)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("no owner fact names %s" % DEF, r.stderr)

    def test_a_month_with_no_month_before_it_has_nothing_to_be_compared_with(self):
        after = self.grown()
        after["partition"].append("partition public.authauditlog_2026_11 of public.authauditlog bound=x")
        after["owner"].append("owner public.authauditlog_2026_11 r postgres")
        r = self.check(after)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("no partition of public.authauditlog existed before", r.stderr)


if __name__ == "__main__":
    unittest.main()

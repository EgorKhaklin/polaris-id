# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""scripts/polaris-compose-parse.py: a documented compose file set that does not parse fails by its
document and line, under this host's Docker Compose.

The fixture is the shape of 2026-10-10's HA alias: an overlay that extends a service only another
overlay defines. Run in CI under the runner's Compose; on a host without Docker Compose the parsing
tests skip, and in CI they fail instead."""
import contextlib
import importlib.util
import io
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("polaris_compose_parse", _HERE / "polaris-compose-parse.py")
parse = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(parse)

BASE = "services:\n  app:\n    image: alpine\n    volumes:\n      - ${SECRETS:-./s}/x.crt:/y:ro\n"
EXT = "services:\n  app-green:\n    image: alpine\n"
HA = "services:\n  app-green:\n    environment:\n      A: \"1\"\n"
BROKEN = 'P="docker compose -f base.yml -f ha.yml exec app-green true"\n'
FIXED = 'P="docker compose -f base.yml -f ext.yml -f ha.yml exec app-green true"\n'


def compose_version():
    if not shutil.which("docker"):
        return None
    r = subprocess.run(["docker", "compose", "version", "--short"], capture_output=True, text=True)
    return r.stdout.strip().lstrip("v") if r.returncode == 0 else None


class ComposeParse(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix="polaris-compose-parse-"))
        self.addCleanup(shutil.rmtree, self.root, True)
        for name, body in (("base.yml", BASE), ("ext.yml", EXT), ("ha.yml", HA)):
            (self.root / name).write_text(body)
        (self.root / "docs").mkdir()
        self.saved = parse.checks._COMPOSE_COMBO_FLOOR
        parse.checks._COMPOSE_COMBO_FLOOR = 1
        self.addCleanup(setattr, parse.checks, "_COMPOSE_COMBO_FLOOR", self.saved)

    def needs_compose(self):
        if compose_version() is None:
            if os.environ.get("CI") == "true":
                self.fail("Docker Compose is missing in CI, where this guard is the authority")
            self.skipTest("no Docker Compose on this host")

    def doc(self, *blocks):
        text = "# Ops\n"
        for marker, body in blocks:
            text += ("\n" + marker + "\n" if marker else "\n") + "```bash\n" + body + "```\n"
        (self.root / "docs" / "OPS.md").write_text(text)

    def run_parse(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = parse.main(["polaris-compose-parse.py", str(self.root)])
        return rc, out.getvalue()

    def test_an_overlay_that_extends_a_service_it_does_not_load_fails_by_its_line(self):
        self.needs_compose()
        self.doc(("", FIXED), ("", BROKEN))
        rc, out = self.run_parse()
        self.assertEqual(rc, 1, out)
        self.assertIn("FAIL  -f base.yml -f ha.yml", out)
        self.assertIn("docs/OPS.md:8", out)   # the broken alias's own line
        self.assertIn("ok    -f base.yml -f ext.yml -f ha.yml", out)
        self.assertEqual(out.strip().splitlines()[-1], "done")

    def test_the_fixed_alias_passes(self):
        self.needs_compose()
        self.doc(("", FIXED))
        rc, out = self.run_parse()
        self.assertEqual(rc, 0, out)

    def test_a_marked_failure_passes_only_while_it_fails(self):
        self.needs_compose()
        self.doc(("<!-- compose-parse: expect-fail shows what a missing overlay does -->", BROKEN))
        self.assertEqual(self.run_parse()[0], 0)
        self.doc(("<!-- compose-parse: expect-fail shows what a missing overlay does -->", FIXED))
        rc, out = self.run_parse()
        self.assertEqual(rc, 1, out)
        self.assertIn("marked to fail", out)

    def test_no_interpolate_on_a_short_bind_with_a_default_is_held_to_the_version_measured(self):
        self.needs_compose()
        v = tuple(int(x) for x in compose_version().split("-")[0].split(".")[:2])
        self.doc(("", "docker compose -f base.yml config --no-interpolate\n"))
        rc, out = self.run_parse()
        if v[0] == 2 and v[1] <= 38:     # refused by 2.33.0 and 2.38.2 (measured 2026-10-10)
            self.assertEqual(rc, 1, out)
            self.assertIn("too many colons", out)
        elif v >= (2, 40):                # accepted by 2.40.3 and 5.5.1
            self.assertEqual(rc, 0, out)
        else:
            self.skipTest(f"Compose {compose_version()} is between the versions measured")

    def test_nothing_to_parse_fails(self):
        rc, out = self.run_parse()
        self.assertEqual(rc, 1, out)

    def test_in_ci_a_missing_compose_fails(self):
        saved_which, saved_ci = parse.shutil.which, os.environ.get("CI")
        parse.shutil.which = lambda name: None
        os.environ["CI"] = "true"
        try:
            rc, out = self.run_parse()
        finally:
            parse.shutil.which = saved_which
            if saved_ci is None:
                os.environ.pop("CI", None)
            else:
                os.environ["CI"] = saved_ci
        self.assertEqual(rc, 1, out)
        self.assertIn("in CI that is a failure", out)


if __name__ == "__main__":
    unittest.main()

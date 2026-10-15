# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The SDK mutation drill's shards invert every refusal exactly once (2026-10-15).

CI runs the drill as four shards (`--shard I/4`): unsharded, a change to the detached verifier
cost 65 minutes in one step. Sharding must lose nothing: the shards together invert exactly the
refusals one run inverts, none twice, each verifier's baseline and negative control run in every
shard, and the declared-survivor list is still checked in both directions. These tests prove
the partition on the real sources, then run the drill's main() per shard with the suites
replaced by a stand-in that catches every inversion except the declared survivors. No suite runs.

    python3 -m unittest test_sdk_drill      (from scripts/)
"""
import contextlib
import importlib.util
import io
import pathlib
import sys
import unittest
from unittest import mock

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
_spec = importlib.util.spec_from_file_location("sdk_drill", HERE / "polaris-sdk-mutation-drill.py")
drill = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(drill)


class ThePartition(unittest.TestCase):

    def setUp(self):
        self.sites = drill.refusal_sites()

    def test_every_verifier_has_refusals_and_labels_are_unique(self):
        self.assertEqual({s[0] for s in self.sites}, set(drill.SDKS))
        labels = [s[3] for s in self.sites]
        self.assertEqual(len(labels), len(set(labels)))

    def test_the_shards_cover_every_refusal_exactly_once(self):
        keys = sorted(s[3] for s in self.sites)
        for n in (1, 2, 3, 4, 7):
            shards = [[s[3] for s in drill.shard_of(self.sites, (i, n))] for i in range(1, n + 1)]
            self.assertEqual(sorted(x for sh in shards for x in sh), keys, n)
            sizes = [len(x) for x in shards]
            self.assertLessEqual(max(sizes) - min(sizes), 1, sizes)

    def test_each_verifier_is_dealt_to_every_shard(self):
        for i in (1, 2, 3, 4):
            self.assertEqual({s[0] for s in drill.shard_of(self.sites, (i, 4))}, set(drill.SDKS), i)

    def test_parse_shard(self):
        self.assertEqual(drill.parse_shard("4/4"), (4, 4))
        for bad in ("", "0/4", "5/4", "x", "1/0"):
            with self.assertRaises(Exception):
                drill.parse_shard(bad)


class TheShardsAgreeWithOneRun(unittest.TestCase):

    def setUp(self):
        self.sites = drill.refusal_sites()
        self.by_text = {}
        for name, sdk in drill.SDKS.items():
            lines = (drill.ROOT / sdk["source"]).read_text().splitlines(keepends=True)
            for s in self.sites:
                if s[0] == name:
                    m = lines[:]
                    m[s[1]] = s[2]
                    self.by_text[(name, "".join(m))] = s[3]

    def run_shard(self, shard, survive, changed="not asked"):
        inverted, baselines = [], []

        def suites(work, sdk):
            name = next(n for n, v in drill.SDKS.items() if v is sdk)
            text = (work / sdk["source"]).read_text()
            label = self.by_text.get((name, text))
            if label is not None:
                inverted.append(label)
                return label in survive
            if text == (drill.ROOT / sdk["source"]).read_text():
                baselines.append(name)
                return True
            return False                       # the negative control: everything inverted

        out = io.StringIO()
        patches = [mock.patch.object(drill, "_suites_pass", side_effect=suites),
                   mock.patch.object(drill, "_liboqs_present", return_value=True)]
        argv = ["--shard", "%d/%d" % shard]
        if changed != "not asked":
            patches.append(mock.patch.object(drill, "_sdks_moved", return_value=changed))
            argv.append("--changed")
        with contextlib.ExitStack() as stack:
            for p in patches:
                stack.enter_context(p)
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(out))
            code = drill.main(argv)
        return code, inverted, baselines, out.getvalue()

    def test_four_shards_invert_what_one_run_inverts_and_pass(self):
        survive = set(drill.DECLARED_SURVIVORS)
        code, one, _, text = self.run_shard((1, 1), survive)
        self.assertEqual(code, 0, text[-600:])
        made = []
        for i in (1, 2, 3, 4):
            code, part, baselines, text = self.run_shard((i, 4), survive)
            self.assertEqual(code, 0, text[-600:])
            self.assertEqual(sorted(baselines), sorted(drill.SDKS), "every shard runs every baseline")
            made += part
        self.assertEqual(sorted(made), sorted(one))
        self.assertEqual(sorted(made), sorted(s[3] for s in self.sites))

    def test_a_closed_gap_fails_only_its_shard(self):
        declared = sorted(drill.DECLARED_SURVIVORS)[0]
        holder = next(i for i in (1, 2, 3, 4)
                      if any(s[3] == declared for s in drill.shard_of(self.sites, (i, 4))))
        for i in (1, 2, 3, 4):
            code, _, _, text = self.run_shard((i, 4), set(drill.DECLARED_SURVIVORS) - {declared})
            self.assertEqual(code, 1 if i == holder else 0, (i, text[-300:]))

    def test_a_declaration_naming_no_refusal_fails_every_shard(self):
        with mock.patch.dict(drill.DECLARED_SURVIVORS, {"python:nowhere:000000": "stale"}):
            for i in (1, 2, 3, 4):
                code, _, _, text = self.run_shard((i, 4), set(drill.DECLARED_SURVIVORS))
                self.assertEqual(code, 1, i)

    def test_an_undeclared_survivor_fails_its_shard(self):
        extra = next(s[3] for s in self.sites if s[3] not in drill.DECLARED_SURVIVORS)
        holder = next(i for i in (1, 2, 3, 4) if any(s[3] == extra for s in drill.shard_of(self.sites, (i, 4))))
        code, _, _, text = self.run_shard((holder, 4), set(drill.DECLARED_SURVIVORS) | {extra})
        self.assertEqual(code, 1, text[-300:])

    def test_changed_with_nothing_moved_inverts_nothing_in_any_shard(self):
        for i in (1, 2, 3, 4):
            code, made, baselines, _ = self.run_shard((i, 4), set(), changed=False)
            self.assertEqual((code, made, baselines), (0, [], []))

    def test_changed_without_a_baseline_refuses_in_every_shard(self):
        for i in (1, 2, 3, 4):
            code, made, _, text = self.run_shard((i, 4), set(), changed=None)
            self.assertEqual((code, made), (2, []), text[-300:])

if __name__ == "__main__":
    unittest.main()

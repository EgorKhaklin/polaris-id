# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Tests for polaris-pin-chart-images.py (lab record 017, phase 3)."""
import importlib.util
import pathlib
import tempfile
import unittest

_HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("pin_chart", _HERE / "polaris-pin-chart-images.py")
pin_chart = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pin_chart)

VALUES = (
    "images:\n"
    "  app: polaris-app:prod\n"
    "  caddy: polaris-caddy:prod\n"
    "  pgbouncer: polaris-pgbouncer:prod\n"
    "  postgres: polaris-postgres:prod\n"
    "  redis: redis:7-alpine@sha256:" + "a" * 64 + "\n"
    "  pullPolicy: IfNotPresent\n"
    "domain: polaris.example.org\n"
)


def _ref(name, digit="b"):
    return f"ghcr.io/egorkhaklin/polaris-{name}@sha256:" + digit * 64


class PinChartImagesTests(unittest.TestCase):

    def _index(self, refs):
        d = pathlib.Path(tempfile.mkdtemp())
        for name, ref in refs.items():
            (d / name).write_text(ref)
        return d

    def test_every_chart_image_is_pinned_and_nothing_else_moves(self):
        refs = {n: _ref(n) for n in pin_chart.CHART_IMAGES}
        out = pin_chart.pin(VALUES, pin_chart.read_refs(self._index(refs)))
        for n in pin_chart.CHART_IMAGES:
            self.assertIn(f"  {n}: {_ref(n)}\n", out)
        self.assertIn("  redis: redis:7-alpine@sha256:" + "a" * 64 + "\n", out)
        self.assertIn("  pullPolicy: IfNotPresent\n", out)
        self.assertIn("domain: polaris.example.org\n", out)
        self.assertNotIn(":prod", out)

    def test_a_missing_reference_is_refused(self):
        refs = {n: _ref(n) for n in pin_chart.CHART_IMAGES if n != "postgres"}
        with self.assertRaises(ValueError):
            pin_chart.read_refs(self._index(refs))

    def test_a_reference_that_is_not_a_digest_is_refused(self):
        refs = {n: _ref(n) for n in pin_chart.CHART_IMAGES}
        refs["app"] = "ghcr.io/egorkhaklin/polaris-app:latest"
        with self.assertRaises(ValueError):
            pin_chart.read_refs(self._index(refs))

    def test_a_reference_for_another_image_is_refused(self):
        refs = {n: _ref(n) for n in pin_chart.CHART_IMAGES}
        refs["caddy"] = _ref("app")
        with self.assertRaises(ValueError):
            pin_chart.read_refs(self._index(refs))

    def test_values_without_an_entry_are_refused(self):
        refs = {n: _ref(n) for n in pin_chart.CHART_IMAGES}
        with self.assertRaises(ValueError):
            pin_chart.pin(VALUES.replace("  caddy: polaris-caddy:prod\n", ""), refs)

    def test_the_command_exits_2_and_leaves_the_file_alone_on_a_bad_index(self):
        values = pathlib.Path(tempfile.mkdtemp()) / "values.yaml"
        values.write_text(VALUES)
        rc = pin_chart.main([str(values), str(self._index({}))])
        self.assertEqual(rc, 2)
        self.assertEqual(values.read_text(), VALUES)

    def test_the_shipped_chart_has_every_image_the_script_pins(self):
        root = _HERE.parent
        text = (root / "deploy" / "helm" / "polaris" / "values.yaml").read_text()
        refs = {n: _ref(n) for n in pin_chart.CHART_IMAGES}
        pinned = pin_chart.pin(text, refs)
        for n in pin_chart.CHART_IMAGES:
            self.assertIn(f"  {n}: {_ref(n)}\n", pinned)


if __name__ == "__main__":
    unittest.main()

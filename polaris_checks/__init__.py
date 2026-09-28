# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris_checks — a flat, legible invariant-check layer for Polaris.

The clean replacement for the legacy cognitive apparatus. A check is a plain
function; there is no mythology. See checks.py.
"""

from .checks import CHECKS, Finding, run_all

__all__ = ["CHECKS", "Finding", "run_all"]

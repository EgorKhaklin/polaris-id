"""polaris_web/__version__.py — single canonical version string.

Pre-v9.06 the version literal lived only in `polaris_web/app.py`
(`POLARIS_VERSION = '9.05'`), bumped by hand each ship, with copies
scattered across other surfaces and no invariant keeping them in sync.

v9.06 promoted the version to this module. `app.py` imports from here
rather than redefining it. The check layer enforces both ends:
`polaris_checks.check_version_is_canonical` asserts `app.py` imports
rather than redefines, and `check_changelog_matches_version` asserts the
CHANGELOG's top entry matches the literal below.

The format is `MAJOR.MINOR`. Never edit historical CHANGELOG entries to
match a future bump — old entries are frozen (audit-of-record discipline).

Bump procedure (see CLAUDE.md "Shipping"):
    1. Edit `__version__` below.
    2. Prepend a `## vX.Y — DATE (subtitle)` block to CHANGELOG.md.
    3. Run `bash scripts/polaris-preflight.sh` (polaris_checks + link-check) until READY.
"""

__version__: str = "9.321"


# Backwards-compat alias for code that imported `POLARIS_VERSION`
# directly from app.py before the v9.06 promotion. Both names point
# at the same string; check_version_is_canonical rejects any divergence.
POLARIS_VERSION: str = __version__

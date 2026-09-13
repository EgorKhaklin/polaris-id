#!/usr/bin/env python3
"""scripts/polaris-verify.py -- the detached verifier, kept reachable at its historical path.

The verifier moved to `packages/polaris-verify/polaris_verify_cli/verifier.py` when
polaris-verify became an independently installable product artifact. It did NOT get
copied: there is one source of truth, and this file is a namespace shim onto it.

The path stays because 426 references across 86 files name it, among them the CHANGELOG
and the paper, which record what happened and are not rewritten to match a later layout.
Every drill that loads this file with `spec_from_file_location` keeps working, including
the ones that reach for module-private names, because the shim copies the whole namespace
rather than re-exporting the public half.

Run the installed command instead where you can: `pip install polaris-verify` then
`polaris-verify --help`.
"""
import pathlib
import sys

_PKG = pathlib.Path(__file__).resolve().parent.parent / "packages" / "polaris-verify"
if _PKG.is_dir():
    sys.path.insert(0, str(_PKG))

from polaris_verify_cli import verifier as _verifier  # noqa: E402

# The whole namespace, module-private names included. `import *` would drop the
# underscore names that several drills and the compat suite reach for.
globals().update({k: v for k, v in vars(_verifier).items()
                  if k not in ("__name__", "__file__", "__loader__", "__spec__",
                               "__package__", "__builtins__")})

if __name__ == "__main__":
    sys.exit(_verifier.main())

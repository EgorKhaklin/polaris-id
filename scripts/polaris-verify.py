#!/usr/bin/env python3
"""scripts/polaris-verify.py -- the detached verifier, kept reachable at its historical path.

The verifier moved to `packages/polaris-verify/polaris_verify_cli/verifier.py` when
polaris-verify became an independently installable product artifact. It did NOT get
copied: there is one source of truth, and this file executes it.

The path stays because 426 references across 86 files name it, among them the CHANGELOG
and the paper, which record what happened and are not rewritten to match a later layout.

WHY `exec` AND NOT AN IMPORT. The first version of this shim imported the canonical module
and copied its namespace in. That looks equivalent and is not. Thirty-four drills and test
harnesses load this path with `spec_from_file_location`, and several of them MUTATE the
loaded module -- the conformance mutation drill replaces a verifier function and asks
whether any published case notices. With a copied namespace those patches landed on
aliases: `verify_manifest`'s internal call to `verify_attestation` still resolved through
the canonical module's own globals, so the mutation did nothing and two fields reported as
unconstrained that the contract does constrain. Measured in CI, not reasoned about.

Executing the source into THIS module's namespace makes the loaded module a genuine
instance of the verifier: intra-module calls resolve through the same globals a caller
patches, which is what the single file did before it moved. One source, no copy, and the
mutation semantics are unchanged.

Run the installed command instead where you can: `pip install polaris-verify` then
`polaris-verify --help`.
"""
import pathlib
import sys

_CANON = (pathlib.Path(__file__).resolve().parent.parent
          / "packages" / "polaris-verify" / "polaris_verify_cli" / "verifier.py")

if _CANON.is_file():
    # `__name__` carries through, so running this file as a script reaches the canonical
    # module's own `if __name__ == "__main__"` and starts the CLI, while a harness that
    # loads it under any other name just gets the definitions.
    exec(compile(_CANON.read_text(encoding="utf-8"), str(_CANON), "exec"), globals())
else:
    # Installed without the repository beside it: fall back to the package.
    from polaris_verify_cli.verifier import *  # noqa: F401,F403
    from polaris_verify_cli.verifier import main  # noqa: F401
    if __name__ == "__main__":
        sys.exit(main())

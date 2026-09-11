#!/usr/bin/env python3
"""polaris-zk-mutation-drill.py - would either witness notice being switched off?

v9.419. The third mutation drill, after the constraints (v9.407) and the triggers
(v9.413). Those two asked whether the DATABASE's guarantees were tested. This asks
it of the engine's: the ZK prover and verifier, and the independent second witness
that exists to disagree with them.

"Two independent witnesses" is a strong claim and a fragile one. It is worth
exactly as much as the tests that would notice a witness saying yes to everything,
and a differential between two implementations is satisfied when both are wrong in
the same direction. So each mutation here disables one of them and requires the
suites to go red.

The third mutation is the sharp one. `check_claim`'s docstring says the second
witness re-derives the leaf opening and the nullifier because "a witness that only
re-checked membership would have gone on agreeing with a Rust verifier that had
quietly stopped constraining the nullifier to the leaf's secret". That is a claim
about what the witness is FOR, and this removes exactly that half and requires the
tests named after it to fail.

  python3 scripts/polaris-zk-mutation-drill.py

Exits 0 when every mutation is caught, 1 when one survives or a file is not restored.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
LIB_RS = ROOT / "polaris_zk" / "src" / "lib.rs"
WITNESS = ROOT / "polaris_zk" / "witness2" / "verifier.py"

#: Cases this drill actually recorded (v9.403).
_cases_recorded = 0


def _rust_suite() -> bool:
    """True when the Rust tests are RED."""
    return subprocess.run(["cargo", "test", "--release"], cwd=str(ROOT / "polaris_zk"),
                          capture_output=True).returncode != 0


def _witness_suite() -> bool:
    """True when the witness and differential suites are RED."""
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q",
         "polaris_zk/witness2/test_witness2.py", "polaris_web/test_zk_second_witness.py"],
        cwd=str(ROOT), capture_output=True).returncode != 0


#: (label, file, the edit, which suite must notice, why it matters)
MUTATIONS = [
    ("the Rust verifier accepts everything", LIB_RS,
     ("pub fn verify(bundle: &ProofBundle) -> Result<bool> {\n",
      "pub fn verify(bundle: &ProofBundle) -> Result<bool> {\n    return Ok(true);  // MUTATION\n"),
     _rust_suite,
     "a verifier that accepts every proof is the whole guarantee gone"),
    ("the second witness accepts everything", WITNESS,
     ('    reasons: list[str] = []\n',
      '    return {"verdict": "ACCEPT", "membership": True, "binding": True,\n'
      '            "opens": True, "nullifier_derived": True, "reasons": []}  # MUTATION\n'
      '    reasons: list[str] = []\n'),
     _witness_suite,
     "a second witness that agrees with anything is not a second witness"),
    ("the second witness stops re-deriving", WITNESS,
     ('    secret_hex = witness.get("secret_hex")\n    if secret_hex:',
      '    secret_hex = witness.get("secret_hex")\n    if False:  # MUTATION'),
     _witness_suite,
     "this is the exact weakening check_claim's docstring says the witness exists "
     "to prevent: membership alone would agree with a verifier that had stopped "
     "constraining the nullifier to the leaf's secret"),
]


def _restore(saved: pathlib.Path, path: pathlib.Path) -> list[OSError]:
    """Put one file back; yield the error rather than raising, so the loop goes on."""
    try:
        shutil.copyfile(saved, path)
        return []
    except OSError as exc:
        return [exc]


def main() -> int:
    global _cases_recorded
    if shutil.which("cargo") is None:
        print("polaris-zk-mutation-drill: cargo is required (the Rust witness is half the "
              "claim)", file=sys.stderr)
        return 1

    print("Polaris ZK mutation drill: does either witness notice being switched off?\n")
    survivors = []
    with tempfile.TemporaryDirectory() as backup_dir:
        backups = {}
        for path in (LIB_RS, WITNESS):
            backups[path] = pathlib.Path(backup_dir) / path.name
            shutil.copyfile(path, backups[path])
        try:
            for label, path, (old, new), suite, why in MUTATIONS:
                _cases_recorded += 1
                original = path.read_text()
                if old not in original:
                    print(f"  MISSING  {label:42} the code this mutates is gone; the drill "
                          f"is measuring nothing")
                    survivors.append((label, why))
                    continue
                try:
                    path.write_text(original.replace(old, new, 1))
                    caught = suite()
                finally:
                    path.write_text(original)
                if caught:
                    print(f"  ok       {label:42} the suite goes red")
                else:
                    survivors.append((label, why))
                    print(f"  SURVIVES {label:42} nothing notices")
        finally:
            # Restore every file, and continue past a failure so one bad write does
            # not leave the rest mutated. The verdict is carried out of the block
            # rather than returned from it, because a return inside `finally`
            # swallows whatever exception was on its way out.
            broken = [f"{path}: {exc}"
                      for path, saved in backups.items()
                      for exc in _restore(saved, path)]
        if broken:
            print("\nFAIL: file(s) were NOT restored:", file=sys.stderr)
            for line in broken:
                print("  " + line, file=sys.stderr)
            return 1

    print()
    if not _cases_recorded:
        print("FAIL: this drill recorded NO cases. It mutated nothing and would have printed "
              "its summary regardless.", file=sys.stderr)
        return 1
    if survivors:
        print("FAIL: the engine's guarantee can be switched off without anything going red:",
              file=sys.stderr)
        for label, why in survivors:
            print(f"  {label}: {why}", file=sys.stderr)
        return 1
    print(f"OK: {_cases_recorded} mutations, 0 survivors. Each witness goes red when it is "
          "disabled, and the second one goes red when it is weakened to the membership check "
          "its docstring says is not enough.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

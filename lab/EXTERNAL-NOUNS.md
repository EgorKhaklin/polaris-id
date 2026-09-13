# EXTERNAL-NOUNS.md: the scoreboard that decides whether this project continues

**Opened 2026-09-13** under the go-forward operating contract. The unit of progress is
NEW EXTERNAL DEPENDENCY SURVIVED. Internal invariant count, LOC, version count and roadmap
breadth are not product progress and are not recorded here.

Zero and blank values are valid entries. **Invented external evidence is prohibited.** A row
is filled in only when a named outside party did the thing, on a date, with a result that can
be pointed at. Anything the author ran against the author's own code is internal evidence and
belongs in the bottom section, not the top.

---

## External nouns

### Wallet

    Wallet:                    (none)
    URL/version:               (none)
    Contact/run date:          (none)

### External conformance profile

    Profile:                   (none run)
    Run date:                  (none)
    Score:                     __ / __
    Published:                 no

### External relying party / operator

    External RP/operator:      (none)

### Use

    Unique outside users:            0
    Presentations outside CI:        0
    Distinct days used:              0

### Findings from outside

    Bugs/ambiguities filed by non-authors:   0
    Fixed because of external findings:      0

---

## Internal readiness (NOT external evidence)

Recorded here so the top section is never padded with it. Everything below was run by the
author against the author's own code, and none of it counts toward the 180-day line.

**Install test, 2026-09-13: PASSES, and now runs on every push.** It is no longer a thing
somebody remembered to try. `scripts/polaris-product-boundary-drill.py` builds a WHEEL from
`packages/polaris-verify/`, installs it into a throwaway virtual environment, and runs the
verifier from a working directory that is not the repository, with `PYTHONPATH` and every
`POLARIS_*` variable stripped. It asserts the forbidden runtime surface is absent (Flask,
psycopg2, polaris_checks, polaris_web, polaris_cli, polaris_sim, redis), that the command
refuses to start without a declared crypto mode, that a genuine ML-DSA-87 credential verifies
and its tampered twin does not, and that `--dev-placeholder` cannot report anything authentic.

It carries a negative control: a second wheel is built with `import psycopg2` bolted onto the
verifier, and the harness has to catch it. Without that, "every leg passed" and "the harness
ran nothing" print the same thing. CI job `product-boundary`.

This matters because every other suite in this repository runs from INSIDE the repository
with the repository on `sys.path`. An import of `polaris_web`, or a read of a file that only
exists in a checkout, would have stayed green here and failed on the first stranger's machine.

**Known gaps against the product contract, same date:**

- ~~There is no `polaris-verify` startup to refuse.~~ **CLOSED.**
  `packages/polaris-verify` 0.1.0 installs a `polaris-verify` console command that exits 4,
  without reading the caller's files, unless the run declares `--pqc-provider
  {oqs,cryptography,auto}` or `--dev-placeholder`. Naming a backend that is not usable on the
  machine is also refused, rather than starting and reporting a verification failure for every
  credential, which reads as the credentials being bad instead of the verifier being unable.
  No default, no environment variable.
- ~~Verification responses carry no `crypto` field.~~ **CLOSED.** Every machine-readable
  verdict carries `"crypto"`, and a banner goes to stderr on every run.

  Building that gate found a defect in it: `--dev-placeholder` originally declared the mode
  without entering it, so a genuine ML-DSA-87 pack verified `signature_valid: true` with real
  cryptography and was stamped `DEV-PLACEHOLDER`. A declared mode that does not change what
  the process does is a label, not a mode. The flag now turns the real backends off, so a
  development run cannot produce a true verdict at all.

  It also found a misreported reason: `--verify-dir` blamed a missing ML-DSA library for every
  artifact that is not an authenticity pack, with a real backend installed and confirmed. The
  two causes are now distinguished.
- `sdk/python/pyproject.toml` declares `name = "polaris-verify"`, `version = "1.0.0"`. Under
  the contract 1.0.0 requires a clean-machine install, explicit real-crypto behavior, a named
  external client completing a presentation, a named external conformance suite run, and a
  published result. One of five holds. The version overstates.
- **Neither SDK has ever been published.** `pypi.org/pypi/polaris-verify` and
  `registry.npmjs.org/@polaris/verify` both answer 404, as do `polaris-sdk-python` and
  `polaris-sdk-ts` (checked 2026-09-13). No outside party has ever been able to install
  either one. The conformance contract certifies implementations of a protocol whose
  reference SDKs cannot be fetched. This is the first thing standing between the tree and
  the 90-day objective, and it is why every count in the top section is zero.
- Both SDKs asserted `1.0.0` while unpublished. Reset to `0.1.0` on 2026-09-13 under
  section 4: 1.0.0 has five named conditions and one of them holds.
- `core/` does not exist as a layout; `packages/` and `lab/` now do. The rest of the tree is
  unmoved, deliberately: the paths that would move are named 426 times across 86 files, the
  CHANGELOG and the paper among them, and those record what happened rather than a later
  layout. `scripts/polaris-verify.py` is a namespace shim onto the packaged verifier, so there
  is one source of truth and the historical path still loads, module-private names included.
- The issuer side downgrades on an environment variable (`POLARIS_USE_REAL_PQC`), which is the
  silent-downgrade shape the contract forbids. It sits in what the contract calls `core/`, so
  it is recorded rather than actioned here.

**First interop target: not started.** OpenID4VP 1.0 + HAIP verifier, one credential format,
format to be chosen from the first real use case.

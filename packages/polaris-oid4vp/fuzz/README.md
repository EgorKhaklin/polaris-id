# Fuzzing polaris-oid4vp

Coverage-guided fuzz targets ([atheris](https://github.com/google/atheris), libFuzzer) for the
functions that read what a wallet, or a status list server, sends. Each target holds one
function to the promise its own docstring makes:

| Target | Function | The promise |
|---|---|---|
| `fuzz_presentation.py` | `sdjwt.verify_presentation` | returns a Verdict and never raises; nothing accepted differs from what the issuer signed |
| `fuzz_signed.py` | `sdjwt.verify_presentation` | the same, with the fuzzer's bytes signed as the issuer's payload or the holder's key binding JWT |
| `fuzz_jwe.py` | `jwe.decrypt_response` | raises nothing but `JweError` |
| `fuzz_response.py` | `Verifier.handle_direct_post` | answers 200 or 400, never an exception; 200 only for an authentic presentation |
| `fuzz_status.py` | `status.decide` | total on hostile input; a checked verdict carries a status |

Keys and the clock are fixed (`_genuine.py`), so an input that crashes a target reproduces
anywhere. Each target seeds an empty corpus directory with genuine artifacts from the suite's
own wallet, the ones its positive control accepts.

CI runs every target for a minute on a pull request that touches this package and for ten
minutes every night (`.github/workflows/fuzz.yml`). A crash fails the job, and the input that
caused it is uploaded as the `fuzz-crashes` artifact.

A target that finds nothing proves nothing until it has found something. Each was run against a
copy of the package with one guard removed, a defect of a kind this package has actually had, and
each found it within five minutes (2026-09-30, emulated x86-64):

| Target | Guard removed | Found |
|---|---|---|
| `fuzz_presentation.py` | the three-part check in `_parse_jws` | `IndexError` |
| `fuzz_signed.py` | `isinstance(vct, str)` before the type lookup | `TypeError`, unhashable `vct` |
| `fuzz_jwe.py` | `isinstance(enc, str)` before the `enc` lookup | `TypeError`, unhashable `enc` |
| `fuzz_response.py` | `isinstance(vp_token, dict)` | `TypeError` on a missing or `null` vp_token |
| `fuzz_status.py` | `isinstance(lst, str)` | `TypeError` on a number as `lst` |

The status target missed its defect in five minutes of byte mutation and found it only after the
typed field forms were added (`_genuine.with_field`), which the signed, JWE and status targets
now all have.

## Running locally

atheris publishes wheels for Linux x86-64 only. On another platform, use a container:

    docker run --rm -it --platform linux/amd64 -v "$PWD":/src -w /src/packages/polaris-oid4vp/fuzz \
      python:3.12-slim-bookworm bash -c \
      "pip install --require-hashes -r requirements.txt && python fuzz_presentation.py corpus/presentation -max_total_time=60"

To replay one input, name the file instead of a directory:

    python fuzz_presentation.py crash-<hash>

`requirements.txt` is compiled from `requirements.in` with hashes; see its header.

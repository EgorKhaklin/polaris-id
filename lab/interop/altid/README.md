# lab/interop/altid: an age-verification presentation, verified offline

Lab work, for one test flow with the AltID test app. The lab verifier asks for one claim, `age_over_18` of an
`eu.europa.ec.av.1` document, as the age-verification profile ([AVP]) of the AltID integration guide 1.0.2 describes
it: OpenID4VP 1.0 over `direct_post`, with a `redirect_uri:` client id. It checks the response against the
guide's Appendix D, and it keeps a capture that the verifiers read again offline. The product is unchanged:
`polaris-oid4vp` asks for and verifies SD-JWT VC.

It reuses the prototype mdoc verifier and its witnesses in place:
- `avp.py` imports [`../mdoc/verify_mdoc.py`](../mdoc/verify_mdoc.py);
- the witnesses are [`../mdoc/witness_isomdl.py`](../mdoc/witness_isomdl.py) and the two in
  [`../mdoc/witness-eudi/`](../mdoc/witness-eudi/).

## What is where

| | |
|---|---|
| [`avp.py`](avp.py) | The profile layer: `new_transaction` (the request, its two link forms and its record), `verify_avp` (Appendix D's steps) and `Transactions` (the records under one lock, the answers, the capture). |
| [`serve.py`](serve.py) | A stdlib HTTP server bound to 127.0.0.1. Its pages are rendered on the server, with inline SVG QR codes and no script, and it keeps no access log. |
| [`run_tunnel.sh`](run_tunnel.sh) | `serve.py` behind the integrator's own cloudflared quick tunnel, modelled on [`scripts/polaris-dev-tunnel.sh`](../../../scripts/polaris-dev-tunnel.sh). On Ctrl-C and on a TERM it stops both processes by their recorded PIDs and deletes the tunnel's log. |
| [`trust/`](trust/) | The guide's Table 13 test certificate, and `PINS`, its SHA-256. A trust PEM whose hash is not pinned is refused when it loads. |
| [`make_vectors.py`](make_vectors.py), [`vectors/`](vectors/) | 23 synthetic responses, made with the lab's own test keys from a public seed. Each case sits in `manifest.json` with its pinned anchors, its instant and the verdict it must get. |
| [`test_avp.py`](test_avp.py) | 79 tests, with no database and no outside network (the server tests bind loopback ports of their own). |
| [`dryrun_appendix_f.py`](dryrun_appendix_f.py) | The guide's own Appendix F response through `avp.py` and `verify_mdoc.py`, read from the guide's text at a path you give. The guide's bytes are not in the tree. |
| [`witness.sh`](witness.sh), [`witness_jobs.py`](witness_jobs.py), [`witness-results/`](witness-results/) | Three outside mdoc verifiers over every vector, offline, the step table, and the record of the last run. |

## The checks of Appendix D

A response is checked in this order: the transaction (step 13: it is known, not yet answered and not expired),
steps 1 to 5, the issuer signature, docType, validity and the digests (6 to 10), the device signature (12), the
status element (11), the state (13) and the verdict (14).

| Step | Where | Refused when |
|---|---|---|
| 1-3 | `avp.py` | `vp_token` is missing or repeated, is not base64url, or is not a CBOR DeviceResponse. Both forms are taken: the string, and the object keyed by the query id that holds one presentation. |
| 4 | `avp.py` | the status is not 0, the response holds anything but one document, or the document is not `eu.europa.ec.av.1`. |
| 5 | `avp.py`, then `verify_mdoc.py` for the chain | the last x5chain certificate is not in the trust list (by DER, pinned by SHA-256), or is not self-signed; or the chain from the issuer certificate to it, in order, does not verify at the instant. |
| 6-10 | `verify_mdoc.py` | the issuer signature, the digests, the MSO's docType or its validity fails. |
| 11 | `avp.py` | the MSO carries a status element. A Proof of Age carries none, so the lab fails closed here. |
| 12 | `verify_mdoc.py` | the device signature fails over the AVP SessionTranscript: the record's client id, nonce and response URI, and a null JWK thumbprint. |
| 13 | `avp.py` | the transaction is unknown, expired or already answered, or `state` differs from the record. The record is marked under the same lock as the check. |
| 14 | `avp.py` | never: `age_over_18` true is satisfied, and false or missing is a 200 that is not satisfied. |

A response that passes steps 1-13 gets 200 and `{}`; any other gets 400 and the refused step in words. On the same
device, the 200 also carries a `redirect_uri` with a one-use code. An error response is answered with 200 and keeps
only its code.

## The witnesses

`witness.sh` runs three outside mdoc verifiers over the 23 vectors, offline. Each vector runs under its pinned anchors
and again with none, which makes 46 cases. `witness_jobs.py` then compares their verdicts with `avp.py`'s, step by
step, and counts a witness for what its code decides on inputs that code did not build. E's verdicts on the
issuer signature (6), the digests (7-8), the MSO's docType (9) and the device signature (12) rest on walt.id's
mdoc library inside it, and they count here, since walt.id built none of these vectors (`make_vectors.py` uses cbor2
and cryptography); `../mdoc`, whose captures walt.id built, reports them and does not count them. Every difference
must carry a stated reason in its `CLASSIFIED`, or the run fails. A control, @owf/mdoc with its ECDSA verify always
true, must produce differences without one. `test_avp.py` rebuilds the table from the raw outputs in
`witness-results/` and runs that control again.

The run of 2026-11-13, with @owf/mdoc 0.9.3 (O), the EU reference verifier eudi-srv-verifier-endpoint v0.12.0 (E) and
isomdl-uniffi 0.2.0 (I), each pinned by digest (`witness-results/run.json`):

| Step | Cases ours judged | O agrees | E agrees | Differences, each with its reason |
|---|---|---|---|---|
| 12, the SessionTranscript bytes | 46 | 46 | 46 | none |
| 1-4, the DeviceResponse | 46 | 42 | 20 | O 4, E 6 |
| 5a, the trust list and the chain | 35 | 32 | 15 | O 1 |
| 6, the issuer signature | 36 | 36 | 30 | none |
| 7-8, the digests | 30 | 30 | 24 | none |
| 9, the MSO's docType | 34 | 34 | 28 | none |
| 10, the validity | 32 | 32 | 26 | none |
| 12, the device signature | 30 | 30 | 24 | none |

No difference is left without a reason, and the control gives 8. Steps 4 (the requested docType), 5b (self-signed),
11, 13 and 14 are judged by `avp.py` alone. I judges no step: it parses mDL documents only. E is given one
classification input of ours, which is not E's code: the eaa "av" entry in `../mdoc/witness-eudi/Witness.kt`, so
that E judges an `eu.europa.ec.av.1` document at all. With no anchor, E's trust answer is its shipped fallback,
which trusts any chain; the driver marks it not witnessed, and it is not counted. E's device signature is judged
only where its output shows it, by its own error or an acceptance. `witness-results/table.txt` gives
each reason in the witness's own words.

## The app's presentation, 2026-11-13

On 2026-11-13 the AltID test app (iOS, the agency's test environment), operated by the author, presented a Proof of
Age to this verifier, and `avp.py` answered `VERIFIED`. Over the same response, offline, @owf/mdoc 0.9.3 and
eudi-srv-verifier-endpoint v0.12.0 (with our classification input) agree, and the lab verifier refuses it posted a
second time to its restored record (step 13) and under a changed nonce (step 12, the device signature).

## Run it

    python3 -m venv /tmp/v && /tmp/v/bin/pip install --require-hashes -r lab/interop/mdoc/requirements.txt
    cd lab/interop/altid
    /tmp/v/bin/python -m unittest test_avp                          # 79 tests
    /tmp/v/bin/python -I make_vectors.py vectors                    # regenerates vectors/ byte for byte
    /tmp/v/bin/python -I dryrun_appendix_f.py GUIDE.txt             # pdftotext -layout of the guide
    PYTHON=/tmp/v/bin/python ./witness.sh                           # writes witness-results/
    AVP_PYTHON=/tmp/v/bin/python ./run_tunnel.sh                    # the flow: needs cloudflared on PATH

A flow's capture goes to `runs/<txid>/`, which git ignores. It holds the input format `verify_mdoc.py` reads
(`device-response.cbor`, `openid4vp-inputs.json`, `captured-at.txt`), the request as offered, the hash of the POST
body, the record and the verdict. It holds no headers, no address and no user agent.

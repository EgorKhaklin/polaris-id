# 003 lab results: signing custody out of the web process

Measured 2026-09-27 for section 9 of
[003-signing-custody-compartment.md](../003-signing-custody-compartment.md), reported against its
section 10. No product file was changed and nothing was committed. The scratch database
`polaris_signer` (00_load_all.sql plus every `migrations/*.up.sql` in sort order) is left in
place. All runs used the placeholder signing profile.

## Files

| File | What it is |
| --- | --- |
| [`CALL-SITES.md`](CALL-SITES.md) | The classification: 21 call sites, their format, route and surface. |
| `record_signing_calls.py` | Runs all of `test_app.py` with every signing entry point and custody driver wrapped, and records format and surface per call. |
| `socket_hop_latency.py` | Kill criterion 3: the cost of one local UNIX-socket round trip with a signature-sized reply. It holds no key and signs nothing. |
| `out/recorded_calls.json`, `out/socket_hop_latency.json` | Raw results. |

## Classification summary

- There are 21 signing call sites. The operator surface alone signs issuance (a raw token_value
  with no format: `/uc1/issue`, `/uc6/migrate`, CLI `bulk-enroll` and `migrate-population`) and
  `polaris-trust-attestation/1`. The relying-party surface signs 15 JSON formats plus two bare
  32-byte digests (the mdoc and the verifiable credential).
- Six formats are signed by both surfaces. Five of them mean the same thing on each side.
  `polaris-signed-document/1` does not: the institution's own act and a holder-authorized act
  differ only in the `on_behalf_of` field inside the statement.
- The dynamic run (904 tests, 0 failed, 189 signing calls) found no path the static list missed.
  Under the placeholder profile it did not reach the exchange receipt, the operator `/api/v1/sign`
  route or the CLI. Those three are classified from the code only.

## Kill criterion 1: do the formats partition? **FIRES.**

The relying-party surface signs, on every request, three formats that are trust-decision formats
by section 10's own list:

- `polaris-federation-manifest/1`: the authority's anchors and the trust edges it has made.
  Section 2 names "manifest" as a signature the public surface would no longer be able to get.
- `polaris-trust-list/1`: the status (active, retired, compromised) of every authority key.
- `polaris-registry/1`: the authorities with their keys, and the in-context trust graph.

It also signs two credential renderings, the mdoc and the verifiable credential.

The allow-list would have to give the relying-party caller these formats, and they are what the
compartment exists to withhold. A signer sees only the statement bytes. Once code runs in the
public process, it picks the content of an allowed format, and a format check does not constrain
content. The damage is not limited to tampering with data. By its own logic, the detached
verifier's `verify_cross_authority` honours an unsigned trust edge carried in an authentic manifest
unless the caller passes `require_signed_attestation=True`, and the default is False. So the
authority's signature on a manifest is on its own enough to create cross-authority trust.

The decisive finding: **the formats do not partition. The public surface needs the manifest, the
trust list and the registry, which are trust-decision formats.**

Two more findings bear on any signer design:

- **Issuance has no format.** Measured: `signature_over_message(token_value.encode())` gives
  bytes identical to the issuance signature for that token_value (both sign SHA3-256 of the input,
  and `verify_pack` checks SHA3-256(token_value)). Today any code that can call
  `signature_over_message` holds a credential-issuing capability. A signer could refuse input that
  does not parse as a known canonical format, but a signature-compatible fix needs domain
  separation at issuance, which is a signature and verifier change that section 1 rules out.
  A related property follows from reading the verifier and was not exercised here, so it should be
  checked with real ML-DSA before anyone relies on it: `verify_pack` places no constraint on the
  shape of `token_value`, so any statement the authority signs may also verify as an authenticity
  pack whose token_value is that statement's text. Checked the same day:
  [`transplant_counterexample.py`](transplant_counterexample.py) re-wraps 11 published signed
  vectors and hands each to the detached verifier and both SDKs with the signing key trusted.
  Before the fix all 33 verdicts were authentic and trusted
  ([`out/transplant_before_fix.txt`](out/transplant_before_fix.txt)); after the serial rule
  (WIRE-SPEC 3.7) all 33 are refused ([`out/transplant_after_fix.txt`](out/transplant_after_fix.txt)).
- **Two call sites sign a bare digest.** The mdoc and VC routes pass SHA3-256 of their document to
  `signature_over_message`, which hashes it again. A signer receives 32 opaque bytes and cannot
  read a format from them. The interface would have to change so the document itself is sent.

## Kill criterion 2: what a compromised relying-party process could make the authority assert

This is for the formats the relying-party surface would be allowed. "DB-computable" means a signer
with its own read access could build the statement from the database and ignore the caller's
content.

| Format | False assertion available to a compromised rp process | DB-computable? |
| --- | --- | --- |
| status assertion | a revoked or expired credential is ACTIVE | Yes: status, expiry and RevocationList for the token. Needs read access and a second copy of `_effective_status`. |
| revocation feed | a revoked credential is left out | Yes: RevocationList joined to IdentityToken per agency. |
| epoch checkpoint / leaves / status bundle | a forked or rolled-back epoch, a wrong anonymity set | Yes: TokenStateEpoch(Leaf). |
| manifest / trust list / registry | extra anchors, extra trust edges, a compromised key shown as active | Yes, from Agency, AuthorityKeyCurrent and AgencyTrustAttestation. That is only worth doing if the public login cannot write those tables, which 002 measured it cannot. |
| holder binding | an attacker key bound to any credential | Only in form: the signer would read HolderKeyEvent, which the rp login can INSERT into for any credential (002 N-3). |
| mdoc / VC | a credential rendered with false status or claims | Yes, if the document is sent (see criterion 1). |
| id token | any subject, audience, context or acr: a login that never took place | **No.** The state lives in a stateless auth code under `app.secret_key`, which the same process holds. |
| exchange receipt | an exchange that never took place, authorized by any edge | Partly: the attestation check can be recomputed, but the hashes and time cannot. |
| timestamp | any digest at the current instant | No, and it does not need to be: it asserts only "seen now". |
| signed document (holder path) | an act on behalf of any credential | Partly: possession can be re-checked only if the signer is given the presented pack. |
| STH | a log head that forks or rewrites | Yes: AnchorBatch, ExchangeReceiptLog, TimestampLog. |

The limit: most of the dangerous content can be computed from the database, but only by a signer
that re-implements every statement builder with its own read access. That is a second read path,
not a format allow-list. The id token, the exchange receipt and the holder-signed document cannot
be fully recomputed, so even that design leaves forged logins and forged evidence of an exchange
available to a compromised public process.

## Step 4 (the lab signer): not built

The task made this step conditional on criterion 1 not firing, and it fired. An attempt to write
the signer was also stopped before any file was written, so no signer exists and nothing about it
was measured. That includes the refusal test in which the relying-party caller requests each
operator format. The dynamic recording run stands in for step 4's other purpose, finding signing
paths the classification missed, and it found none.

## Kill criterion 3: latency. **Does not fire.**

`socket_hop_latency.py` ran 5,000 round trips over a UNIX socket, after 500 warm-up calls, with a
3,309-byte reply the size of an ML-DSA-65 signature: **p50 0.012 ms, p90 0.014 ms, p99 0.030 ms**
(max 0.193 ms). That is about 0.2% of the 17.8 ms end-to-end request in lab/evaluation at p99, and
smaller than the 0.12 ms liboqs sign.

The client and server were threads in one process, so this is a lower bound on a real process
boundary. Serialization, the policy check and a scheduler hop to a separate process would add
tens of microseconds, not milliseconds. The 17.8 ms figure is for verification, which does not
sign. The routes that do sign pay the hop once per signature, and the document-signing route pays
it five times (document, timestamp, manifest, checkpoint, feed), which still comes to well under
1 ms. The hop can also be optional: in-process signing stays the single-host default.

## Recommendation: **kill the bet as specified, and record one narrower bet.**

- **Kill** the per-caller-format signer. Criterion 1 fires: the public surface signs the manifest,
  trust list and registry, and a format list cannot stop a compromised caller from filling those
  formats with any content.
- **Narrow, as a new bet if anyone wants it:**
  1. Move the trust-decision artifacts out of per-request signing. Manifest, trust list, registry,
     checkpoint, revocation feed, epoch leaves and STH depend only on (agency, now) and already
     carry TTLs of hours. A publisher on the operator side can sign them on a schedule, and the
     public surface serves bytes it cannot sign.
  2. Give issuance its own entry point that the public process cannot reach. This needs domain
     separation at issuance, because of the finding above, which is a signature change; the bet as
     written excluded that.
  3. Once 1 and 2 are done, the public surface signs only per-request status and evidence formats.
     For those, the criterion 2 table shows which ones a signer could recompute from the database.
     Id tokens and exchange receipts stay a named limit.
- **Latency is not the obstacle.**

The cross-format property and the bare-digest mdoc and VC paths belong in the threat model as
findings about today's product, whatever happens to this bet.

## Reproduce

```bash
PY=~/.local/share/polaris-venv312/bin/python
POLARIS_DB_HOST=localhost POLARIS_DB_NAME=polaris_signer POLARIS_DB_USER=vanta \
  POLARIS_TEST_RELOAD_USER=vanta POLARIS_SECRET_KEY=local-test-secret-key-32-bytes-long \
  POLARIS_STATE_DIR=/tmp/polaris-state-signer POLARIS_PQC_PROFILE=placeholder \
  $PY lab/strategy/003/record_signing_calls.py
$PY lab/strategy/003/socket_hop_latency.py --n 5000
```

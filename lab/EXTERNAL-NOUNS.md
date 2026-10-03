# EXTERNAL-NOUNS.md: the scoreboard that decides whether this project continues

**Opened 2026-09-13** under the [operating contract](../docs/OPERATING-CONTRACT.md). The unit of
progress is NEW EXTERNAL DEPENDENCY SURVIVED; internal counts are not recorded here. A row is
filled only when a named outside party did the thing, on a date, with a result that can be
pointed at. Zero and blank are valid entries. **Invented external evidence is prohibited.**
Anything the author ran against the author's own code belongs in the last section.

| Noun | State |
|---|---|
| Wallets | 4 unmodified wallets presented to `polaris-oid4vp` and were accepted; 2 received wallet copies from the product |
| Conformance profile | `polaris-oid4vp 1.0.0rc7` OpenID Certified to OID4VP 1.0 + HAIP 1.0 Verifier, 2026-09-24 |
| Outside test corpus | Wycheproof ML-DSA-65 verify vectors, 58 of 58, every push |
| Public distribution | all four packages on PyPI and npm since 2026-09-15 |
| External relying party / operator | none |
| Use | 0 outside users |
| Findings from outside | 1 filed, 2 fixed |
| Independent security review | none |
| Pilot | none |

## External nouns

### Wallets

Every wallet ran unmodified, with no contact with its authors; configuration only (trust
anchors, TLS roots). Each run carries controls that must be refused, because a verifier that
accepts everything prints the same success line.

| Date | Wallet | Verifier | Result | Controls, each refused | Evidence |
|---|---|---|---|---|---|
| 2026-09-15 | walt.id Wallet API v2 1.0.0 (`waltid/wallet-api2:1.0.0`) | this repository, edeecf7 | accepted: `200 authentic` | wrong issuer key under the same kid; a replayed `state` | [lab/interop/waltid](interop/waltid/README.md) |
| 2026-09-17 to 2026-09-28 | walt.id, the same image | PyPI: 1.0.0rc1, rc3, rc7, rc8 | accepted each time | as above | [STRANGER-PATH.md](../docs/STRANGER-PATH.md), walked from the registry |
| 2026-09-27 | Credo 0.6.3 (OpenWallet Foundation, TypeScript) | PyPI 1.0.0rc7 | accepted | wrong issuer key; a `cnf` key Credo does not hold; the same response twice; Credo trusting an unrelated CA (Credo refused) | [lab/interop/credo](interop/credo/README.md) |
| 2026-09-28 | eudi-dev v2.3.7 and v2.4.3 (Go), HAIP 1.0 enforced in strict mode | PyPI 1.0.0rc7 | accepted | wrong issuer key; the answered request again; a mismatched `client_id` (the wallet refused) | [lab/interop/eudi-dev](interop/eudi-dev/README.md) |
| 2026-09-30 | eudi-dev v2.3.7 (Go), HAIP strict, presenting a PID credential its own issuer signed (`x5c`, ISO 18013-5 document signer) | PyPI 1.0.0rc11 (c8014978); 1.0.0rc10 refused it | accepted | an unrelated CA; the answered request again | [lab/interop/eudi-dev](interop/eudi-dev/README.md#an-issuer-nobody-here-wrote-2026-09-30) |
| 2026-09-28 | OID4VCgo 0.12.0 and 0.19.0 (Go), presenting a credential it issued under an x5c chain | this repository, 1156db81 | accepted; the wallet followed the `redirect_uri` into a 404, fixed | an unrelated CA; the answered request again; a mismatched `client_id` (the wallet refused) | [lab/interop/oid4vcgo](interop/oid4vcgo/README.md) |
| 2026-09-30 | OID4VCgo 0.22.0 (Go), checking the verifier's request-object chain against its CA | this repository, c655b1ea | accepted; the wallet logged that it does not verify TLS | the three above, and the wallet trusting an unrelated CA for the verifier (the wallet refused) | [lab/interop/oid4vcgo](interop/oid4vcgo/README.md#v0220-the-wallet-checks-the-verifiers-chain-2026-09-30) |
| 2026-10-01 | OID4VCgo 0.23.0 (Go), which also refuses a verifier leaf that is a CA, cannot sign, or travels with its anchor | this repository, 4e208b5a | accepted | the same four (the wallet refused) | [lab/interop/oid4vcgo](interop/oid4vcgo/README.md#v0230-the-verifiers-leaf-is-held-to-haip-2026-10-01) |
| 2026-10-01 | Pomerium 0.33.3 (identity-aware proxy, unmodified), with the lab gate as its OIDC provider and walt.id's wallet presenting | this repository, lab/strategy/007 | admitted; the released claims reached the protected app | the issuer untrusted (refused, not admitted) | [lab/strategy/007](strategy/007/README.md) |
| 2026-10-01 | Pomerium 0.33.3 (unmodified), checking an agent's bearer token on each request (`bearer_token_format: idp_identity_token`, a `claim/action` policy per route) | this repository, lab/strategy/007, with an ML-DSA-65 grant chain | admitted on each action's own route | the other action's route; no token; a token the gate never signed (Pomerium refused); the same proof twice; an action outside the grant; a revoked grant (the gate refused) | [lab/strategy/007](strategy/007/README.md#pomerium-end-to-end) |
| weekly since 2026-09-28 | eudi-dev v2.3.7 (by digest) and latest | the newest PyPI release | accepted (rc7, then rc8) | all three | `.github/workflows/wallet-canary.yml` |
| 2026-10-02 | eudi-dev v2.5.0 (Go), strict mode now checking the verifier's TLS | this repository, PyPI 1.0.0rc13 | strict mode refused the self-signed listener (`x509: certificate signed by unknown authority`); with `--tls-verify=false` it presented, `200 authentic` | all three (in the `--tls-verify=false` run) | [eudi-dev](interop/eudi-dev/README.md#the-verifiers-tls-checked-in-strict-mode-2026-10-02) |
| 2026-10-03 | eudi-dev v2.3.7 (Go), HAIP strict, its own binary (no Docker) | this repository, PyPI 1.0.0rc14 | accepted: `200 authentic` | wrong issuer key; the answered request again; a mismatched `client_id` (the wallet refused) | [eudi-dev](interop/eudi-dev/README.md) |
| 2026-10-03 | eudi-dev v2.5.0 and v2.5.1 (Go), HAIP strict with its TLS check on, trusting the verifier's listener certificate (`--tls-ca`) | PyPI 1.0.0rc14 | accepted: `200 authentic` | wrong issuer key; the answered request again; a mismatched `client_id` and an unrelated TLS trust (both refused by the wallet) | [eudi-dev](interop/eudi-dev/README.md#the-verifiers-tls-checked-in-strict-mode-2026-10-02) |
| 2026-10-03 | eudi-dev v2.5.0 (Go), HAIP strict with its TLS check on, through cloudflared quick tunnels, presenting a PID its own issuer signed under an intermediate CA | PyPI 1.0.0rc14, then this repository at bf3798d4 | 1.0.0rc14 refused it (`issuer_key`: the chain was read one link deep); bf3798d4 accepted: `200 authentic` | an unrelated issuer CA; the answered request again; a mismatched `client_id` (the wallet refused) | [eudi-dev](interop/eudi-dev/README.md#strict-mode-with-the-verifiers-tls-checked-through-a-tunnel-2026-10-03) |

eudi-dev v2.3.7 and OID4VCgo 0.12.0 are listed by the OpenID Foundation as certified OID4VP 1.0
+ HAIP 1.0 wallets.

**The issuing side, 2026-09-28.** walt.id Wallet API v2 1.0.0 and Credo 0.6.3 each received a
wallet copy from `polaris_web` itself, over OpenID4VCI 1.0 with a pre-authorized code, signed
with a TEST chain for one agency (from 6803f9f2). Each copy verified to the test anchor, was
bound to a key the wallet generated, and read VALID on the agency's status list, then INVALID
after `uc8_revoke_token`. A credential revoked between offer and redemption got no copy
(`credential_request_denied`, from the record). Each wallet then presented its copy to
`polaris-oid4vp`, which read the product's status list (from 21d545db): VALID, then INVALID after
revocation; the relying party asked for `age_over_18` and learned no name, birthdate or
jurisdiction. Credo fetched the
status list on receipt; walt.id did not. Evidence: [lab/strategy/005/STEP5.md](strategy/005/STEP5.md),
[STEP6.md](strategy/005/STEP6.md); `product/run.py` and `product/present.py` reproduce both.

**No outside holder at rc.67 (2026-09-30).** Strategy 005's fourth criterion asked whether, by the
release after wallet copies shipped, an outside party had issued into or presented from a
wallet with one. None had. The paragraph above stays what it is, the author's own
interoperability run, and the criterion's blank is recorded here.

**OID4VCgo changed after a report from here, 2026-09-30.** Its harness accepted any verifier TLS
certificate without saying so; reported as [issue 312](https://github.com/IDFoundry/OID4VCgo/issues/312),
its author shipped v0.22.0 the same day ([PR 314](https://github.com/IDFoundry/OID4VCgo/pull/314)):
a startup warning, an optional check of the verifier's request-object chain against configured
anchors, and a README section on what a passing run shows. Its author closed the issue as fixed on
2026-10-01 and shipped v0.23.0, which also holds the verifier's leaf to HAIP 1.0 section 5. The
last two rows are those versions, checked here on request. It is an outside project acting on a report, not an outside party using Polaris.

**eudi-dev changed after a report from here, 2026-10-02.** It did not validate the verifier's TLS
certificate, even in `--mode strict`; reported as
[issue 21](https://github.com/dominikschlosser/eudi-dev/issues/21). The maintainer fixed it in
[v2.5.0](https://github.com/dominikschlosser/eudi-dev/releases/tag/v2.5.0), whose release notes say
strict mode now verifies TLS for every HTTPS destination, with `--tls-verify` and `--tls-ca`
overrides, and asked for a re-test. Checked here against the eudi-dev walk, with `polaris-oid4vp`
1.0.0rc13 as the verifier: `eudi-dev:v2.5.0 --mode strict` refuses its self-signed listener
certificate (`tls: failed to verify certificate: x509: certificate signed by unknown authority`),
where v2.3.7 presented; and `--tls-verify=false` restores presenting (accepted, all three controls
refused). The one destination checked here is that listener; every-destination is the release's
claim, not this run's. It is an outside project acting on a report, not an outside party using
Polaris. Evidence: [lab/interop/eudi-dev](interop/eudi-dev/README.md#the-verifiers-tls-checked-in-strict-mode-2026-10-02). On 2026-10-03, with each
verifier behind its own tunnel, strict mode presented with its TLS check on, and the run found a
gap on this side: v2.5.0's issuer signs under an intermediate CA, and the verifier read one link.
Fixed in bf3798d4 (row above).

**walt.id refused Polaris first, and was right.** `polaris-oid4vp keygen` issued a
request-signing leaf with no `digitalSignature` key usage; eleven conformance modules, 142
package tests and every internal check had passed over it. Fixed in v9.465 with a test. Two
findings were walt.id's own, recorded and not absorbed: its `present/resolve-request` route
ignores configured trust anchors, and `x509TrustAnchors` wants PEM although its comment says
base64 DER.

**What the wallet rows do not establish.** Each was driven by the author, on one machine,
against this repository's issuer script or a test CA and a scratch database (the 2026-09-30
eudi-dev row against the wallet's own issuer): interoperability,
not an outside party using Polaris. One credential format (SD-JWT VC), one presentation path
(OpenID4VP `direct_post.jwt`), ES256 throughout; nothing about mdoc, other wallets or the
post-quantum path. The issuing side is not HAIP (pre-authorized code only), and a wallet copy is
a classical ES256 credential: nothing verified from it rests on ML-DSA-65.

### Conformance profile

**Certified, 2026-09-24.** `polaris-oid4vp 1.0.0rc7` is OpenID Certified™ by Egor Khaklin to the
OpenID4VP 1.0 + HAIP 1.0 Verifier profile (`sd_jwt_vc`, `direct_post.jwt`): hosted plan
`oid4vp-1final-verifier-haip-test-plan` 7hXWngaA7f0QO, 11 of 11 modules finished without failure
against the PyPI artifact's source, keys minted for the run and discarded; published with the
signed Certification of Conformance; request OCS-3049 approved and
[listed](https://openid.net/certification/certified-oid4vp-haip-final/), read back from the page.
The fee was waived on 2026-09-23 under the Foundation's open-source policy.

It is a self-certification the Foundation reviewed and published, not an endorsement and not an
independent verification (Certification Terms 3(e)). It covers that version in the verifier role
on that profile. It does not cover the rest of Polaris, other versions (1.0.0rc8 to 1.0.0rc14 are
not certified), the wallet role, other formats, or anything the suite does not test.
Measured after it, on 2026-09-30: 1.0.0rc7 refuses an issuer certificate whose extended key
usage is ISO 18013-5's document signer, as EUDI issuers' are (eudi-dev's PID Provider: its chain
check answers no), and its `serve` takes issuer keys only as a JWKS (`--issuer-jwks`), so an `x5c`
issuer can be trusted only through the library call. The tree takes the document signer.

Earlier runs, same plan: a hosted run of 0.1.0 on 2026-09-15 finished 11 of 11 with zero FAILURE
or WARNING (7 negative modules PASSED automatically, 4 positive in human REVIEW), after a first
attempt that used one alias for every module and so interrupted the positive ones, corrected
with an alias per test; and a self-hosted run of the suite on 2026-09-14, 11 of 11 clean. Both
runs carried two negative controls: a verifier patched to answer 400 to everything fails the
happy flow, and one answering 200 to everything fails all seven negative modules. The
Foundation's signed exports were downloaded and are not committed, because they embed the run's
throwaway issuer key; their test identifiers let anyone signed in fetch the same logs.

### Outside test corpus

Project Wycheproof, `testvectors_v1/mldsa_65_verify_test.json` at 613a2e44cb64: 58 of 58 under
both witnesses (liboqs and `cryptography`), on every push (CI job `pqc-real`). It tests the
cryptographic primitive, not the credential protocol, and moves no row above.

### Public distribution

All four packages are published by trusted publishing over OIDC (no long-lived token; npm's
first 0.1.0 used a bootstrap token, revoked at once), and each version was installed from the
live registry into a clean environment before being recorded. npm publishes are staged and
become installable only when a maintainer approves them with a second factor.

| Package | First | Release candidate | Current |
|---|---|---|---|
| `polaris-verify` (PyPI) | 0.1.0, 2026-09-15 | 1.0.0rc1, 2026-09-16 | 1.0.0rc7, 2026-10-01 |
| `polaris-oid4vp` (PyPI) | 0.1.0, 2026-09-15 | 1.0.0rc1, 2026-09-16 | 1.0.0rc14, 2026-10-03 (1.0.0rc7 is the certified one) |
| `polaris-sdk-python` (PyPI) | 0.1.0, 2026-09-15 | 1.0.0rc1, 2026-09-16 | 1.0.0rc7, 2026-10-01 |
| `polaris-id-cli` (PyPI) | 1.0.0rc1, 2026-09-30 | 1.0.0rc1, 2026-09-30 | 1.0.0rc1, 2026-09-30 |
| `polaris-sdk-ts` (npm) | 0.1.0, 2026-09-15 | 1.0.0-rc.1, 2026-09-16, under `next` | 1.0.0-rc.9, 2026-10-03, under `next` |

Every run is recorded in [docs/RELEASING.md](../docs/RELEASING.md). Being installable is not
external use: a download count is not a person.

### External relying party / operator

None.

### Use

    Unique outside users:            0
    Presentations outside CI:        0
    Distinct days used:              0

### Findings from outside

    Bugs/ambiguities filed by non-authors:   1
    Fixed because of external findings:      2

1. walt.id declined the request-signing certificate (above): nobody filed it, but the cause was
   outside this repository. Fixed in v9.465.
2. 2026-09-17: an outside reviewer's five design-intent observations, answered in
   [docs/DESIGN-INTENT-REVIEW.md](../docs/DESIGN-INTENT-REVIEW.md). One was a defect and is the
   filed ambiguity: the README stamped the tree's version while its status line named the
   published one. Fixed the same day. The reviewer is not named, so this is not validated
   external evidence; three observations were answered "intentional" with measurements.

### Independent security review

None. No pentest, red team, threat-model review or cryptographic review has been performed by
anyone who did not build this. Self-attack is not a substitute.

### Pilot

None. Nothing has run with real people, real operators or real consequences.

### Known limitations, held here and not in ROADMAP.md

Qualifications on the evidence above, not a plan. One leaves this list when an outside party
trips over it.

- **The OpenID path correlates more easily than the native privacy path.** A plain SD-JWT VC
  presentation is exposed, never unlinkable; unlinkability is scoped to issuer-side and ZK mode.
- **No native `age_over_21` anonymous credential.** The benchmark's first scenario is met by a
  disclosed attribute, not an anonymous predicate.
- **An offline status assertion's maximum lifetime rests partly on relying-party policy.** The
  issuer mints a one-hour TTL and `expires_at` is signed and enforced; a caller that wants a
  lower ceiling passes `max_window_seconds`. The artifact's own `max_window_seconds` is NOT
  signed, so a verifier must never read it (`check_status_assertion_window_is_caller_policy`);
  removing it is a wire change for the next format version.
- **Algorithm deprecation is not signed runtime policy**: it lives in `CryptographicAlgorithm`
  rows, not in anything a verifier is handed.
- **The physical token is an emulator and a specification**, not certified silicon; enrollment
  proofing has not been field-tested.

---

## Internal readiness (NOT external evidence)

Run by the author against the author's own code; none of it counts toward the 180-day line.

- **The product boundary, on every push.** `scripts/polaris-product-boundary-drill.py` builds each
  package, installs it outside the repository with `PYTHONPATH` and every `POLARIS_*` variable
  stripped, asserts the forbidden runtime surface is absent (Flask, psycopg2, the application and
  check layers), and verifies genuine and tampered ML-DSA material; each package has a negative
  control that must be caught.
- **Material this project did not make.** `packages/polaris-oid4vp/testdata/conformance-suite-capture.json`
  is a `direct_post.jwt` response built by the conformance suite's own wallet (Nimbus JOSE); it
  decrypts under this package's ECDH-ES and verifies, and is refused under another nonce, another
  audience, or with one disclosure rewritten.
- **The conformance drill.** `scripts/polaris-oid4vp-conformance-drill.py` runs the Foundation's
  plan against a local suite with both negative controls.
- **Refusals under mutation.** The SDK drill inverts 175 refusals across both SDKs and the
  detached verifier and the OID4VP drill 106; each must be caught by a test, with declared
  exceptions and a negative control.
- **The lab's three questions have answers.** [lab/linkability](linkability/README.md): no adversary
  advantage beyond the anonymity set, which is the epoch's membership. [lab/duress](duress/README.md):
  the evidence did not support "compulsion-resistant", so the word is "duress-aware".
  [lab/crypto-migration](crypto-migration/README.md): agility is real issuer-side and a software
  release verifier-side.

How each of these came to be, including the defects found building them, is in the git history
and [docs/history/](../docs/history/README.md).

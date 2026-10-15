# Negative test vectors for SD-JWT VC presentations

**Reader:** anyone building or testing a verifier of SD-JWT VC presentations under OpenID4VP 1.0 and
HAIP 1.0, with or without Polaris. **What it is:** [`vectors.json`](vectors.json), 36 presentations a
verifier must judge, each with the verdict a correct verifier reaches. Each of the 33 refusals carries the
clauses it rests on and a `class` saying how directly they require the refusal.
[Lab record 018](../../strategy/018-negative-vectors.md) explains why it exists and what would end it.

The public suites test acceptance well and refusal thinly, and a protocol-level suite cannot always see a
refusal: OpenID4VP 1.0 lets a verifier answer a bad presentation with a 2xx and decide later. A vector run
against the verification function sees the verdict directly.

## The vectors

Two **controls** come first: valid presentations, one with the issuer key in an `x5c` chain, one given as
a JWK. A verifier that refuses them refuses everything, and its refusals below mean nothing. A third,
`accept-status-list`, opens the status-list family. Each of the other 33 is a control with exactly one thing
changed, re-signed wherever the change needs it, so the only reason to refuse it is the clause it cites:

| Group | Vectors |
|---|---|
| JOSE | `crit` in the issuer JWT and in the key binding JWT; an ES256 signature DER-encoded |
| Key binding JWT | `aud` or `nonce` missing, `aud` as an array, `aud` without the Client Identifier prefix, `typ` JWT, `alg` none, HS256 keyed with the holder's public JWK, `iat` NaN, `exp` a string |
| Disclosures | a digest committed twice, a claim already in the clear, `exp` or `iss` disclosed, four elements, a claim named `_sd` |
| `x5c` chain | a self-signed leaf, the anchor sent in the chain, an unknown root, an expired leaf, an intermediate that is not a CA |
| The signer is not the named issuer | another issuer's valid leaf under the trusted root signs a credential whose `iss` is the trusted issuer: the leaf names that issuer's URL; names only a DNS host that is not `iss`'s; names that URL and also a host both share |
| Status goes dark | the Token Status List the credential names gives no answer; answers with an HTML page; has a `lst` whose ZLIB stream never ends; is signed by another issuer's key under the same root; sits at a uri no key is stated for; has expired; does not reach the credential's index |

**The signer is not the named issuer** is the class of swiyu change dossier CD-008 (2026-07-31), in which a
verifier accepted a credential signed by an attacker's key while its `iss` named a trusted issuer. Its shape
differs: there the key was a DID named by `kid` and checked against `iss`; here it is an `x5c` leaf, where
SD-JWT VC draft-19 s2.5 makes the leaf's subject the issuer ("the Issuer of the Verifiable Digital Credential is the
subject of the end-entity certificate") and refuses a credential whose key cannot be validated as the Issuer's, and
s7.3 requires that "the integrity of the relationship between the iss value of the SD-JWT, if present, and the
public keys of the Issuer" be kept. The family
holds `x5c` cases only and targets verification whose issuer key comes from `x5c`. polaris-oid4vp refuses all
three there; no vector is graded under its `--issuer-jwks` mode, which is documented not to bind `iss` to a key
(its README: "list one issuer's keys per verifier"), and each vector's `notes` says so.

**Status goes dark** vectors carry `status_list`: the `uri` the credential names and the `response` a GET of it
returns (`null`: no answer). Each is judged under the `policy` it names, `status-required` (in the file's
`policies`): the credential is accepted only when its list is a Status List Token signed by the key
`settings.status_list_keys` states for its `iss` and that uri, not expired, covering the index, and VALID there.
draft-ietf-oauth-status-list-21 says a failed check means the credential SHOULD be rejected (s8.3: "If any of
these checks fails, no statement about the status of the Referenced Token can be made and the Referenced Token
SHOULD be rejected."); its one MUST about the credential is an index past the list's end (s8.3 step 6). So those
vectors are graded `policy`, never `spec`, and that one is `spec`. polaris-oid4vp keeps each credential authentic and reports the
revocation state (`unreachable`, `list_refused` with its code, `no_authority`, or `checked` for the control); its
`Verifier` refuses on its own only a checked status that is not VALID (`revoked`), and leaves the other states
to the relying party's policy. Each vector's `notes` names its state.

`class` says how strong the requirement is: `spec` when a sentence requires the refusal, `spec-implied`
when the sentence binds the issuer or the wallet, or a definition implies it, `policy` when the text says the
verifier SHOULD refuse and the verdict is the one the vector's `policy` reaches. `layer` says whose job the
refusal is: `jose`, `sd-jwt` (RFC 9901), `sd-jwt-vc` (the profile), `openid4vp`, `haip-x509` (the
issuer's certificate chain), `x5c-issuer` (the binding of `iss` to that chain's leaf) or `status-list` (the
Token Status List). A library that implements only some layers is judged on those alone.

## Run them

```bash
python3 run_vectors.py vectors.json --adapter polaris-oid4vp
```

The `polaris-oid4vp` adapter uses the installed package when there is one (for a release:
`pip install polaris-oid4vp==1.0.0rc16`), else this tree's, and prints the version and path it used.
For it the refusal code counts too: each negative must be refused with the code `POLARIS_OID4VP_CODES` names
(for a status-list vector, the revocation state, with `list_refused`'s code after a slash). It serves each
status list from the vector, in memory: no vector opens a socket.
The run fails when a control is refused or a negative accepted, and also when the file holds no vectors, no
control, or no negative the adapter judged, or when it judges a negative in a layer whose own control
(`accept-status-list` for `status-list`) it left to its caller; a run that passes ends `done`.

An adapter is one function, `(vector, settings) -> ("accept" | "reject", reason)`. `settings` holds the
instant, nonce, audience, credential type, trust anchors (PEM) and issuer JWKs every vector assumes.
Adding a verifier means adding its function to `run_vectors.py`; it answers `n/a` for a layer it leaves to
its caller (a control included). Adapters so far: `polaris-oid4vp`; `sd-jwt-python` (the Python reference implementation of RFC 9901, run
from its own venv: `pip install sd-jwt`); and `sd-jwt-js` (the OpenWallet Foundation's `@sd-jwt/sd-jwt-vc`,
through [`adapters/sd_jwt_js.cjs`](adapters/sd_jwt_js.cjs); `SD_JWT_JS_MODULES` names the folder whose
`node_modules` holds it and `@sd-jwt/crypto-nodejs`).

## How they are made

[`make_vectors.py`](make_vectors.py) derives every key from a public seed and signs with deterministic
ECDSA (RFC 6979), so `python3 make_vectors.py > vectors.json` regenerates the file byte for byte.
**The keys and certificates are test material: never trust them.**
[`test_vectors.py`](test_vectors.py), run in CI:
- the file has not drifted from its generator;
- `polaris-oid4vp` reaches all 36 verdicts with the expected refusal codes, under the default binding, under
  another verifier's, and under the EU test harness's;
- each leaf in the signer family signs an authentic credential when `iss` is the name it gives, so the name is
  the only defect; and a leaf that names nobody is accepted with `iss` unbound (see Limits);
- each status vector leaves the credential authentic with the state its `notes` names, carries the control's
  credential byte for byte where it names the control's index and uri, and is accepted by a verifier that
  checks no status;
- a run with no vectors, no control or no judged negative fails;
- the views equal the generator's output, and a view with no vectors or a missing pair file fails;
- each certificate defect is the only one, because the same chain repaired is accepted.

## Bind them to your verifier

Every Key Binding JWT names one verifier (`aud`, `nonce`) and one instant, so the published file is refused by any
verifier but the one in its `settings`, controls included. Regenerate it for yours:

```bash
python3 make_vectors.py --audience 'x509_san_dns:verifier.test' --nonce 'your-test-nonce' --now 1830297600 --out DIR
```

Two flags are optional: `--issuer-key FILE` and `--holder-key FILE` replace the seeded issuer and holder keys.

Your two settings:
- **the verifier:** `--audience` is your client_id, with its OpenID4VP 1.0 Client Identifier Prefix
  (`x509_san_dns:`, `x509_hash:`, `redirect_uri:`, ..., or `origin:` over the Digital Credentials API;
  `kb-aud-no-prefix` strips it, so one is required: a pre-registered client_id without one cannot be bound), and
  `--nonce` is the nonce your test request carries. `--now` (Unix seconds) is the instant your verifier judges at:
  every `iat`, `exp` and certificate validity moves with it, the expired leaf included.
- **the issuer:** your test configuration trusts the root in `DIR/vectors.json`'s `settings.trust_anchors_pem`
  (for the `x5c` vectors) and the key in `settings.issuer_jwks` (for the `jwks` ones). The root depends on `--now`
  only. `--issuer-key` signs every issuer JWT with your own key instead, still under the generated root.

`--issuer-key` and `--holder-key` are PEM files holding an unencrypted P-256 private key, PKCS#8 (`PRIVATE KEY`)
or SEC1 (`EC PRIVATE KEY`), for example from `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`.
Without binding flags, `python3 make_vectors.py > vectors.json` reproduces `vectors.json` byte for byte, and
`python3 make_vectors.py --out .` run in this directory (or `--out` naming it) reproduces `vectors.json` and
`views/` byte for byte.

## Views

[`views/`](views) holds the same vectors in layouts other suites read. They are derived from the generator
(`python3 make_vectors.py --out .`) and never edited by hand; the test fails on any difference.

- [`views/eudi/`](views/eudi): the EU reference verifier's test-resource layout. Vector N of `vectors.json`
  (from 0) is the pair `<50+N>-<id>-dcql.json` (the transaction-init body: the DCQL query for the control's
  claims, the nonce, `request_uri_method` post) and `<50+N>-<id>-vpToken.json` (`{"pid": [<presentation>]}`).
  Numbering starts at 50 so it collides with nothing there, and follows the file's order so an added vector
  never renumbers one. `INDEX.json` is the index below. Its [`README.md`](views/eudi/README.md) gives the
  binding it carries and the command and settings that bind it to the EU test harness.
- [`views/index.json`](views/index.json): one entry per vector, `id`, `spec_section` (the first clause),
  `target` (the layer), `input` (the presentation), `expected`, `hardening` (true for `spec-implied` and `policy`),
  `reference_rejected_at_mint`, `clauses`, `trust`, `profile`, `files` (its EU pair), and `policy`, `status_list` and
  `notes` where the vector has them. `profile` is `haip`
  for every vector: the KB-JWT `typ` is `kb+jwt`, as the header's `scope` says. A verifier that requires another
  KB-JWT typ (for example `kb+sd-jwt`) refuses the controls at the key-binding layer; for such a verifier only the
  issuer-signed cases apply, checked on their own. `reference_rejected_at_mint` is
  polaris-oid4vp's verdict when the views were made: the generator runs every vector through
  `run_vectors.py`'s `polaris-oid4vp` adapter with the vectors' own settings, as `test_vectors.py` does (this
  tree's package, else an installed one). Making the views therefore needs polaris-oid4vp.
- [`views/expected-failures.example.json`](views/expected-failures.example.json): where a consumer lists the
  vectors its verifier does not yet refuse. We ship it empty and list nobody's exceptions. The file is a JSON
  array; each entry is `{"test-name": <vector id>, "expected-result": <the verdict the verifier reaches today>,
  "reason": <why>, "link": <the tracking issue>}`. `test-name` and `expected-result` follow the conformance
  suite's expected-failures files; `reason` and `link` are ours.

## Credits

The signer family takes its class from swiyu change dossier CD-008, "VC Authorization Bypass" (published
2026-07-31; swiyu-admin-ch/swiyu-admin-ch.github.io, `_change-dossiers/CD-008-Critical-Vulnerability-Generic-Verifier.md`).

The views take their shapes from others' work: the mint-time reference verdict and the hardening flag from
goodmeta/ap2-conformance (Apache-2.0); the index fields `spec_section`, `target`, `input` and `expected` from
reallyme/openid4vp's test vectors; the pair layout from the EU reference verifier's test resources
(eudi-srv-verifier-endpoint, Apache-2.0); and the exceptions file from the OpenID Foundation conformance
suite's expected-failures files (MIT). Nothing of theirs is copied into this directory.

## Limits

- One credential type and one issuer profile; the response layer (`direct_post.jwt` encryption) has no vectors yet.
- A leaf that names no issuer at all (no subjectAltName) is not a vector: draft-19 makes `iss` optional with
  `x5c` and the issuer the leaf's subject, so no verdict follows. polaris-oid4vp accepts such a credential and
  reports its `iss` apart as unbound.
- The signer family is for `x5c`. A verifier configured with several issuers' JWKs can bind `iss` to a key only
  by a mapping the vectors do not carry.
- The `sd-jwt-python` and `sd-jwt-js` adapters have not been run against 0.3.0, so nothing here says how they judge
  the two new families.
- A status-list vector needs its `response` served at its `uri` and the verifier held to its `policy`; the EU
  view carries neither, so a run of that view judges the credential alone.
- A verdict is pass or refuse. Why a verifier refused is compared for polaris-oid4vp only; for any other
  adapter, a refusal for the wrong reason counts as a pass.
- Version 0.3.0 (0.2.0 plus the signer and status-list families; `settings.status_list_keys`, `policies`, the
  `policy` class and the vector fields `policy`, `status_list` and `notes` are new). 0.2.0 added `kb-aud-missing`
  and `kb-nonce-missing`. Vectors may be added, and none will change meaning under the same id.

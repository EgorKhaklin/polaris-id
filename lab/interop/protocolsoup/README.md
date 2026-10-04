# ProtocolSoup (holder) → polaris-oid4vp

[ProtocolSoup](https://github.com/ParleSec/ProtocolSoup) (Apache-2.0) is an interactive sandbox
for identity and access protocols. Its wallet harness, `backend/cmd/walletharness`, is a
standalone OpenID4VP wallet in Go, and v4.0.0 is the release the OpenID Foundation lists as a
certified OpenID4VP 1.0 + HAIP 1.0 wallet. Here that harness, built unmodified at the v4.0.0
commit, presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp` as
installed from PyPI.

The harness is a service with a headless JSON API (its browser UI calls the same endpoints), and
it does the work:
- it makes the holder key, which `/api/session` names as a `did:jwk`;
- before it stores a credential (`/api/import`) it fetches the issuer's key from the
  credential's `iss` (`/.well-known/jwks.json` there) and checks the signature; it binds a
  credential to the wallet's DID by `sub`, and refuses one without it;
- it resolves the request (`/api/present`): the signed request object fetched by POST with a
  wallet nonce, its `x5c` chain checked against the verifier anchor it was configured with, the
  launch URI's client_id compared with the request's, the DCQL query matched against the stored
  credential; then it builds the presentation (the requested disclosures and a key binding JWT
  signed with its key) and posts the response, encrypted to the verifier's key (`ECDH-ES`).

[`walk.py`](walk.py) does only what is outside the wallet. It is the issuer: a key under a CA
made for the run, its JWKS served over HTTPS at the `iss`, and one `urn:eudi:pid:1` credential
per wallet, bound to the harness's key by `cnf` and to its DID by `sub`, signed with
[`../waltid/issue_sdjwt_vc.py`](../waltid/issue_sdjwt_vc.py)'s functions (that script's payload
has no `sub`). And it is the user: it hands the harness the credential and the launch URI and
approves the presentation (`approve_external_trust`), as a person does in the harness's UI.

The harness is configured only by environment:
- `WALLET_TARGET_BASE_URL` is the verifier's origin. The harness refuses `.internal` names and
  private addresses for any host but this one and the issuer's. It does not make Polaris the
  wallet's own verifier, whose callback would be `<origin>/oid4vp/response`, so the harness
  treats Polaris as an external verifier and asks for the user's approval.
- `WALLET_ISSUER_BASE_URL` is the issuer's origin, which the harness exempts the same way.
- `WALLET_DID_METHOD=jwk`, so the holder key can be read from the wallet's DID.
- `WALLET_VERIFIER_X509_TRUST_ANCHOR_PEM` is the CA `polaris-oid4vp keygen` made for the
  verifier.
- `SSL_CERT_FILE` is the image's CA bundle plus the verifier's and the issuer's listener
  certificates, the TLS registration a counterparty makes for a test verifier. No check is
  turned off.

## Versions

- ProtocolSoup at commit `97d306cafa3a005dd01c1641b13c9b5abb6bcc19` (tag v4.0.0), the harness
  only, compiled in `golang:1.26.5-alpine` pinned by digest (the Go version ProtocolSoup's
  `docker/Dockerfile.wallet-harness` uses), with every module checked against ProtocolSoup's own
  `go.sum`. The browser UI is not built: the JSON API needs none.
- The OpenID Foundation's test plan for the listing names commit `105282f`. Built there, the
  harness refused this verifier's launch URI (`request_uri_method "post" is not supported`).
  Launched without that parameter, it fetched the request by GET and then would not answer it:
  `direct_post.jwt is only supported for trusted verifier callbacks`, which at that commit means
  its own configured verifier only. Commit `36a4102`, between that commit and v4.0.0, added the
  POST fetch and the encrypted response to an external verifier, and keys an SD-JWT `vp_token` by
  the DCQL query id, which OpenID4VP 1.0 requires and this verifier checks.
- `polaris-oid4vp` 1.0.0rc15 from PyPI.

## Run it

    lab/interop/protocolsoup/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/protocolsoup/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- ProtocolSoup's `backend/` at the pinned commit (that one commit, fetched sparse), and the
  harness compiled from it in the pinned Go image for the machine Docker runs on;
- the verifier's test PKI, the issuer's keys and its JWKS server, three harness containers (one
  per trust configuration), and a credential for each, bound to that harness's key;
- the presentation and the six controls.

It exits 0 only if the presentation is accepted and every control is refused. Docker and git are
required. The verifier listens on port 9485 (`PORT`); the issuer and the three harnesses take the
next four ports.

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer CA | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; the harness: `the verifier answered 400` |
| (b) | The same request presented again after it was answered | the verifier, at the request | the harness: `request_uri POST returned 404: ... no such outstanding request` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the wallet | the harness: `request object client_id "x509_hash:..." does not match URI client_id "x509_hash:AAAA..."` |
| (d) | The wallet trusts an unrelated CA for the verifier | the wallet | the harness: `request object verification failed: validate request object x5c chain: ... x509: certificate signed by unknown authority` |
| (e) | The wallet trusts a different listener certificate | the wallet | the harness: `tls: failed to verify certificate: x509: certificate signed by unknown authority` |
| (f) | The credential is signed by a key its `iss` does not publish | the wallet, at import | the harness: `validate issuer signature (issuer_trust=failed): credential signature verification failed` |

(c) and (d) are controls on the harness: the user approved both presentations, and the harness
still compared the request object with the link it was launched with and applied the verifier
anchor it was configured with; the approval stands in for neither check. (e) shows the listener
certificate is checked: the run adds trust for it and turns nothing off. (f) shows the issuer's
signature is checked before a credential is stored. The verifier ignores the key the harness
fetched: it trusts only the CA it was given, which is what (a) shows.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI, with ProtocolSoup v4.0.0 on Go 1.26.5: accepted,
`<- 200 authentic, claims ['cnf', 'family_name', 'given_name', 'iat', 'iss', 'sub', 'vct']`. The
harness reported the verifier's 200, the `x509_hash` request object verified, Polaris treated as
an external verifier and the presentation approved. All six controls were refused. From empty
caches (no Go image, module or build cache) the harness built in 13 s and the whole run took 29 s,
on a shared machine.

## What this does not establish

- It is the harness at the listed release, run as a service and driven through its JSON API; the
  issuer, the user's approval and the TLS trust are this repository's lines. The harness keeps
  keys and credentials in memory, per session.
- The credential was minted by this repository under a CA made for the run, and the harness
  fetched the issuer key from a server the run started. One credential format and one path,
  ES256 throughout.
- The verifier's origin was named in `WALLET_TARGET_BASE_URL` so that the harness would reach a
  `.internal` host; the run says nothing about the harness under its default configuration.
- Polaris answers an accepted presentation with a `redirect_uri`; the harness declined to follow
  one whose host is a `.internal` name, so the redirect step was not exercised.
- Same category as the other rows: the author drove a published wallet on one machine. It is not
  an outside party using Polaris, and not a claim of interoperability in general.

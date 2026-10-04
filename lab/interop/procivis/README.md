# Procivis One Core (holder and issuer) → polaris-oid4vp

[Procivis One Core](https://github.com/procivis/one-core), Procivis's Rust credential engine
(Apache-2.0), presents an SD-JWT VC over OpenID4VP 1.0 `direct_post.jwt` to `polaris-oid4vp` as
installed from PyPI. Procivis also issued the credential, under a certificate whose CA the
verifier is given, so the verifier is the only Polaris software in the exchange.

One `core-server` instance, built from source at the pinned tag, holds two organisations: an
issuer and a holder. [`procivis.py`](procivis.py) makes the REST calls an operator would make and
nothing else. Procivis does the work:
- its issuer makes a key and a certificate signing request for it; the walk's test CA certifies
  the key, naming `procivis.test`. Procivis signs the credential (`dc+sd-jwt`, `urn:eudi:pid:1`,
  `given_name` and `family_name` as disclosures) with that certificate alone in `x5c`;
- its issuer offers the credential over OpenID4VCI 1.0 and its holder accepts the offer, bound to
  a holder key Procivis made;
- its holder resolves the OpenID4VP request (`x509_hash`, the signed request object, which it
  fetches by GET, the DCQL query), builds the presentation (the disclosures and the key binding
  JWT) and sends the response, encrypted to the verifier's key (`ECDH-ES`).

The verifier trusts the issuer only through `--issuer-trust-anchor`, the CA certificate. With
`x5c` the credential's `iss` must be a name the certificate carries, and Procivis writes its base
URL into `iss`; the certificate names `procivis.test`, so the base URL is
`https://procivis.test`. `core-server` serves plain HTTP, so [`tls_front.py`](tls_front.py)
terminates TLS for that name inside its container. Procivis's OpenID4VP is its own, beside
walt.id's, Credo's, eudi-dev's, OID4VCgo's, the EU reference library's and vck's.

## Run it

    lab/interop/procivis/run.sh
    POLARIS_OID4VP=polaris-oid4vp==1.0.0rc15 lab/interop/procivis/run.sh

[`run.sh`](run.sh) runs everything in a scratch directory (`WORK`):
- `polaris-oid4vp` from PyPI in a fresh venv, its dependencies by hash;
- Procivis One Core v1.87.2, downloaded at commit `8b701da8` and checked against its SHA-256,
  then built with cargo from the lockfile it ships (`--locked`), `-j 4`, in a Rust image pinned
  by digest. The upstream Dockerfile starts from an image on Procivis's own registry, so there is
  no image to pull. The binary, cargo's registry and the target directory stay in named volumes,
  so only the first run builds: a cold build took 13.6 minutes here (8 arm64 cores under Docker
  Desktop, cargo's default parallelism, other builds running);
- the test PKI: the verifier's (`polaris-oid4vp keygen`), the issuer CA
  ([`pki.py`](pki.py)), a TLS certificate for `procivis.test`, and a fresh API token and
  encryption keys for `core-server`, made for the run and never written into the tree;
- `core-server` on SQLite ([`procivis.yml`](procivis.yml) over Procivis's own base
  configuration), in the same image, trusting for TLS the system store plus the certificate for
  `procivis.test` and the verifier's listener certificate;
- the credential, issued and accepted, then two presentations, launched by `openid4vp://` and
  `haip-vp://` (Procivis's `OPENID4VP_FINAL1` and `OPENID4VP_FINAL1_HAIP` holder profiles; the
  second accepts only `x509_hash`), then the four controls, launched by `haip-vp://`.

It exits 0 only if both presentations are accepted and every control is refused. Docker is
required. The verifier listens on port 9484 (`PORT`) and `core-server`'s REST API on
127.0.0.1:9485 (`API_PORT`).

## Controls

| | What changed | Refused by | What it said |
|---|---|---|---|
| (a) | The verifier trusts a different issuer CA | the verifier | `<- 400 refused: issuer_key: the x5c leaf does not chain to any configured trust anchor`; Procivis reported the `400` from the response endpoint |
| (b) | The same request presented again after it was answered | the verifier, at the request | Procivis: `Error while fetching authorization request`, `404`, `no such outstanding request` |
| (c) | The launch URI names a `client_id` that is not the signed request's | the holder | Procivis: `Invalid request: client_id mismatch with the request token` |
| (d) | The holder's TLS trust holds an unrelated certificate in place of the verifier's listener certificate | the holder | Procivis: `error sending request for url (https://host.docker.internal:9484/request.jwt?...)`; its log: `failed to verify TLS certificate: invalid peer certificate: BadSignature` |

(c) is a control on Procivis: it compares the signed request object with what it was launched
with. (d) restarts `core-server` on the same database with the other certificate in its trust
store. That certificate names the same host, so the listener's certificate was checked against
it and refused (`BadSignature`): the holder does not fetch a request from a listener it cannot
authenticate.

## Result, 2026-10-04

Against `polaris-oid4vp` 1.0.0rc15 from PyPI, with Procivis One Core v1.87.2 (`core-server`,
Rust 1.95.0): Procivis issued the credential and its holder stored it (`ACCEPTED`). Both
presentations were accepted, `<- 200 authentic, claims ['cnf', 'family_name', 'given_name',
'iat', 'iss', 'nbf', 'vct']`, and Procivis reported the proof `ACCEPTED`. All four controls were
refused.

The credential's header carries `x5c` (the issuer's certificate, without the CA), `x5t#S256` and
an `x5u` on `procivis.test` that the verifier does not fetch; its `iss` is an https URL on
`procivis.test` and it has no `exp`.

The build uses upstream's lockfile unchanged. OSV lists 14 advisories against 11 of its 782
crates.io packages (2026-10-04), all in `core-server`'s dependency graph as the lockfile records
it: seven unmaintained notices (bincode 1.3.3, bitmaps 2.1.0, im 15.1.0, proc-macro-error 1.0.4,
proc-macro-error2 2.0.1, sized-chunks 0.6.5, smallstr 0.3.1) and seven soundness or panic
advisories (git2 0.20.4 twice, im 15.1.0, rand 0.8.5, rkyv 0.7.46, serde_with 3.16.1,
sized-chunks 0.6.5).

## What this does not establish

- It is Procivis One Core's server driven over its REST API, not the Procivis One wallet app.
  The core is the part that speaks OpenID4VCI, OpenID4VP and SD-JWT VC: it issued, stored,
  fetched, checked and answered. The certificates and the TLS trust are this repository's few
  lines, as they are any deployment's.
- The issuer and the holder are one instance, two organisations. The credential crossed
  Procivis's own OpenID4VCI endpoints between them, over TLS, but it never left the container.
- The credential carries no status (the schema names no revocation method), so this run says
  nothing about revocation.
- One credential format and one path, ES256 throughout.
- Same category as the other rows: the author drove a published implementation on one machine.
  It is not an outside party using Polaris, and not a claim of interoperability in general.

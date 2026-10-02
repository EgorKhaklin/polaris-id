# Integrating with Polaris

**Reader:** someone connecting a system to Polaris: a relying party that verifies credentials, a
wallet, an issuing authority, or a peer authority. **Job:** point you at the right door and the
self-test that proves your integration before you touch a live instance.

Polaris is pre-pilot software on notional data; [PRODUCTION-READINESS.md](PRODUCTION-READINESS.md)
is the bound on what it may be claimed to do. Two properties hold across every door: the
verification path returns no personal data and keeps no who-verified-whom record, and authenticity
is checkable offline against published keys with no Polaris code.

---

## 1. You verify Polaris credentials (a relying party)

- **Offline, no network.** `pip install polaris-verify`, then check a presentation against the
  authority's published keys. The cleanest proof is [STRANGER-PATH.md](STRANGER-PATH.md): a clean
  machine to an accepted presentation.
- **Online, for authoritative status.** The stable `/api/v1` API answers whether a credential is
  authentic and currently authoritative. It is described by one machine-readable contract,
  [reference/openapi.yaml](reference/openapi.yaml); generate a typed client in your language with
  [`scripts/polaris-gen-api-clients.sh`](../scripts/polaris-gen-api-clients.sh) instead of
  hand-writing HTTP. The quickstart (register, get a token, verify in a few lines) is
  [reference/API-CLIENTS.md](reference/API-CLIENTS.md).
- **Self-test.** The conformance runner drives YOUR verifier in any language:
  `python conformance/run_conformance.py --verifier "<your command>"`. The contract and the frozen
  version-1 protocol are in [../conformance/SPEC.md](../conformance/SPEC.md).

## 2. A wallet presents to, or is issued by, Polaris

- **Present a credential (OpenID4VP, HAIP).** Polaris's verifier is OpenID Certified to the
  OID4VP 1.0 + HAIP 1.0 Verifier profile (`polaris-oid4vp`). A wallet fetches the signed request
  object and posts an encrypted response.
- **Reach a local instance in one command (dev/eval).**
  [`scripts/polaris-dev-tunnel.sh`](../scripts/polaris-dev-tunnel.sh) stands up a verifier and a
  public HTTPS URL a wallet anywhere can reach, using your own cloudflared tunnel, with no domain,
  DNS or certificate to provision. The design and its bounds are
  [../lab/strategy/010-dev-tunnel.md](../lab/strategy/010-dev-tunnel.md).
- **Obtain a wallet copy (OpenID4VCI).** Each agency with a wallet-copy key is a credential issuer
  at `/api/v1/oid4vci/<agency_id>/...`, with issuer metadata at the `.well-known` paths.
- **Self-test.** The outside-wallet and OpenID Foundation conformance assets are under
  [../lab/interop/README.md](../lab/interop/README.md).

## 3. You run Polaris to issue (an issuing authority)

- **Deploy.** Dev: `./polaris_mac_launch.sh`. Production: the Helm chart under `deploy/helm/` or the
  systemd install under `deploy/linux/`, behind your own domain and TLS.
- **Keys plug in.** Your signing keys live in an HSM over PKCS#11, or in AWS KMS (ML-DSA-65); see
  [`polaris_web/custody.py`](../polaris_web/custody.py) and the custody compose overlays.
- **Self-test.** [`../lab/strategy/006/try.sh`](../lab/strategy/006/try.sh) is one command: issue a
  credential and verify it with the published verifier, on a clean build.

## 4. You federate with Polaris (a peer authority)

Trust is explicit and non-transitive. Publish and consume the signed trust list, federation
manifest, epoch checkpoint and revocation feed (`/api/v1/trust-list/<agency_id>` and its siblings);
a relying party then decides a foreign credential offline. The protocol is
[design/inter-authority-protocol.md](design/inter-authority-protocol.md).

---

## Where to go next

- Every endpoint, in prose: [reference/API.md](reference/API.md) (the machine form is
  [reference/openapi.yaml](reference/openapi.yaml)).
- The normative wire formats, so an implementation importing no Polaris code can interoperate:
  [reference/WIRE-SPEC.md](reference/WIRE-SPEC.md).
- What is and is not built: [../ROADMAP.md](../ROADMAP.md). What the outside has done with Polaris:
  [../lab/EXTERNAL-NOUNS.md](../lab/EXTERNAL-NOUNS.md).

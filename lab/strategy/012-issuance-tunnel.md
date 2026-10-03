# 012: An issuance tunnel, so a wallet can get a credential copy from a local issuer

**Opened 2026-10-02.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-02 (build the issuance half of the round-trip, so a wallet
completes issue, hold, present and verify from a clone in one command). State: OPEN. The falsifiers
in section 10 were written before the build; section 11 records what they found. This is the third
step of the connector track: the first was an OpenAPI contract for `/api/v1` and a client generator
(#185, #188), the second a dev tunnel that makes a LOCAL verifier reachable by a wallet (record 010).

---

## The finding that started it

The dev tunnel (010) makes the VERIFIER reachable: a wallet anywhere can send a presentation to a
local Polaris and get a verdict. It does not make the ISSUER reachable, and says so in its own
header: "The issuer/app issuance path is a separate, data-bearing surface and is NOT tunnelled by
this script." So an evaluator can see the second half of the round-trip (present, verify) but not
the first (a wallet GETS a credential copy from Polaris). Getting a wallet to receive a copy over
the internet today needs the full production path: a public domain, DNS, TLS, and an issuer
certificate whose subjectAltName names that domain, because the OID4VCI issuer identifier is read
from the wallet-copy key's leaf certificate (`credential_copy_keys.credential_issuer`), not from the
request host. That is the wall between "a wallet verified against my local Polaris" and "a wallet
was issued by, held, and then presented to my local Polaris".

- **Kept:** the production issuer path (a real domain, the agency's own PKI, a leaf whose SAN URI
  names the public issuer); the rule that no credential traffic routes through a Polaris-operated
  service (MISSION; the commercial mandate's "hosted Verify must not become a correlation point");
  the dev tunnel's refusal to run in production; the separation of the wallet-copy signing key from
  custody.
- **Dropped:** that issuance can be reached only by owning a public domain and provisioning an
  agency certificate for it first, and the dev tunnel's implicit corollary that issuance stays off
  the tunnel because the only way to put it on would expose the whole application.
- **New position:** an evaluator exposes ONLY the OID4VCI wallet-facing endpoints of a LOCAL issuer,
  over their OWN tunnel, with a TEST copy-key certificate minted for the tunnel host at start, so a
  wallet completes the pre-authorized-code flow and receives a copy. Every other path (the operator
  console, the relying-party API, the offer-minting route, sign-in) is refused before it reaches the
  application. Polaris operates no relay, the data is notional, and the script refuses to run in
  production.

## 1. What capability is being considered?

A one-command issuance tunnel (`scripts/polaris-issuance-tunnel.sh`) that:

- refuses to run under `POLARIS_ENV=production`, and refuses if cloudflared is absent, with how to
  get it (as 010 does);
- starts a cloudflared quick tunnel and reads back the public https URL;
- mints a TEST wallet-copy certificate chain whose leaf SAN URI is
  `https://<tunnel-host>/api/v1/oid4vci/<agency>` (`scripts/polaris-credential-copy-test-pki.py`,
  already in the tree), so the issuer identifier the metadata and every offer advertise is the
  tunnel URL;
- serves the application on the loopback behind a request filter that forwards ONLY the OID4VCI
  wallet-facing paths (the two well-known metadata shapes, `/token`, `/nonce`, `/credential`, the
  status list) and answers 403 to every other path, so the operator console, the relying-party API,
  the offer-minting route and sign-in are never reachable through the tunnel;
- prints the issuer URL, the test anchor to register with the wallet, and the LOCAL command the
  operator runs to mint a credential offer (against the loopback, not the tunnel), and cleans up
  both processes on exit.

## 2. What problem would it solve?

The round-trip (issue, hold, present, verify) cannot be exercised end to end by an outside wallet
without the full production issuer path. The verifier half is one command (010); the issuer half is
not. This closes that gap for a demo or an evaluation, without exposing anything but issuance.

## 3. Who would plausibly need it?

Wallet implementers running the OID4VCI pre-authorized-code flow against Polaris (the interop thread
with an outside wallet project); evaluators who want to see a credential arrive in a real wallet,
not only a verdict; the conformance and interop story, where "a wallet was issued by Polaris" is a
stronger, more external sentence than "a wallet verified a fixture". No one has asked for it by
name: this is a bet, which is why it is recorded here.

## 4. What existing systems already solve it?

The dev tunnel (010), for presentation only. A hand-rolled ngrok or cloudflared pointed at the whole
application, which exposes the operator console and the relying-party API to the internet and still
needs an issuer certificate minted for the tunnel host by hand. The production path (a domain, DNS,
TLS, the agency PKI), which is the right answer for a deployment and the wrong amount of work for an
evaluation.

## 5. Can Polaris interoperate instead of rebuild?

Yes, almost entirely. The OID4VCI endpoints exist (`oid4vci_routes.py`, record 005). The copy-key
certificate minter exists (`scripts/polaris-credential-copy-test-pki.py`). cloudflared is the
operator's own. What is new is small: a request filter that enforces the issuance-only allowlist, a
launcher that wraps the application's WSGI callable with it, and the orchestrator script. Nothing is
added to the product application's behaviour: the filter and launcher are development tooling under
`scripts/`, and the application served is the ordinary one, with paths refused in front of it.

## 6. What unique advantage could Polaris obtain?

The full round-trip as plug-and-play, run on the operator's own tunnel with no Polaris-operated
relay and so no correlation point, which is the property the mission and the commercial mandate both
require of any hosted convenience. An evaluator can get a credential into a wallet and then present
it back, in minutes, from a clone.

## 7. What happens if Polaris does NOT build it?

The verifier tunnel stands; issuance stays a production-path exercise. An evaluator either provisions
a domain and an agency certificate to see issuance, or skips the issuer half and verifies a fixture.
Nothing breaks; the round-trip demo stays half a command short.

## 8. What other work would be delayed?

Little. This is lane-2 connector tooling and touches no product route, no schema object and no check.
It does not go before the THREAT-MODEL work in flight (#55's trigger and gates, #213's
migration-window fixes); it is built beside them.

## 9. Can the idea be tested cheaply in LAB first?

Yes. The filter's allowlist is a pure function of path and method, unit-tested against the real route
table: every wallet-facing path passes, and a representative set of non-issuance paths (sign-in, the
operator console, the relying-party verify route, the SQL console, the offer-minting route) is
refused, including path-normalization attempts (`..`, encoded dots, doubled slashes). The round-trip
itself runs locally through the filter without cloudflared: mint a test key for a loopback issuer
URL, create an offer, and drive token then credential through the filtered callable, asserting a copy
comes back and that the same client is refused on a non-issuance path. A failure leaves a local
process, not a broken release.

## 10. What evidence would prove the bet was wrong?

Any one of these, written before the build:

- the request filter cannot in fact keep a non-issuance route unreachable (a path the application
  routes but the allowlist does not refuse, found by the drill in section 9), so the scoping buys
  nothing and the tunnel exposes more than it demonstrates;
- the issuer identifier cannot be made the tunnel URL without editing the product application (the
  metadata or an offer still advertises the loopback), so a wallet cannot follow the flow over the
  tunnel and the capability does not exist;
- the operator console, the relying-party API or any other data-bearing route is reachable through
  the tunnel in the drill, so the tool is net-negative and must be pulled rather than shipped;
- ninety days after it lands, no wallet or evaluator outside the repository has used it to receive a
  copy, as [EXTERNAL-NOUNS.md](../EXTERNAL-NOUNS.md) would record.

---

## 11. What the falsifiers found

Written after the build, by `polaris_web/test_issuance_tunnel.py` and `scripts/test_issuance_scope.py`:

- **The filter keeps every non-issuance route unreachable.** The scope drill drives the pure
  predicate over the wallet paths and a set of the application's other surfaces, plus
  path-normalisation attempts (`..`, `//`, encoded dots, trailing segments, non-numeric agency); the
  round-trip test cross-checks the filter against the application's real route table (`app.url_map`),
  and the filter admits exactly the eight wallet rules and refuses every other route the application
  serves. The first falsifier did not fire.
- **The issuer identifier becomes the tunnel URL without touching the application.** The certificate
  minted for the tunnel host carries it, and the metadata and every offer read it from the
  certificate. A wallet completes the pre-authorized-code flow through the filter and receives a copy
  (nonce, token, proof over the c_nonce, credential). The second falsifier did not fire.
- **No data-bearing route leaks.** The offer-minting route, sign-in, the operator console and the
  relying-party API are 403 through the filter, in the test and in a live smoke on 2026-10-02 (the
  metadata and nonce answered 200; sign-in, the offer route, the console and the root answered 403).
  The net-negative falsifier did not fire.
- **Open:** the ninety-day external-use falsifier stands, as [EXTERNAL-NOUNS.md](../EXTERNAL-NOUNS.md)
  would record. State remains OPEN until a wallet or evaluator outside the repository uses it.

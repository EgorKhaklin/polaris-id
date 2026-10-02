# 010: A dev tunnel, so a wallet can reach a local verifier

**Opened 2026-10-02.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-01 ("a tunnel setup for plug in play ... seamless integration
with the outside world"). State: OPEN. The falsifiers in section 10 were written before the build;
section 11 records what they found. This is the second step of a connector track; the first (an
OpenAPI contract for `/api/v1` and a client generator) shipped as #185 and #188.

---

## The finding that started it

The biggest "plug and trouble" barrier is that there is no "run it locally and point a wallet at
it" path. Any real stack needs `POLARIS_DOMAIN` set to a public name, public DNS pointing at the
host, and ports 80/443 internet-reachable before first start, because Caddy auto-provisions a
certificate and because the OID4VP verifier metadata must advertise an origin a wallet can fetch.
An evaluator who wants to see a wallet present to Polaris must therefore provision a domain and TLS
first. That is the wall between "I cloned it" and "a wallet talked to it".

- **Kept:** the production path (Caddy + a real domain + ACME, or an external terminator) for a
  real deployment; the rule that no credential presentation routes through a Polaris-operated
  service (MISSION; the commercial mandate's "hosted Verify must not become a correlation point").
- **Dropped:** that the only way to be wallet-reachable is to own a public domain and terminate TLS
  yourself before you can see the system work at all.
- **New position:** an evaluator makes a LOCAL verifier reachable by a wallet anywhere with one
  command, using THEIR OWN tunnel, with the verifier advertising the tunnel's origin in its
  metadata. Polaris provides the deployability options and a convenience script; it operates no
  relay, and the script refuses to run in production.

## 1. What capability is being considered?

Two deployability options on the certified verifier (both EXT-INTEROP, each with its own test), and
one convenience script (this record's STRATEGIC-BUILD):

- `polaris-oid4vp serve --public-base-url URL` (shipped #187): the `request_uri` and `response_uri`
  a wallet fetches are URL, not `https://host:port`, so a verifier behind a proxy or tunnel
  advertises a reachable origin.
- `polaris-oid4vp serve --no-local-tls` (shipped with this record): the local listener is plain
  HTTP on `--bind`; the proxy or tunnel terminates the public HTTPS the HAIP profile requires.
- `scripts/polaris-dev-tunnel.sh`: starts a cloudflared quick tunnel (the integrator's own, no
  account), reads back the public https URL, mints a test certificate for the tunnel host, and
  serves the verifier bound to localhost advertising the tunnel URL. One command from clone to
  wallet-reachable. Refuses `POLARIS_ENV=production`.

Not in this record: the OpenID4VCI ISSUANCE tunnel. The app's credential-issuer identifier is
derived from a certificate SAN, so making issuance reachable through a tunnel needs a dev-only
origin override that fails to start in production. That is a separate, data-bearing surface and is
deferred to its own step.

## 2. What problem would it solve?

The gap between cloning Polaris and watching a real wallet present to it. Today that gap is a public
domain plus TLS plus DNS; the tunnel closes it to one command on a laptop.

## 3. Who would plausibly need it?

- The owner, by direction.
- Any evaluator or prospective pilot operator who wants to see a wallet present to a Polaris verifier
  before provisioning infrastructure.
- Us, for the interop walks: a wallet on a phone reaching a verifier on a laptop.

## 4. What existing systems already solve it?

cloudflared quick tunnels (no account), ngrok, tailscale funnel: all terminate TLS and give a public
HTTPS URL to a local port. Nothing is invented; the work is making the verifier advertise the
tunnel's origin and serve the plaintext origin a terminator expects, and refusing to do either in
production.

## 5. Can Polaris interoperate instead of rebuild?

Entirely. The tunnel is a third-party tool the integrator runs. Polaris adds two serve options and a
convenience script that wires them to cloudflared.

## 6. What unique advantage could Polaris obtain?

A ten-minute path from "git clone" to "a wallet presented to my verifier over the public internet,"
with no account, no domain, and no credential traffic touching a Polaris-operated service. The
anti-"plug and trouble": the trial that closes an evaluation.

## 7. What happens if Polaris does NOT build it?

The first thing an evaluator tries, pointing a wallet at it, is the first thing that fails without
hours of infrastructure work, and most never get past it. The certified verifier's value is
invisible until a wallet can reach it.

## 8. What other work would be delayed?

Nothing on the other lane. On this track, the OID4VCI issuance tunnel and the connector catalog wait
behind this, which is correct: reachability precedes them.

## 9. Can the idea be tested cheaply in LAB first?

Yes, and it was (section 11): one machine, a cloudflared quick tunnel, and a remote fetch of the
verifier's wallet-facing endpoints through the public URL.

## 10. What evidence would prove the bet was wrong?

Written before the build. Any one falsifies the claim it names:

1. **A Polaris-operated relay.** Any part of the tunnelled path routes credential or presentation
   traffic through a service Polaris runs. The tunnel must be the integrator's own.
2. **Real data behind a quick tunnel.** The tooling makes a non-notional or production instance
   publicly reachable; it must refuse rather than expose it.
3. **Origin mismatch.** After tunnelling, a wallet's flow fails because the advertised origin
   (`request_uri`, `response_uri`) does not match the tunnel URL, or the endpoints are unreachable
   through it.
4. **It leaks into production.** The dev-tunnel script or the plaintext listener is a production
   default rather than an explicit, dev-gated choice.
5. **It still needs manual DNS or TLS.** Standing up and tunnelling still requires provisioning a
   domain, a DNS record, or a certificate by hand.

## Kill criterion

If, by 2026-12-31, no external party has used the dev tunnel to reach a Polaris verifier with a
wallet (a row on the scoreboard), it reverts to lab and the product keeps only the production origin
path.

## 11. What the falsifiers found (the verifier dev tunnel, 2026-10-02)

Run on one machine. `cloudflared tunnel --url http://localhost:9444` returned a public
`https://<name>.trycloudflare.com` with no account, no DNS record and no certificate;
`polaris-oid4vp serve --public-base-url <url> --no-local-tls` advertised its `request_uri` and
`response_uri` at that URL (with an `x509_hash` client_id); and a remote GET through the PUBLIC URL
reached the verifier: `GET /request.jwt` returned the verifier's own `404 {"error":"not_found", ...}`
and `GET /done` returned `200 text/html`.

- **Falsifier 1 (a Polaris-operated relay):** holds. The tunnel is cloudflare's; Polaris runs
  nothing on the path, and the script uses the integrator's own cloudflared.
- **Falsifier 3 (origin mismatch):** holds. The advertised origin equalled the tunnel URL and the
  wallet-facing endpoints answered through it.
- **Falsifier 5 (manual DNS or TLS):** holds. No domain, DNS record or certificate was provisioned;
  cloudflare terminated the public HTTPS and the local listener was plain HTTP.
- **Falsifier 4 (leaks into production):** holds. `polaris-dev-tunnel.sh` refuses
  `POLARIS_ENV=production`, and `--no-local-tls` is an explicit serve option, never a default.
- **Falsifier 2 (real data behind a quick tunnel):** the verifier holds no credential data; it
  checks presentations. The data-bearing OID4VCI issuance tunnel is out of scope here and carries
  its own guard when built.

Remaining: a full presentation (a wallet completing `direct_post` through the tunnel) is the next
evidence to record, beside the reachability shown here. The scoreboard row is a NAMED external
wallet that presented through the tunnel; until then this is "implemented and externally reachable,"
not "externally exercised".

# Runtime self-protection

**Reader:** an engineer or an assessor. **Job:** The runtime self-protection rules, which are implemented and which are gaps.

Runtime application self-protection is a marketing category for a set of
techniques with one thing in common: detect anomalous behaviour while the
system is running, and answer with something more precise than dropping the
request. This document takes the techniques and leaves the category. It lists
concrete rules, where each is enforced, and which ones are not built.

The rules fall into three layers: bounds on rate, signals on pattern, and what
the edge refuses before a request reaches the application.

## Rate bounds

| Rule | Where it is enforced | The bound |
|---|---|---|
| Per-IP, on authentication | `security.py`, through the Redis limiter | Ten requests a minute on `/login` and the WebAuthn assertion endpoints |
| Per-IP, on read paths | `security.py` | Sixty requests a minute on the verification and Atlas endpoints |
| Per-IP, at the edge | The Caddy `rate_limit` zone `polaris_global` | Two hundred requests a minute, before anything reaches the application |
| Per-agency, per kind | `enforce_agency_quota`, a database trigger | Operator-configured caps on issuance, revocation and verification in a rolling window |
| Per-agency revocation share | `enforce_revocation_velocity_bound`, a database trigger | A share of the agency's issued base (every credential it has issued, any status) per window, above which a co-signature is required |

The per-IP limits and the edge limit are defence in depth against brute force
and scraping. The two database triggers are the ones that bound an
*authorised* party, which is the harder problem and the one
[abuse-controls.md](abuse-controls.md) and
[issuer-discretion.md](issuer-discretion.md) cover in full.

**The gap.** There is no bound on how often one agency may verify one
individual. The quotas are per agency and per kind, so an agency inside its
cap can direct all of it at a single person. A cap on the pair, enforced in
the same transaction as the verification insert, would close it. This is the
single highest-value rule not built, because bulk attestation aimed at one
holder is a coercion pattern rather than a load pattern.

## Pattern signals

Detection is separate from enforcement on purpose: a bound refuses, a signal
tells a human something is happening. All of these are Prometheus alert rules
in `deploy/observability/polaris-alerts.yml`, each with a runbook section that
`check_alert_runbooks` keeps in step.

| Signal | What it watches |
|---|---|
| `PolarisDuressEvent` | Any duress code matching, at severity one with no delay |
| `PolarisIssuanceVelocity` | An agency issuing far above its own trailing week, over an absolute floor |
| `PolarisRevocationVelocity` | The same, for revocations |
| `PolarisVerificationVelocity` | The same, for verifications, which is the closest thing to a bulk-attestation signal today |
| `PolarisQuotaRefusals` | A cap actually refusing writes, which is as often a misconfiguration as an attack |
| `PolarisHigh5xx`, `PolarisHighRequestLatency`, `PolarisHighDBLatency` | The service degrading |
| `PolarisAppDown`, `PolarisAppInfoAbsent` | The service gone |

**The gaps.** Two signals do not exist. Failed authentications are counted, in
`auth_failures_per_minute`, but no alert rule fires on a spike from a single
address, so the counter is visible on a dashboard and pages nobody. And no
signal watches an individual receiving an unusual number of verifications,
which is the detection half of the missing rate bound above.

## What the edge and the headers refuse

Security headers are set by `apply_security_headers` in `security.py`, on
every response:

- `Content-Security-Policy` with `script-src 'self'`, which is C5 and is
  checked per route.
- `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`.
- `Referrer-Policy: strict-origin-when-cross-origin`.
- `Permissions-Policy` denying camera, microphone, geolocation, payment, USB,
  Bluetooth and the advertising-topics interfaces.
- `Cross-Origin-Opener-Policy` and `Cross-Origin-Resource-Policy`, both
  `same-origin`.
- `Strict-Transport-Security`, in production only.
- The `Server` header removed at the edge.

TLS terminates at Caddy, which provisions its own certificate and negotiates
the X25519MLKEM768 hybrid key exchange, proven against a real certificate in
CI on every push.

**The gap.** There is no web application firewall, and none is planned. The
SQL boundary is parameterised throughout, so injection is structurally
prevented rather than filtered, and a firewall in front is a deployment
decision an operator makes with their own provider. It is listed here so that
its absence is a stated choice rather than an oversight.

## The open list, in order

1. **A per-agency-per-individual verification bound**, enforced in the
   verification transaction. Anti-coercion, and the largest gap.
2. **An alert on that pattern**, so the bound has a detection half.
3. **An alert on authentication-failure spikes per address**, using the
   counter that already exists.

Everything else in this document is either built and named above, or
deliberately out of scope.

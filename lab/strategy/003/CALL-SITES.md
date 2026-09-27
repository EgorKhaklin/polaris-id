# 003 call sites: every signing entry point, by format and surface

Measured 2026-09-27. Static: an AST walk of `polaris_web/` and `polaris_cli/` for every call of
`pqc_signing.signature_over_message`, `signature_with_key_for_token`, `signature_bytes_for_token`,
`signature_for_migration` and `sign`, each traced to the route or command that reaches it.
Dynamic: [`record_signing_calls.py`](record_signing_calls.py) ran the whole of
`polaris_web/test_app.py` (904 tests, 0 failed, 3 skipped, placeholder profile, scratch database
`polaris_signer`) with every entry point and every custody driver's `sign` wrapped
([`out/recorded_calls.json`](out/recorded_calls.json)). The dynamic run found no signing path
missing from the static list, and no custody `sign` call outside `pqc_signing`.

Surface: **operator** is a login-gated route or the CLI; **rp** is `/api/v1` except the two
login-gated routes (002). "Format" is the `format` string of the canonical statement.

## Table

| # | Call site | Format signed | Route or command | Surface | Seen in suite |
| --- | --- | --- | --- | --- | --- |
| 1 | `use_case_routes.py:97` `uc1_issue` (`signature_with_key_for_token`) | **none: raw token_value** (issuance) | `POST /uc1/issue` (login, admin/operator) | operator | yes (44) |
| 2 | `use_case_routes.py:622` `uc6_migrate` (`signature_with_key_for_token`) | **none: raw token_value** (re-issue) | `POST /uc6/migrate` (login) | operator | yes (1) |
| 3 | `migration.py:157` `migrate_batch` (`signature_for_migration`) | **none: raw token_value** (population re-sign) | CLI `polaris migrate-population` | operator (CLI) | yes, called directly (37) |
| 4 | `polaris_cli/polaris.py:2115` `cmd_bulk_enroll` (`signature_with_key_for_token`) | **none: raw token_value** (bulk issuance) | CLI `polaris bulk-enroll` | operator (CLI) | no (CLI not in test_app) |
| 5 | `federation_routes.py:244` `_sign_attestation` | `polaris-trust-attestation/1` | `POST /api/federation/attest` (login, admin) | operator | yes (2) |
| 6 | `rp_api.py:473` `api_v1_epoch_leaves` | `polaris-epoch-leaves/1` | `GET /api/v1/epoch/<id>/leaves` | rp | yes |
| 7 | `rp_api.py:586` `_holder_binding_for` | `polaris-holder-binding/1` | `POST /api/v1/holder-key`, `POST /api/v1/holder-binding` | rp | yes |
| 8 | `rp_api.py:738` `api_v1_status_assertion` | `polaris-status-assertion/1` | `POST /api/v1/status-assertion` | rp | yes |
| 9 | `rp_api.py:828` `api_v1_mdoc` | **bare 32-byte digest** (SHA3-256 of a COSE Sig_structure over the mdoc MSO) | `POST /api/v1/mdoc` | rp | yes |
| 10 | `rp_api.py:922` `api_v1_verifiable_credential` | **bare 32-byte digest** (SHA3-256 of the W3C VC body) | `POST /api/v1/verifiable-credential` | rp | yes |
| 11 | `rp_api.py:1056` `_federation_manifest_body` | `polaris-federation-manifest/1` | `GET /api/v1/federation-manifest/<id>`; LTV of `POST /api/v1/sign/<id>` and `/sign/<id>/holder` | **both** | yes (rp) |
| 12 | `rp_api.py:1158` `_epoch_checkpoint_body` | `polaris-epoch-checkpoint/1` | `GET /api/v1/epoch-checkpoint/<id>`, status bundle; LTV of both sign routes | **both** | yes (rp) |
| 13 | `rp_api.py:1219` `_revocation_feed_body` | `polaris-revocation-feed/1` | `GET /api/v1/revocation-feed/<id>`, status bundle; LTV of both sign routes | **both** | yes (rp) |
| 14 | `rp_api.py:1333` `api_v1_federation_status_bundle` | `polaris-federation-status-bundle/1` | `GET /api/v1/federation-status-bundle/<id>` | rp | yes |
| 15 | `rp_api.py:1447` `_build_exchange_receipt` | `polaris-exchange-receipt/1` | `POST /api/v1/exchange-receipt/<id>` (login); `POST .../<id>/signed` (service-signed, real PQC only); `POST /api/v1/exchange/<id>` (gateway) | **both** | no (placeholder profile) |
| 16 | `rp_api.py:1586` `_timestamp_body` | `polaris-timestamp/1` | `POST /api/v1/timestamp/<id>`; LTV of both sign routes | **both** | yes (rp) |
| 17 | `rp_api.py:1823` `api_v1_registry` | `polaris-registry/1` | `GET /api/v1/registry/<id>` | rp | yes |
| 18 | `rp_api.py:2048` `_sign_document` | `polaris-signed-document/1` | `POST /api/v1/sign/<id>` (login); `POST /api/v1/sign/<id>/holder` (possession) | **both** | yes (rp path) |
| 19 | `rp_api.py:2328` `api_v1_auth_token` | `polaris-id-token/1` | `POST /api/v1/auth/token` | rp | yes |
| 20 | `rp_api.py:2365` `api_v1_trust_list` | `polaris-trust-list/1` | `GET /api/v1/trust-list/<id>` | rp | yes |
| 21 | `rp_api.py:2428` `_sth_body` (no `agency_id`: the global key) | `polaris-transparency-sth/1` | 6 `GET /api/v1/transparency/...` and inclusion routes; `_anchor_timestamp` | rp | yes |

Out of scope but noted: `polaris_card/personalization.py` takes an `issuer_sign(digest)` callback
(a bare-digest signer); nothing in `polaris_web/` or `polaris_cli/` wires it today, only
`scripts/polaris-personalization-drill.py`. A future wiring would be a bare-digest signing path the
signer cannot parse. `scripts/` drills and the transparency ledger import `pqc_signing` too; they are
operator tooling, not a web surface.

## Formats signed by both surfaces

| Format | Operator use | Relying-party use | Same meaning? |
| --- | --- | --- | --- |
| `polaris-exchange-receipt/1` | operator mints a receipt for a responder it may act for | the responder's own service (authenticated by a mint statement under its registered key) or the gateway mints it | **Yes.** One builder, same attestation check, same receipt. Only the caller's authentication differs. |
| `polaris-signed-document/1` | the institution signs a digest in its own name (`on_behalf_of: null`) | the authority signs for a holder proved by possession (`on_behalf_of: {credential_hash}`) | **Same format, different assertion.** The field that says whose act it is sits inside the statement, so a per-format policy cannot tell them apart; a policy would have to read `on_behalf_of`. |
| `polaris-federation-manifest/1`, `polaris-epoch-checkpoint/1`, `polaris-revocation-feed/1`, `polaris-timestamp/1` | long-term-validation evidence inside an operator-signed document | the public endpoints, and LTV inside a holder-signed document | **Yes.** The same builder at an instant; both are views over the database. |

## Formats by kind

- **Issuance / credential:** raw token_value (sites 1-4; operator and CLI only). Rendered credentials
  on the rp surface: mdoc and VC (9, 10, both passed as bare digests).
- **Trust decision:** `polaris-trust-attestation/1` (operator only); `polaris-federation-manifest/1`,
  `polaris-trust-list/1`, `polaris-registry/1` (**rp**).
- **Status:** status assertion, holder binding, revocation feed, epoch checkpoint, epoch leaves, status
  bundle (all rp).
- **Evidence:** exchange receipt, timestamp, signed document, STH, id token (rp, three also operator).

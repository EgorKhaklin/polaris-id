# The operator console: information architecture and design system

**Reader:** anyone changing a page of the operator console, or judging whether it shows Polaris
as it is. **Job:** say what the console is for, how it is organised and why, what it looks like,
and which rules every page keeps.

Decided 2026-10-01 at the owner's direction: the console is rethought from the system Polaris
is now, not restyled from the one it began as. The first version was organised around the use
cases it was built from (UC-1 to UC-12, a "PROOFS" menu); Polaris since gained a relying-party
API, holder keys, wallet copies, transparency logs, federation, an authority key register and a
governance layer that the console never showed.

## Who it serves

- **An evaluator** who has never seen Polaris: the first ten minutes (sign in, issue a credential,
  verify it, revoke it, see the verdict change) explain themselves and claim nothing the
  [readiness ledger](../PRODUCTION-READINESS.md) does not.
- **An operator** at an authority in a pilot: find a person or credential, act on it, see the
  consequence before an irreversible step, work from a queue.
- **An auditor or reviewer**: read the policy in force, the logs, and the role gates, without any
  write path.

## Information architecture

Navigation names places; actions live on the thing they act on. A credential's page offers the
actions that credential admits (activate a reserve, bind a device, migrate its algorithm, revoke
it, offer a wallet copy); the use-case forms stay as routes those actions open. Use-case ids
remain as small secondary labels for readers of the design records.

| Group | Pages | Roles |
|---|---|---|
| Overview | Status and signing mode, queues that need attention, population, recent activity | all |
| Registry | Credentials, People (with enrolment), Authorities | all; edits admin |
| Operations | Issue a credential; Recovery queue | admin, operator (queue all) |
| Verification | Verification log, record a verification | all; record admin, operator |
| Transparency | Anchor batches, anonymity epochs, federation | all |
| Governance | Athena (constitution, authority, proof, trust); read-only views of keys, algorithms, relying parties and policy as they are added | all |
| Analytics | Atlas | all |
| Audit | Warrant audit, the signals queue, SQL console | admin, auditor |

Renamed: Dashboard to Overview, Tokens to Credentials, Individuals to People, Agencies to
Authorities, "PROOFS" to Transparency. Removed: the "USE CASES" menu (its entries are actions on a
credential or a person, or the Operations group). Added: the signing mode and environment on every
page, and the Governance group.

Governance stays read-only in the console. Keys, quotas, discretion bounds, retention and
relying-party registration are the schema owner's acts through the CLI; the console runs as
`polaris_app` and gains no write path by showing them.

## Visual system

- **Identity.** Khaklin Technologies is monochrome: black and white grounds, hairlines, widely
  tracked uppercase captions, the owl in a Greek-key ring. Polaris brings navy and gold from its
  logo, which is used byte for byte and never redrawn. Gold marks the current place and the
  brand; colour otherwise carries state only. No glows, gauges or game styling.
- **Themes.** Dark (the default) and light, chosen by the viewer and stored per browser; both are
  token sets in `polaris_web/static/polaris.css`. Every text token clears 4.5:1 on every ground in
  both themes, every input border 3:1.
- **Type.** Inter for the interface, JetBrains Mono for identifiers, hashes and instants, Cinzel
  for the POLARIS wordmark only.
- **Third-party assets** are self-hosted and unmodified, with their sources, licences and SHA-256
  in `polaris_web/static/vendor/VENDOR.md`: Inter, JetBrains Mono, Cinzel (OFL), Lucide icons (ISC,
  a sprite built by `scripts/polaris-vendor-icons.py`), MapLibre GL JS (BSD-3-Clause).

## Rules every page keeps

- **CSP C5:** no inline script; behaviour lives in `static/*.js` loaded with `defer` (the theme
  script loads first, before paint).
- **Roles:** a navigation entry is shown only to the roles its route admits.
- **An operator's page never names the duress mechanism** in any wording. The signals queue and its
  entry exist for admin and auditor only.
- **Honest labels:** pre-pilot, notional data, and the signing mode in force, on every page.
- **Scale:** lists are server-paged and filtered, never one unbounded table.
- **WCAG 2.2 AA**, held by `scripts/polaris-accessibility-drill.sh` on every operator surface.

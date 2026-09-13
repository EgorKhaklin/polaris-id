# Duress codes

**Reader:** an engineer or an assessor. **Job:** The duress-aware verification path: which coercer cannot see it, and which can.

A verification either succeeds or fails, and a coercer standing over the
holder can read that result. So the holder under coercion has no move: refusing
is visible, and complying is indistinguishable from consent. The vocation above
the ten constraints says no person can be compelled to surrender their identity
against their will, and this is the mechanism that gives that sentence
something to stand on.

The answer is old and comes from banking and high-security retail: a second
credential that looks exactly like success to whoever is watching, while an
alert goes out through a channel the watcher cannot see.

## The four pieces

1. **`IdentityToken.duress_code_hash`**, a nullable column holding a scrypt
   hash of the holder's duress code. NULL means the holder has not enrolled
   one, which is the default.
2. **`DuressEvent`**, an append-only table. One row per detected signal, and
   one of the audit-of-record instances, because an alert whose history can be
   edited is not an alert.
3. **`uc12_record_duress`**, the procedure that writes the row. It refuses
   calls for a token with no enrolled duress code.
4. **The verification flow**, which accepts an optional code, checks it, and
   writes the event silently when it matches.

## What the coercer sees

Four branches exist: no code enrolled and none supplied; no code enrolled and
one supplied; a code enrolled and the wrong one supplied; a code enrolled and
the right one supplied. Only the fourth writes a `DuressEvent`.

All four produce the same redirect, the same flash message, the same
`VerificationEvent` row carrying the operator's requested outcome, and the same
rendered page. The only difference is a row in a table the operator's screens
do not show.

Timing is the obvious way that could leak, and three things address it. The
comparison uses Werkzeug's `check_password_hash`, the same primitive that
checks operator passwords, chosen because it is constant-time rather than
because it is convenient. `_check_and_record_duress` performs the hash
comparison whenever the token has an enrolled hash, so the work is paid on the
negative path as well as the positive one. What remains is the database write
on a match, which is below the variance of the surrounding request. A no-op
write on the negative path would close even that, and is not built.

## Keeping it off the operator's screen

The operator is the surface a coercer can observe, so it is the surface that
must be blind:

- The verification list does not join `DuressEvent`, so the row count cannot
  be inferred from the operator's own history.
- The form field is labelled neutrally. The word duress does not appear on the
  operator's screen, and the field carries `autocomplete="off"` so the browser
  does not remember a typed code.
- `/duress` and `/api/duress/events` require the admin or auditor role, and
  the navigation link to the queue is hidden from the operator role.

`DuressCodeTests.test_anti_revealing_verifications_list_excludes_duress` logs
in as an operator, which is the role the property protects, and asserts the
page never contains the word.

An attacker who has compromised an admin account can see the events. That is
inherent: the audit of record has to be readable by someone. The design
separates the front-of-house signal from the audit signal, so compromising the
verification surface is not enough, and reading the audit needs a privilege
escalation that is independent of it.

## Where the alert goes

Today the row is the alert. An admin or auditor watching `/duress`, or the
API, or the metric, sees signals as they arrive, and `duress_events_total`
feeds `PolarisDuressEvent`, which pages at severity one with no delay. That is
the load-bearing path: a duress code that raises a row nobody reads makes the
whole mechanism decorative.

`DuressEvent.oob_channel` enumerates the channels a production deployment
would add, an SMS gateway, a chat webhook, a security event stream, under a
CHECK constraint. Only the audit-table and stderr values are wired. The column
is there so that adding a channel is wiring rather than a migration.

`oob_notified_at` is the acknowledgement field, set once when a responder
takes the alert. Nothing sets it yet; the workflow that would is not built.

## Where an adversary ends up

- **The claim.** A duress code produces an appended, immutable event and an
  operator-visible outcome identical to an ordinary verification.
- **The direct attack.** Coerce the holder to verify, and watch the operator's
  screen for a tell. This succeeds only if the operator-visible surface
  differs, which is why the three measures above are structural rather than
  cosmetic.
- **Where it settles.** The front of house cannot distinguish, so the attacker
  must attack the back: an admin or auditor session, or the database directly.
  Both need a privilege escalation the verification surface does not provide.
- **The next attack.** Timing. Addressed by the constant-time comparison and
  by paying the comparison cost on both paths; what remains is one database
  write, below the noise floor.
- **What it costs.** A holder who enrols has a second secret to remember, and
  enrolment is therefore optional. Not every holder will have one, and the
  mechanism is per-token opt-in rather than universal.

Three safeguards hold this up: the constant-time comparison with matched work
on both paths, the omission of the events from every operator surface, and the
role gate on the queue. Removing any one of them degrades the property.

## What is deliberately not built

- **No holder-side panic button.** The code is typed on the verifier's
  terminal. A holder-device signal would be a stronger mechanism and a
  different system.
- **No external notification channels.** The column names them; the wiring is
  an operator integration.
- **No defence against long-run frequency analysis.** Constant-time comparison
  covers a single call. An attacker measuring aggregate rates over a long
  period could in principle infer how often duress events occur, which is
  accepted rather than solved.
- **No acknowledgement workflow.** The field exists; the responder-facing
  process does not.

## Reading the code

- `polaris_sql/01_schema.sql`: the `duress_code_hash` column with its
  well-formedness check, and the `DuressEvent` table.
- `polaris_sql/05_procedures.sql`: `uc12_record_duress`.
- `polaris_sql/06_triggers.sql`: `trg_duress_event_append_only`.
- `polaris_sql/10_auth.sql`: the notional demo enrolment in the sample data.
- `polaris_web/app.py`: `_check_and_record_duress`, the verification
  extension, `/duress`, and the two API routes.
- `polaris_web/test_app.py`: `DuressCodeTests`.
- [audit-of-record.md](audit-of-record.md): why the event table is append-only.

# DEVNOTES/known-gotchas.md

Things that have wasted my time. Skip the rediscovery.

---

## Database

### `reload_sample_data()` operates on whatever DB `POLARIS_DB_NAME` says

Pre-v6 it was hardcoded to `polaris_test`, which silently wiped the
wrong database when tests ran with `POLARIS_DB_NAME=polaris_test_clean`
set. The 2M synthetic stress data evaporated this way. Fixed in v6 via
`os.environ.get('POLARIS_DB_NAME', 'polaris_test')`. Confirm before
running tests.

### `ca.algorithm_name` doesn't exist

The column on `CryptographicAlgorithm` is `name`, not `algorithm_name`.
Caught me when I wrote `11_atlas.sql`. The table-prefix convention
isn't applied to the column.

### Postgres needs restarting between bash turns in this sandbox

The cluster goes away between agent turns. Use `pg_ctlcluster 16 main
start`. It will report "Removed stale pid file" and recover. Wait ~5 s
for "consistent recovery state" before reconnecting. Add `for i in
$(seq 1 30); do …; done` polling for robustness.

### Test admin account locks itself out

After F01_AuthenticationTests runs 5+ wrong-password attempts. To
unlock: `UPDATE AppUser SET locked_until=NULL,
failed_login_count=0`. The bootstrap script has a `--fix` mode for
this.

### `psql -h /var/run/postgresql -U postgres` fails with "Peer authentication failed"

Use `su postgres -c 'psql …'` to switch UID first. The peer auth check
happens against the OS user, not the `-U` flag.

### Postgres docker volume drift

If the password in env doesn't match what the docker volume was
initialized with, all auth fails. The launcher's
`docker_compose_up_with_heal` auto-detects this signature in db logs
and wipes the volume. If running outside the launcher: `docker compose
down -v && docker compose up`.

---

## Application code

### `script-src 'self'` blocks all inline scripts and event handlers

CSP is set in `security.py::apply_security_headers()`. It blocks all inline
executable `<script>` blocks AND all inline event-handler attributes
(`onclick=`, `onsubmit=`, `onchange=`, etc.). **v8.46 cleaned this up
in templates**: the heartbeat moved to `static/heartbeat.js`; the
6 `onclick`/`onsubmit`/`onchange` handlers became `data-confirm="…"`
and `data-submit-on-change` attribute opt-ins served by
`static/confirm-submit.js`; `verifications_form.html` and
`sql_console.html` got their own dedicated external scripts.

The only remaining inline `<script>` is the `<script id="atlas-globe-data"
type="application/json">[]</script>` **data-island** at `atlas.html:157`:
this is correct because the browser places the tag in the DOM (readable
via `getElementById`) but never executes it (`type` is `application/json`,
not JavaScript). No CSP violation.

**What the check actually pins:** `check_csp_forbids_unsafe_inline` reads
`polaris_web/security.py` and fails if `script-src 'self'` is absent or if any
directive carries `'unsafe-inline'` for scripts. It does NOT scan the templates,
so a stray inline handler in a template is caught at runtime by the browser's CSP
and by the app's response tests, not by the check layer. Keep inline JavaScript
out of templates on that basis, not on the belief that a check will catch it.

**If you need inline JS for any reason: don't.** Add a new
`static/*.js` file and load it via `<script src="..." defer></script>`.
See `confirm-submit.js` for the attribute-driven opt-in pattern.
Never add `'unsafe-inline'` to CSP.

### `{{ … }}` in HTML comments breaks Jinja

Even comments are parsed for template tags. If you have curly braces
in a comment, write `{# … #}` (Jinja comment) or escape them. Caught
me in `atlas.html`.

### Two unique-pattern conventions exist

Some indexes are `uq_*`, others `idx_*`. Match the surrounding
convention; don't introduce a third.

### `nodeSelection.each()` blew up before any data arrived

Pre-v6 the static `var nodeSelection = ...enter().append(...)` chain
guaranteed nodeSelection was always defined. Post-v6, render is
async: first redraw fires before fetchData() completes. Always
null-guard: `if (nodeSelection) nodeSelection.each(...)`.

### Filter chips broke clusters

`isVisibleByFilter()` originally returned `Boolean(d.tokenId)` for the
'tokens' filter. Cluster nodes don't have `tokenId` (they aggregate
many), so all clusters got hidden. Fix: clusters bypass the filter
entirely; the filter chip's effect is communicated server-side via the
`kind` parameter.

---

## Tooling

### `stat -f` means different things on macOS vs Linux

On macOS (BSD): `-f` is "format string" (`stat -f %m file` → mtime
unix timestamp). On Linux (GNU): `-f` is "filesystem stats" (prints
useless filesystem info, NOT mtime). Detect kernel:

```bash
if [[ "$(uname)" == "Darwin" ]]; then stat -f %m "$f"
else                                  stat -c %Y "$f"
fi
```

This bit `polaris_mac_launch.sh` once. Fixed in v5.

### `awk match($0, RE, arr)` with the array argument is gawk-only

Linux base awk (mawk on Ubuntu/Debian) doesn't support the third array
argument. Use Python or grep-based parsing for portability.

### Playwright `wait_for_load_state("networkidle")` hangs on this site

Heartbeat fetches every 10 seconds → "networkidle" never reached.
Use `wait_until="domcontentloaded"` plus `wait_for_timeout(N)`.

### Background gunicorn dies when the parent shell exits

`setsid nohup … &` keeps it running across shells, but if the calling
script ends with `kill -9 $APP_PID` the child dies. For Playwright
runs, keep gunicorn alive in the SAME Python process via
`subprocess.Popen` with explicit `terminate()` after.

### `pg_dump --schema-only` includes `SET` statements that fail in CREATE DATABASE

If you migrate schemas via `pg_dump`, prepend `--no-owner
--no-privileges` or strip the `SET ROLE` lines. Polaris uses
`00_load_all.sql` instead, which is portable.

---

## Behavioral

### "Larping": VANTA's named pattern to monitor

Cosmic-significance framing instead of concrete building. When I write
"This represents a substrate-level shift in identity infrastructure
sovereignty…" instead of "I added an index," I'm larping. Name the
pattern when it appears, in either of us.

### Premature scope creep

When VANTA asks for X and I do X+adjacent improvements, I burn budget
on stuff he didn't request. The marginal cost of completeness is near
zero IF X is what was asked; adding Y costs token budget that could
have been spent finishing X. Stick to scope unless the adjacency is
load-bearing for X.

### Dangling threads at session end

Token budget runs out mid-task. The honest move is to stop, name what
isn't done, and document where to pick up. Pretending the bundle is
shipped when the zip step wasn't reached is worse than admitting the
session ended mid-execution.

---

## Frontend / atlas

### d3 `enter.merge(sel).classed(...)` sometimes fails to attach the class

Symptom: every probe shows the d3 selection has the right size and the
right data, but the class never lands on the DOM elements. v8.2 / V2
hit this when adding `.node-fresh` to entering reticles: classed()
through enter+merge silently no-op'd.

Fix: skip the `enter.merge(sel)` form. Re-`selectAll('g.d3-globe-node')`
after the enter pass and apply via `.each(function (d) { if (...)
this.classList.add(...) })`. Also works as `.classed()` on the full
post-render selection.

This took ~30 minutes to debug because cache (browser AND server) made
it look like the JS edit wasn't even running. **Always verify the JS
served by the dev server matches disk** before debugging logic.

### Browser caches `/static/*.js` even with `?v=` query parameters

Symptom: edit JS, reload page, behavior unchanged. The browser keeps
the cached resource even when its URL gets a fresh query string,
*sometimes*. Empirical observations:
- Same URL with no query → always cached
- Same URL with same `?v=X` query → cached
- Same URL with different `?v=X` query → usually fetches fresh, NOT
  always; depends on Cache-Control headers Flask sends
- New URL (different query string AT NAVIGATION TIME) → reliably fresh

Reliable reset: navigate to `/atlas?nuke=$(date +%s)` (a NEW URL with a
random param): this forces Flask to re-render the template, and any
new `?v=` in that template lands. Just hard-reloading the same URL
sometimes doesn't.

The `?v=` query parameter on `/static/*.js` is a content hash, so
identical content keeps the same URL (cache stays useful) and any
edit changes the URL.

### Postgres function overloading silently keeps both signatures

Symptom: edit `11_atlas.sql`, change a function's parameter list, run
`\i 11_atlas.sql`. The OLD signature is still callable; PostgreSQL
overloads. Two atlas_clusters_verifications now exist; the planner
picks one based on argument types, often picking the wrong one.

Fix: `DROP FUNCTION IF EXISTS atlas_clusters_verifications(<exact old
signature>)` BEFORE the `CREATE OR REPLACE`. `CREATE OR REPLACE` only
replaces a function with an identical signature; it creates a new
overload otherwise.

v8.3 hit this when extending atlas SQL functions with optional filter
params. The DROP-then-CREATE pattern is now standard in the file.

### Postgres `TIMESTAMP` (without time zone) is local wall-clock

Symptom: query `WHERE event_timestamp >= '2026-05-09T08:46:24'` returns
zero rows even though there are events at "right now"; the test suite's
`window=1h` filter returned nothing.

Cause: `event_timestamp` column is `TIMESTAMP` (no time zone), storing
the local-time wall clock at insert. Python's `datetime.utcnow()` is
UTC; if the server's local TZ is anything other than UTC, the boundary
shifts by N hours.

Fix: when comparing against a `TIMESTAMP`-no-zone column, use
`datetime.now()` (local) on the Python side. Co-located app + DB
makes this safe; if they're ever split, push the time-boundary math
into SQL via `CURRENT_TIMESTAMP - INTERVAL`.

Caught during v8.3 smoke testing. Documented also in the `_parse_atlas_filters`
helper comment.

---

## Bash / shell

### Backticks inside heredoc'd Python confuse `$()`

Symptom: `OUTPUT=$( python3 - <<'PY' ... PY )` parser fails with
"unexpected EOF while looking for matching `\``" even though the
heredoc body should be literal.

Cause: bash's `$( ... )` parser scans the body for nested old-style
backtick command substitution before checking that the heredoc
delimiter is single-quoted.

Fix: don't put bare backticks in the heredoc body. If you need to match
a backtick in regex, use the character escape or rewrite to avoid it.
Caught when polaris-link-check.sh's regex had `[\'"`]` and the script wouldn't
parse.

### `setsid` doesn't exist on macOS

The standard background-launcher recipe `setsid nohup … &` works on
Linux but not on macOS (no `setsid`). On macOS use plain `nohup … &`
or `(… &)` for a sub-shell. The launcher already handles this; ad-hoc
test scripts have to remember.

---

## Docs / release

### Stale numbers in documents

Symptom: a done-list item once said "134 Python tests" while reality was
200+; the number was correct in v6/v7 and then drifted across many
releases. Since v9.194 `check_stated_counts` and
`check_table_count_matches_doc` re-measure the headline counts on every
run; test-suite totals are still measured by hand and stamped with the
version (README's "Verified, not asserted" table is canonical).

### "is this ready to ship?" checklists, scattered

Every release had to remember: tests green, CHANGELOG updated,
link-check clean, no orphaned debug code, no stale `?v=v8.X` cache
busters. Easy to miss one.

`scripts/polaris-preflight.sh` runs `polaris_checks` plus the link-check and
prints a single verdict. Make this the last step before claiming a
feature is shipped.

---

## Launcher + browser (the v8.51-v8.58 cluster)

The launcher's "watch mode" + browser heartbeat interaction
produced three months' worth of gotchas in 36 hours. Recording the
cluster so future operators don't rediscover any of them.

### "Localhost refused to connect" mid-session had TWO root causes

The user reported this symptom multiple times across v8.51 and
v8.55. Resolved in two parts because the surface had two
independent bugs masquerading as one:

- **v8.51 (browser-background throttling).** Pre-v8.51 the
  launcher's `POLARIS_WATCH_STALE` default was 45 seconds, but
  browsers throttle `setInterval` in hidden tabs to about one
  beat per minute. The moment the user switched away from the
  Polaris tab for more than 45s the heartbeat went stale and the
  launcher ran `docker compose down`. **Fix:** raised the default
  to 180s; added `visibilitychange` / `focus` / `pageshow`
  listeners to `heartbeat.js` so the first foreground-return
  produces a fresh beat. Regression-guarded by
  `check_launcher_stale_threshold_survives_tab_throttling` and
  `check_heartbeat_beats_on_foreground_return`.

- **v8.55 (navigation fires quit beacon).** Pre-v8.55
  `heartbeat.js` wired `pagehide` + `beforeunload` listeners to
  `sendBeacon('/api/quit')`. Both events fire on EVERY page
  navigation, not just tab close. Every intra-site click silently
  wrote `/tmp/polaris-state/quit`, and the launcher's 3s-poll
  watch loop tore down the stack on the next tick. **The browser
  API has no reliable way to distinguish navigation from
  tab-close.** Fix: removed both listeners entirely; the launcher
  now relies on stale-heartbeat alone (about 3 minutes teardown
  latency on actual tab close). Regression-guarded by
  `check_heartbeat_does_not_quit_on_navigation`.

- **2026-09-15 (the quit beacon was honoured unconditionally).**
  The third instance, and the one that had no guard when it
  landed. The beacon means "a tab went away", not "the last tab
  went away", and every open tab writes the same `$QUIT_FILE`.
  Closing the second of two tabs, a reload, or a stale tab from a
  previous session firing as the new stack came up each tore down
  a session somebody was using. Observed with a beacon 46 seconds
  old beside a heartbeat 6 seconds old, the stack going down three
  seconds after it came up; the report was that the launcher
  "isn't launching when I hit it". **Fix:** the beacon is consumed
  and ignored while the heartbeat is under 15 seconds old, and
  staleness decides when the last tab is really gone.
  Regression-guarded by
  `check_launcher_quit_beacon_defers_to_fresh_heartbeat`.

If the symptom returns on a future build, run
`python3 -m polaris_checks.run` and read the launcher rows; one of
them will tell you which root cause came back.

### Session cookie surviving relaunch had TWO root causes too

Same shape as above. Two regressions, sequential fixes.

- **v8.56 (hardcoded compose secret).** `docker-compose.yml`
  hardcoded `POLARIS_SECRET_KEY: 'dev-secret-rotate-in-production'`.
  Same key across launches meant Flask validated old session
  cookies on relaunch, dropping users straight into the
  dashboard. **Fix:** compose reads `${POLARIS_SECRET_KEY:-...}`
  from host env; launcher rotates the env var on every `up` via
  `rotate_session_secret_if_unset`. (Rotating on every `up` was
  itself reversed in v8.100; see below. The compose passthrough
  was not, and is guarded.)

- **v8.58 (early-return bypass).** v8.56's rotation only worked
  when the launcher actually brought up a fresh stack. Both
  `launch_docker` and `launch_native` had pre-existing early-return
  short-circuits firing BEFORE the rotation call. When the
  container was already running, the function returned without
  rotating; the existing container kept its baked-in
  `POLARIS_SECRET_KEY`; the user's cookie kept validating.
  **Fix:** `launch_docker` already-running branch now calls
  `docker compose up -d --force-recreate --no-deps app` after
  rotation; `launch_native` already-running branch kills the
  gunicorn pid and falls through to the normal start path.
  Regression-guarded by
  `check_launcher_applies_session_secret_when_already_running`.

- **v8.100 (the rotation was the bug).** Rotating on every launch
  did invalidate leaked cookies, and it also logged the operator
  out of every tab they still had open. The report was "sometimes
  I'm logged in, sometimes I'm at /login", with nothing on screen
  connecting it to the launcher. **Fix:** the secret is persisted
  to `$STATE_DIR/secret_key` and reused; the v8.56 defense is now
  an explicit operator action (`rm` the file, then relaunch).
  Reuse means the key is at rest in a file under `/tmp`, which is
  multi-user on macOS, so the mode is part of the guarantee:
  `umask 077` on create, `chmod 600` after. Regression-guarded by
  `check_launcher_persists_session_secret_securely`, which also
  pins the compose passthrough, because a hardcoded literal there
  would give every install one published signing key and make the
  rest of this moot.

The combined regression-guard family (six checks across the
launcher-watch-mode surface) is the canonical guard against this
whole class of failure.

It has been a family of *checks* only since 2026-09-20. The six
tests that held it lived in `polaris_web/test_structural_invariants.py`,
and v9.55 deleted that file whole: 16,646 lines, almost all of it
apparatus being cut on purpose, with these guards inside it.
Nothing failed. The citations above are bare names, so the link
check had no path to resolve, and `check_documented_symbols_resolve`
reads only citations that name a file and a symbol together, which
these do not. This document went on naming six
tests, and telling you to run three of them, for 104 days, at the
end of which the class came back (the 2026-09-15 entry above) and
its fix added no test either, because the surface no longer had a
file to put one in. `check_documented_test_citations_resolve` is
what now refuses a named guard that does not exist.

### CSP externalization (v8.46): inline JS is gone from templates

Pre-v8.46, the heartbeat lived as an inline `<script>` in
`base.html` and 6 templates had `onclick=`/`onsubmit=`/`onchange=`
event handlers. CSP `script-src 'self'` blocked all of them at
runtime (browsers silently dropped the handlers). **v8.46 moved
everything to external files:** `static/heartbeat.js`,
`static/verifications-form.js`, `static/sql-console.js`,
`static/confirm-submit.js`. The opt-in pattern for adding a new
confirm-on-submit is `data-confirm="..."`; for submit-on-change
it's `data-submit-on-change`. The only inline `<script>`
remaining is the `application/json` data-island in `atlas.html`
(non-executable; CSP allows it).

**`polaris_checks` (the C5 check)** scans templates and flags any
new inline event-handler attribute or executable `<script>` as
drift. Never add `'unsafe-inline'` to CSP. If you need inline JS,
you do not. Add a new `static/*.js` file.

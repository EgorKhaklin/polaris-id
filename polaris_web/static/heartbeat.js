// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* polaris_web/static/heartbeat.js
 *
 * Browser-presence beacon for the launcher's --watch mode. While this
 * tab is open we POST /api/heartbeat every 10s. The launcher tears
 * the stack down when the heartbeat goes stale (default 180s per
 * v8.51).
 *
 * v8.46: externalized from base.html inline <script> so that
 * `script-src 'self'` (CSP, C5) does not block the beacon.
 *
 * v8.51: visibility + focus + pageshow listeners added. Browser
 * background-tab throttling (~1/min in Chrome/Safari/Firefox) was
 * exceeding the launcher's then-45s stale threshold. The fix raised
 * the threshold AND made the first foreground-return always produce
 * a fresh beat.
 *
 * v8.55: REMOVED `pagehide` / `beforeunload` listeners + the
 * `farewell()` function that called `sendBeacon('/api/quit')`.
 *
 * Why removed: those events fire on EVERY page navigation, not just
 * tab close. Every intra-site click (`/individuals` → `/agencies` →
 * `/tokens` etc.) was firing a sendBeacon to /api/quit, touching the
 * quit-beacon file, and the launcher's watch loop interpreted that
 * as "browser tab closed" → ran `docker compose down` → "localhost
 * refused to connect." Reproduced reliably whenever the user
 * navigated between sections.
 *
 * The browser API offers no reliable way to distinguish "user
 * navigated to another same-site page" from "user closed the tab" -
 * both fire pagehide AND beforeunload. The quit-beacon-on-navigation
 * was fundamentally unsafe.
 *
 * Replacement: the launcher's stale-heartbeat detection (v8.51's
 * 180s default) is the sole shutdown signal. Cost: ~3 min teardown
 * latency on actual tab close vs. the prior near-instant beacon
 * path. Acceptable for a dev launcher; eliminates 100% of the false
 * positives on navigation.
 *
 * The `/api/quit` endpoint still exists server-side (any explicit
 * operator action can hit it directly), it just isn't fired by the
 * browser anymore.
 *
 * No external dependencies. Same-origin only.
 */
(function () {
    var INTERVAL_MS = 10000;

    function beat() {
        try {
            fetch('/api/heartbeat', {
                method: 'POST',
                keepalive: true,
                credentials: 'same-origin',
                headers: { 'Content-Length': '0' }
            });
        } catch (e) { /* ignore, best effort */ }
    }

    // Initial beat + steady-state interval.
    beat();
    setInterval(beat, INTERVAL_MS);

    // v8.51, beat on foreground return. Browsers throttle
    // setInterval in background tabs to ~1/min, which can exceed the
    // launcher's stale threshold. These listeners force a fresh beat
    // the instant the tab becomes user-visible again.
    function beatOnReturn() {
        if (document.visibilityState === 'visible') {
            beat();
        }
    }
    document.addEventListener('visibilitychange', beatOnReturn);
    window.addEventListener('focus', beat);
    // pageshow fires after navigation + bfcache restore (back/forward
    // cache), without this, hitting the back button after a sleep
    // could land on a stale page that wouldn't beat until the next
    // setInterval tick.
    window.addEventListener('pageshow', beat);

    // v8.55: pagehide / beforeunload listeners deliberately ABSENT.
    // See the module docstring for the rationale. Do not add them
    // back without addressing the navigation-vs-tab-close ambiguity.
})();

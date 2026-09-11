#!/usr/bin/env python3
"""
polaris-ui-drill.py — headless-browser UI verification for the Atlas (v9.262).

Drives the REAL Atlas in a bundled headless Chromium (Playwright), so a UI ship
is verified end to end — the JavaScript, the fetches, the live DOM updates — not
just its endpoints. It captures screenshots as evidence AND asserts on the DOM,
so it is a real pass/fail test, not a screenshot dump. This is the instrument
that closes the gap v9.261 shipped with: the live simulation mode's endpoint was
tested, but its live UI had never been watched running.

The drill (roadmap P2.14 S4, live simulation mode): log in, open the Atlas,
confirm the Simulate control is present, click it, and confirm the console
actually streams — the counter climbs — then stop and confirm it halts.

Assumes the app is already serving with POLARIS_SIM_MODE on (scripts/
polaris-ui-drill.sh boots it). Env:
  POLARIS_UI_URL   base URL           (default http://127.0.0.1:5057)
  POLARIS_UI_USER  operator username  (default admin)
  POLARIS_UI_PASS  operator password  (default Admin@123!)
  POLARIS_UI_OUT   screenshot dir     (default ./ui-drill-out)

Exit 0 iff every assertion held; the screenshots land in POLARIS_UI_OUT either way.
"""
import os
import pathlib
import re
import sys
import time

from playwright.sync_api import sync_playwright

URL = os.environ.get("POLARIS_UI_URL", "http://127.0.0.1:5057").rstrip("/")
USER = os.environ.get("POLARIS_UI_USER", "admin")
PASS = os.environ.get("POLARIS_UI_PASS", "Admin@123!")
#: How long to let the streamed counter settle after Stop, and how often to look.
#: The console's ticker fires every 2500ms (atlas-console.js), so one in-flight
#: batch lands within one interval; the deadline is several of those, wide enough
#: that a slow runner never trips it and narrow enough that a simulation which is
#: still running cannot hide inside it (it would add a batch every 2.5s forever).
SIM_SETTLE_DEADLINE_S = 12.0
SIM_SETTLE_POLL_S = 0.5

OUT = pathlib.Path(os.environ.get("POLARIS_UI_OUT", "ui-drill-out"))


def fail(msg):
    print(f"::error::UI drill FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def _num(s):
    """Parse a console number, honouring the 'k' thousands formatting."""
    m = re.match(r"\s*([\d.,]+)\s*(k?)", s or "")
    if not m:
        return None
    n = float(m.group(1).replace(",", ""))
    return n * 1000 if m.group(2) == "k" else n


def streamed_count(text):
    """The leading number of the sim counter ('N streamed · M total')."""
    m = re.search(r"([\d.,]+\s*k?)\s+streamed", text or "")
    return _num(m.group(1)) if m else None


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 900},
                                ignore_https_errors=True)

        # --- log in -------------------------------------------------------
        page.goto(URL + "/login", wait_until="domcontentloaded")
        page.fill("input[name=username]", USER)
        page.fill("input[name=password]", PASS)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_load_state("networkidle")

        # --- open the Atlas ----------------------------------------------
        page.goto(URL + "/atlas", wait_until="networkidle")
        time.sleep(1.0)   # let the first Overview aggregates paint
        page.screenshot(path=str(OUT / "01-atlas-baseline.png"))
        if not page.query_selector("[data-atlas-sim]"):
            fail("the Simulate control is not present (is POLARIS_SIM_MODE on?)")
        toggle = page.query_selector("[data-atlas-sim-toggle]")
        if not toggle:
            fail("the Simulate toggle button is missing")
        # The Overview 'Verifications' KPI is a live aggregate (not the sim
        # counter); reading it before and after proves the CHARTS refresh with the
        # stream, i.e. the sim cache-bypass works, not just the tick counter.
        kpi_el = page.query_selector('[data-ov-kpi="volume"]')
        kpi_before = _num(kpi_el.text_content() if kpi_el else "")

        # --- start the simulation ----------------------------------------
        toggle.click()
        # The host gets .atlas-sim-on while running; the button reports pressed.
        page.wait_for_selector(".atlas-sim.atlas-sim-on", timeout=5000)
        if toggle.get_attribute("aria-pressed") != "true":
            fail("the toggle did not report aria-pressed=true after starting")

        # Let a few ticks land (each ~2.5s), reading the counter as it climbs.
        first = None
        last = None
        for _ in range(6):
            time.sleep(2.5)
            ct = page.query_selector("[data-atlas-sim-count]")
            txt = ct.text_content() if ct else ""
            n = streamed_count(txt)
            if n is not None:
                if first is None:
                    first = n
                last = n
        page.screenshot(path=str(OUT / "02-atlas-simulating.png"))

        if first is None or last is None:
            fail("the streamed counter never appeared while simulating")
        if not (last > first):
            fail(f"the streamed counter did not climb (first={first}, last={last}): "
                 "the live loop is not actually streaming")
        print(f"  streamed counter climbed {first:.0f} -> {last:.0f} across the run")

        # The Overview 'Verifications' aggregate must have grown too — that proves
        # the CHARTS refresh live with the stream (the sim cache-bypass), not just
        # the tick counter.
        kpi_el = page.query_selector('[data-ov-kpi="volume"]')
        kpi_after = _num(kpi_el.text_content() if kpi_el else "")
        if kpi_before is None or kpi_after is None:
            fail("could not read the Overview 'Verifications' KPI")
        if not (kpi_after > kpi_before):
            fail(f"the Overview aggregate did not grow while simulating "
                 f"(before={kpi_before:.0f}, after={kpi_after:.0f}): the charts are "
                 "not refreshing live (is the sim cache-bypass working?)")
        print(f"  Overview 'Verifications' aggregate grew {kpi_before:.0f} -> {kpi_after:.0f} "
              "(the charts refresh live, not just the counter)")

        # --- stop ---------------------------------------------------------
        toggle.click()
        page.wait_for_selector(".atlas-sim:not(.atlas-sim-on)", timeout=5000)
        if toggle.get_attribute("aria-pressed") != "false":
            fail("the toggle did not report aria-pressed=false after stopping")
        # The counter must STOP climbing. It is not required to stop in the same
        # instant: stop() clears the ticker's interval, it does not un-send a
        # batch already in flight, and when that response lands the counter
        # jumps by one batch. Those events did stream, so the counter is right
        # to show them. Asserting no movement at all made this drill red on a
        # real run (v9.406 CI: "240 -> 280"), which is a drill reporting a
        # failure it had not established.
        #
        # So wait for it to SETTLE, then require it to stay settled. A simulator
        # that is genuinely still running never settles and fails on the
        # deadline, which is a stronger statement than the old check made.
        settled_at = None
        deadline = time.time() + SIM_SETTLE_DEADLINE_S
        previous = None
        while time.time() < deadline:
            ct = page.query_selector("[data-atlas-sim-count]")
            n = streamed_count(ct.text_content() if ct else "")
            if n is not None and previous is not None and n == previous:
                settled_at = n
                break
            previous = n
            time.sleep(SIM_SETTLE_POLL_S)
        if settled_at is None:
            fail(f"the counter never stopped climbing in "
                 f"{SIM_SETTLE_DEADLINE_S:.0f}s after Stop (last read {previous}); "
                 "the simulation loop is still running")
        time.sleep(3.0)
        ct = page.query_selector("[data-atlas-sim-count]")
        after_stop = streamed_count(ct.text_content() if ct else "")
        if after_stop is not None and after_stop > settled_at:
            fail(f"the counter resumed climbing after settling at {settled_at:.0f} "
                 f"({settled_at:.0f} -> {after_stop:.0f})")
        page.screenshot(path=str(OUT / "03-atlas-stopped.png"))

        # --- Trends tab (ship 7): the heatmap and the stacked series render ---
        # The simulation above left a window of events, so both aggregates have
        # data. This verifies the JS builds the SVG (168 heatmap cells, >=1
        # stacked band, a legend) in a real browser.
        tab = page.query_selector('[data-atlas-view-tab="trends"]')
        if tab:
            tab.click()
            page.wait_for_selector('.trends-hm-cell', timeout=5000)
            cells = len(page.query_selector_all('.trends-hm-cell'))
            bands = len(page.query_selector_all('.trends-band'))
            if cells != 168:
                fail(f"the Trends heatmap rendered {cells} cells, expected 168 (7x24)")
            if bands < 1:
                fail("the Trends composition chart rendered no stacked bands")
            print(f"  Trends tab: {cells} heatmap cells, {bands} stacked bands rendered")
            page.screenshot(path=str(OUT / "04-atlas-trends.png"))

        # --- Athena console (v9.266): the constitution renders and an
        # interactive drill-down resolves in a real browser. ---------------
        page.goto(URL + "/athena", wait_until="networkidle")
        page.wait_for_selector('.athena-rule', timeout=5000)
        rules = len(page.query_selector_all('.athena-rule'))
        if rules < 11:
            fail(f"Athena constitution rendered {rules} rules, expected >= 11 (C1-C10 + Vocation)")
        # every rule must show at least one enforcement mechanism (the map is live)
        mechs = len(page.query_selector_all('.athena-mech'))
        if mechs < rules:
            fail(f"Athena rendered {mechs} enforcement mechanisms for {rules} rules; "
                 "every rule must resolve to at least one live mechanism")
        # interactive: switch to Authority, run the chain, assert a verdict renders
        page.query_selector('[data-athena-tab="authority"]').click()
        page.wait_for_selector('[data-athena-chain-run]', timeout=5000)
        page.query_selector('[data-athena-chain-run]').click()
        page.wait_for_selector('.athena-verdict', timeout=5000)
        if not page.query_selector('.athena-chain-step'):
            fail("the Athena authority chain resolved no steps")
        print(f"  Athena console: {rules} constitution rules, {mechs} live mechanisms, "
              "authority chain resolved")
        page.screenshot(path=str(OUT / "05-athena-console.png"))

        browser.close()

    print(f"UI drill PASSED. Evidence in {OUT}/ "
          "(01-baseline, 02-simulating, 03-stopped, 04-trends, 05-athena).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""polaris_web/test_e2e_atlas.py — Atlas end-to-end smoke tests.

**Why end-to-end for the Atlas.** The Atlas (`/atlas`) is the operational
investigation surface: a MapLibre map rendered by `atlas-map.js`, with
server-side clustering, individual event markers at high zoom, and
click-through into token records. None of that is exercised by the
structural-invariant suite, which reads source, or by the route tests, which
only confirm the page returns 200. The defects that reach this surface are
CSS-class drift, script load failures, JSON data-island parse errors and CSP
violations against a new source, and every one of them needs a real browser to
see. Playwright drives Chromium against a live server; the tests skip, rather
than fail, when Playwright or its browser is not installed.
"""

import os
import socket
import unittest
import urllib.error
import urllib.request


POLARIS_HOST = os.environ.get("POLARIS_E2E_HOST", "localhost")
POLARIS_PORT = int(os.environ.get("POLARIS_E2E_PORT", "2222"))
POLARIS_URL = f"http://{POLARIS_HOST}:{POLARIS_PORT}"


def _app_reachable() -> bool:
    """Return True iff something is listening on POLARIS_PORT AND serves
    the login page (i.e., it's actually Polaris, not just any process on
    that port)."""
    try:
        with socket.create_connection((POLARIS_HOST, POLARIS_PORT), timeout=1):
            pass
    except OSError:
        return False
    try:
        urllib.request.urlopen(f"{POLARIS_URL}/login", timeout=2).read()
        return True
    except (urllib.error.URLError, socket.timeout, OSError):
        return False


def _playwright_available() -> bool:
    """Return True iff `playwright.sync_api` imports AND a chromium
    binary is installed (the `launch()` call fails fast if not)."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        # Browser not installed, or platform mismatch, or any other launch
        # failure. Treat as "skip" rather than "fail" — operator action
        # required to activate, not a regression.
        return False


_REQUIRE = os.environ.get("POLARIS_E2E_REQUIRE") == "1"
_APP_OK = _app_reachable()
_PW_OK = _playwright_available()


@unittest.skipUnless(_REQUIRE or _APP_OK,
    f"Polaris app not reachable at {POLARIS_URL} — start it via "
    f"`./polaris_mac_launch.sh up --detach` to exercise these tests")
@unittest.skipUnless(_REQUIRE or _PW_OK,
    "Playwright not available — `pip install playwright && "
    "playwright install chromium` to exercise these tests")
class TestAtlasGlobeE2E(unittest.TestCase):
    """Headless-Chromium smoke tests for the Atlas globe surface.

    Three tests; each completes in <5s with a warm browser cache. The
    suite is deliberately small — measurement, not exhaustive coverage.
    The v9.27 constraint on the chaos test: each
    scenario must catch a real failure mode the static suite cannot.
    """

    @classmethod
    def setUpClass(cls):
        if _REQUIRE:
            # CI mode: an unavailable prerequisite is a failure, not a skip.
            if not _APP_OK:
                raise AssertionError(
                    f"POLARIS_E2E_REQUIRE=1 but no Polaris app is reachable "
                    f"at {POLARIS_URL}; the suite must RUN, not skip")
            if not _PW_OK:
                raise AssertionError(
                    "POLARIS_E2E_REQUIRE=1 but Playwright/chromium is "
                    "unavailable; the suite must RUN, not skip")
        from playwright.sync_api import sync_playwright
        cls._playwright = sync_playwright().start()
        cls._browser = cls._playwright.chromium.launch(headless=True)
        cls._context = cls._browser.new_context(
            # Match the launcher's default viewport so the globe sizing
            # matches what a real operator sees.
            viewport={"width": 1280, "height": 800},
        )

    @classmethod
    def tearDownClass(cls):
        cls._context.close()
        cls._browser.close()
        cls._playwright.stop()

    def _login_and_goto(self, page, path: str = "/atlas") -> None:
        """Log in as admin (seeded role from polaris_sql/04_data.sql) +
        navigate to the requested path. Uses `domcontentloaded` per
        gotcha #6 — `networkidle` never resolves because of the 10s
        heartbeat POST."""
        page.goto(f"{POLARIS_URL}/login", wait_until="domcontentloaded")
        # Pages share one browser context, so a previous test's login cookie
        # survives here and /login redirects straight past the form. Filling
        # unconditionally then times out waiting for a field that never
        # renders; only authenticate when the form is actually present.
        if page.query_selector('input[name="username"]'):
            page.fill('input[name="username"]', "admin")
            page.fill('input[name="password"]', "Admin@123!")
            page.click('button[type="submit"]')
        # After login, /atlas requires admin role (which the seeded
        # admin has). Navigate explicitly rather than relying on a
        # redirect target.
        page.goto(f"{POLARIS_URL}{path}", wait_until="domcontentloaded")

    def test_atlas_page_loads_with_map_and_data_island(self):
        """The /atlas page must serve 200 AND contain the MapLibre map
        container plus the JSON data island. Catches: route regression
        (404/500), template rename (the element id moves), CSP block
        (script-src refuses atlas-map.js).

        v9.160: this test originally selected #atlas-globe, which the
        v9.146 MapLibre rewrite renamed to #atlas-map. The suite was
        wired to no CI job, so it rotted unnoticed: exactly the failure
        mode it exists to catch, suffered by the test itself."""
        page = self._context.new_page()
        try:
            self._login_and_goto(page)
            self.assertIsNotNone(page.query_selector("#atlas-map"),
                "atlas.html must render the #atlas-map container")
            self.assertIsNotNone(page.query_selector("#atlas-globe-data"),
                "atlas.html must render the #atlas-globe-data JSON island")
        finally:
            page.close()

    def test_overview_is_default_view_with_headline_kpis(self):
        """v9.248 (the analytical console): the Atlas opens on the OVERVIEW
        tab (the globe is demoted to a tab), and the Overview's KPI strip
        renders its headline figures with server-rendered values on first
        paint. Catches: the default view flipping back to the map, the KPI
        markup contract breaking, the /atlas health snapshot regressing."""
        page = self._context.new_page()
        try:
            self._login_and_goto(page)
            # Overview panel is the visible default; the Map panel is hidden.
            page.wait_for_selector('[data-atlas-view-panel="overview"]', state="visible", timeout=3000)
            self.assertTrue(page.is_hidden('[data-atlas-view-panel="map"]'),
                "the Map panel must start hidden (Overview is the default view)")
            # The KPI figures ride data-ov-kpi hooks; the point-in-time ones are
            # server-rendered so first paint is honest and non-empty.
            for hook in ("volume", "active", "pq", "zk"):
                el = page.query_selector(f'[data-ov-kpi="{hook}"]')
                self.assertIsNotNone(el, f"Overview must render the [data-ov-kpi={hook}] figure")
                self.assertNotEqual((el.text_content() or "").strip(), "",
                    f"[data-ov-kpi={hook}] must carry a value on first paint")
        finally:
            page.close()

    def test_map_tab_reveals_the_globe(self):
        """Clicking the Map tab must reveal the #atlas-map container (the map
        boots lazily on first show). Catches: the tab wiring breaking, the
        lazy-boot event never firing, the map panel staying hidden."""
        page = self._context.new_page()
        try:
            self._login_and_goto(page)
            page.click('[data-atlas-view-tab="map"]')
            page.wait_for_selector("#atlas-map", state="visible", timeout=3000)
            self.assertTrue(page.is_visible("#atlas-map"),
                "the Map tab must reveal the #atlas-map container")
        finally:
            page.close()

    def test_map_v2_modes_and_globe_toggle(self):
        """v9.253 (Map v2): the map is aggregation-first. It must open on the
        Regions layer (jurisdiction rollup) with a FLAT projection, switch
        between Regions/Density/Points, and toggle the globe on. Catches: the
        mode wiring, the default-mode/default-projection flip, the layer
        sources failing to build, and the projection toggle."""
        page = self._context.new_page()
        try:
            self._login_and_goto(page)
            page.click('[data-atlas-view-tab="map"]')
            page.wait_for_selector("#atlas-map", state="visible", timeout=3000)
            page.wait_for_timeout(2800)  # lazy boot + first aggregate fetch
            # Regions is the default active mode; the projection starts flat.
            self.assertEqual(page.get_attribute('[data-atlas-mapmode="regions"]', 'aria-pressed'), 'true',
                "the map must open on the Regions layer (aggregation-first)")
            proj0 = page.evaluate("() => { try { return window.atlasMap.getProjection().type } catch(e){ return 'n/a' } }")
            self.assertEqual(proj0, 'mercator', "the map must open FLAT, not on the globe")
            self.assertFalse(page.is_visible('[data-atlas-error]'),
                "the Map error banner must stay hidden when the aggregate loads")
            # Density then Points activate their modes.
            page.click('[data-atlas-mapmode="density"]'); page.wait_for_timeout(1200)
            self.assertEqual(page.get_attribute('[data-atlas-mapmode="density"]', 'aria-pressed'), 'true')
            page.click('[data-atlas-mapmode="points"]'); page.wait_for_timeout(1200)
            self.assertEqual(page.get_attribute('[data-atlas-mapmode="points"]', 'aria-pressed'), 'true')
            # The globe is an opt-in toggle.
            page.click('[data-atlas-projection]'); page.wait_for_timeout(1500)
            proj1 = page.evaluate("() => { try { return window.atlasMap.getProjection().type } catch(e){ return 'n/a' } }")
            self.assertEqual(proj1, 'globe', "the globe toggle must switch the projection to a sphere")
        finally:
            page.close()

    def test_breakdown_tab_renders_table_and_crosstab(self):
        """v9.249: the Breakdown tab must reveal its panel and populate the
        ranked table plus a cross-tab matrix, with no error banner. Catches:
        the tab wiring, the /api/atlas/breakdown + /crosstab fetches, and the
        hidden-attribute CSS regression that made the error banner show."""
        page = self._context.new_page()
        try:
            self._login_and_goto(page)
            page.click('[data-atlas-view-tab="breakdown"]')
            page.wait_for_selector('[data-atlas-view-panel="breakdown"]', state="visible", timeout=3000)
            # the ranked table renders at least one row, and a cross-tab a matrix
            page.wait_for_selector('[data-bd-ranked] .bd-row', timeout=4000)
            page.wait_for_selector('[data-bd-crosstab="outcome"] .bd-matrix-grid', timeout=4000)
            self.assertFalse(page.is_visible('[data-bd-error]'),
                "the Breakdown error banner must stay hidden when the fetches succeed")
            # v9.250: the dimension list is searchable (scale-hardening). Typing a
            # term narrows it, and the footer reflects the match.
            page.fill('[data-bd-search]', 'national')
            page.wait_for_timeout(1500)  # debounce (220ms) + fetch
            foot = (page.text_content('[data-bd-count]') or '').lower()
            self.assertIn('national', foot,
                "the Breakdown footer must reflect the search term")
        finally:
            page.close()

    def test_global_filter_coordinates_the_overview(self):
        """v9.251: the global filter bar drives the views. Selecting an outcome
        facet must add a filter chip and re-fetch the Overview (coordinated,
        cross-filtered). Catches: the facet wiring, the filter serialization,
        the chip render, and the apply-to-view path."""
        page = self._context.new_page()
        try:
            self._login_and_goto(page)
            page.wait_for_selector('[data-atlas-globalbar]', state="visible", timeout=3000)
            # open the Outcome facet and pick a value
            page.click('.gf-facet[data-gf-facet="outcome"] > summary')
            page.wait_for_selector('.gf-facet[data-gf-facet="outcome"] .gf-facet-opt', timeout=4000)
            opts = page.query_selector_all('.gf-facet[data-gf-facet="outcome"] .gf-facet-opt')
            self.assertTrue(opts, "the outcome facet must list values with counts")
            opts[0].click()  # select the first outcome value
            page.wait_for_timeout(1200)
            chips = page.text_content('[data-gf-chips]') or ''
            self.assertNotEqual(chips.strip(), "",
                "selecting a facet value must add an active filter chip")
            self.assertFalse(page.is_hidden('[data-gf-clear]'),
                "the Clear all control must appear once a filter is active")
        finally:
            page.close()

    def test_records_tab_renders_grid_and_keyset_pages(self):
        """v9.252: the Records tab must reveal a data grid, populate it, and
        page it with the keyset 'load more' control (not an OFFSET). Catches:
        the tab wiring, the /api/atlas/records fetch, the row render, and the
        cursor-append pagination."""
        page = self._context.new_page()
        try:
            self._login_and_goto(page)
            page.click('[data-atlas-view-tab="records"]')
            page.wait_for_selector('[data-atlas-view-panel="records"]', state="visible", timeout=3000)
            page.wait_for_selector('[data-rec-body] .rec-row', timeout=4000)
            self.assertFalse(page.is_visible('[data-rec-error]'),
                "the Records error banner must stay hidden when the fetch succeeds")
            before = len(page.query_selector_all('[data-rec-body] .rec-row'))
            self.assertGreater(before, 0, "the grid must render at least one record row")
            # keyset 'load more' appends the next page without dropping page one
            if page.is_visible('[data-rec-more]'):
                page.click('[data-rec-more]')
                page.wait_for_timeout(1000)
                after = len(page.query_selector_all('[data-rec-body] .rec-row'))
                self.assertGreater(after, before,
                    "the keyset 'load more' must append the next page of rows")
        finally:
            page.close()

    def test_atlas_page_has_no_inline_script_csp_violations(self):
        """The page must not log any CSP violations to the console.
        Per CLAUDE.md C5 + pre-known-gotcha #5: script-src 'self' is
        load-bearing; any inline `<script>` or event-handler attribute
        triggers a CSP report-uri (or console error). The only
        legitimate inline script is the `application/json` data-island
        at atlas.html:157 (which is type=application/json, not
        executable). Any new inline script-src violation indicates
        someone weakened CSP or added a script tag improperly."""
        page = self._context.new_page()
        violations = []
        page.on("console", lambda msg:
            violations.append(msg.text) if "Content Security Policy" in msg.text
            else None)
        try:
            self._login_and_goto(page)
            # Give the page a beat to settle (atlas-map.js initializes
            # asynchronously after DOMContentLoaded).
            page.wait_for_timeout(500)
            self.assertEqual(violations, [],
                f"Atlas page must produce no CSP violations; "
                f"got: {violations}")
        finally:
            page.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)

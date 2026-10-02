// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// =============================================================================
// Polaris Atlas, the regions map (lab/strategy/009, step 4)
//
// A MapLibre GL basemap with one data layer: the window's counts by jurisdiction, each placed at
// a reference point for the jurisdiction (static/atlas-regions.json, via the route), never where
// anyone was verified. The server reads the activity rollups, which hold no event and no
// coordinate, so a zero-knowledge verification is counted in its jurisdiction and located
// nowhere (C6). A jurisdiction with fewer than the minimum cell size is not drawn; its count
// joins "elsewhere". A withheld count reads "fewer than 5", never a number.
//
// Read before editing:
//   ../../lab/strategy/009-atlas-athena-rework.md   (what the Atlas may and may not show)
//   ../../docs/design/atlas-scaling.md              (how it stays the same cost at any size)
// =============================================================================
(function () {
    'use strict';

    var mapEl = document.getElementById('atlas-map');
    if (!mapEl || !window.maplibregl) return;

    // The Atlas opens on the Overview tab, so the map container starts hidden. A GL canvas
    // cannot size itself inside a display:none container, so the map boots LAZILY: now if the
    // container is visible, otherwise the first time atlas-console.js reveals the Map tab.
    function boot() {
        if (boot.done) return;
        boot.done = true;

    var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    var MIN_CELL = parseInt(mapEl.getAttribute('data-min-cell') || '5', 10);

    // The basemap style comes from the deployment (POLARIS_ATLAS_BASEMAP_STYLE_URL, rendered onto
    // the map element by the view). The CSP relaxation for its origin is scoped to /atlas only.
    var STYLE_URL = mapEl.getAttribute('data-basemap-style')
        || 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json';

    // Cyan is the colour of an aggregate; red marks a region whose failure share runs high.
    var TONE_COLORS = { cluster: '#5dd6ff', alert: '#ff7478', withheld: '#5f6b7a' };
    var EMPTY_FC = { type: 'FeatureCollection', features: [] };

    // -- Filter state (the model the API speaks). One context and one authority at a time: a set
    // of either would let one answer subtract from another (lab/strategy/009, step 4). ---------
    var filterState = {
        view:      'verification',
        window:    'all',
        modifiers: { anomalies: false, full: false },
        context:   null,
        agency:    null
    };

    // =========================================================================
    // Map init
    // =========================================================================
    // Default view: over the notional deployment's jurisdictions at a continent zoom.
    var HOME = { center: [-96, 39], zoom: 3.2, bearing: 0, pitch: 0 };

    var map = new maplibregl.Map({
        container: 'atlas-map',
        style: STYLE_URL,
        center: HOME.center,
        zoom: HOME.zoom,
        minZoom: 0.4,
        // A region is a jurisdiction: nothing on this map is finer than one, so there is
        // nothing to read at street zoom.
        maxZoom: 9,
        dragRotate: true,
        attributionControl: false
    });
    // OSM/CARTO attribution (ODbL requires it) goes top-right, the one stage corner with no HUD.
    map.addControl(new maplibregl.AttributionControl({ compact: true }), 'top-right');
    try { window.atlasMap = map; } catch (e) { /* noop */ }

    // The projection defaults to FLAT; the globe is an opt-in toggle.
    var projection = 'flat';
    function applyProjection() {
        try { map.setProjection({ type: projection === 'globe' ? 'globe' : 'mercator' }); }
        catch (e) { /* older engine: mercator only */ }
    }

    map.on('style.load', function () {
        applyProjection();
        try {
            map.setSky({
                'sky-color': '#0a1421', 'horizon-color': '#0e1a2b',
                'fog-color': '#050a12', 'fog-ground-blend': 0.5,
                'sky-horizon-blend': 0.6, 'atmosphere-blend': 0.7
            });
        } catch (e) { /* older style spec */ }
        addRegionLayers();
        fetchData();
        loadStrip();
        syncReadouts();
    });

    map.on('error', function (e) {
        // Basemap/tile/glyph errors are non-fatal and often transient. They must NOT raise the
        // data-feed chip, which is reserved for /api/atlas failures. Log only.
        if (e && e.error) console.warn('Atlas basemap warning:', e.error.message || e.error);
    });

    // =========================================================================
    // The regions layer: proportional symbols at each jurisdiction's reference point, sized by
    // volume, tinted red when the failure share runs high. A withheld count draws at a fixed size
    // in grey: the region is large enough to show, its exact count is not.
    // =========================================================================
    function addRegionLayers() {
        if (map.getSource('atlas-regions')) return;
        map.addSource('atlas-regions', { type: 'geojson', data: EMPTY_FC });
        map.addLayer({
            id: 'atlas-region-fill', type: 'circle', source: 'atlas-regions',
            paint: {
                'circle-radius': ['case', ['get', 'withheld'], 14,
                    ['interpolate', ['linear'], ['get', 'count'],
                        5, 10, 100, 20, 1000, 32, 10000, 46, 100000, 60]],
                'circle-color': ['case', ['get', 'withheld'], TONE_COLORS.withheld,
                    ['>=', ['get', 'failRate'], 0.15], TONE_COLORS.alert, TONE_COLORS.cluster],
                'circle-opacity': 0.20,
                'circle-stroke-width': 1.6,
                'circle-stroke-color': ['case', ['get', 'withheld'], TONE_COLORS.withheld,
                    ['>=', ['get', 'failRate'], 0.15], TONE_COLORS.alert, TONE_COLORS.cluster],
                'circle-stroke-opacity': 0.9
            }
        });
        map.addLayer({
            id: 'atlas-region-count', type: 'symbol', source: 'atlas-regions',
            layout: {
                'text-field': ['get', 'label'], 'text-size': 11,
                'text-font': ['Open Sans Bold'], 'text-allow-overlap': true
            },
            paint: { 'text-color': '#eaf4ff', 'text-halo-color': '#050a12', 'text-halo-width': 1 }
        });

        // A click shows the region's counts. There is nothing beneath a region to open.
        map.on('click', 'atlas-region-fill', function (e) {
            var p = e.features[0].properties;
            new maplibregl.Popup({ closeButton: true, maxWidth: '260px' })
                .setLngLat(e.features[0].geometry.coordinates)
                .setDOMContent(regionSummary(p))
                .addTo(map);
        });
        map.on('mouseenter', 'atlas-region-fill', function () { map.getCanvas().style.cursor = 'pointer'; });
        map.on('mouseleave', 'atlas-region-fill', function () { map.getCanvas().style.cursor = ''; });
    }

    function regionSummary(p) {
        var box = document.createElement('div');
        box.className = 'atlas-region-pop';
        var h = document.createElement('strong');
        h.textContent = p.name + ' (' + p.juris + ')';
        box.appendChild(h);
        [['Events', p.countText], ['Not successful', p.failText], ['Zero-knowledge', p.zkText]].forEach(function (row) {
            var line = document.createElement('div');
            line.textContent = row[0] + ': ' + row[1];
            box.appendChild(line);
        });
        return box;
    }

    // =========================================================================
    // Fetch: the regions are the whole deployment's, not the viewport's, so moving the map
    // fetches nothing.
    // =========================================================================
    var lastFetchKey = null, inflight = null;

    function apiKind() { return filterState.view === 'lifecycle' ? 'lifecycle' : 'verification'; }

    function serializeFilters() {
        var parts = ['window=' + encodeURIComponent(filterState.window)];
        if (filterState.modifiers.anomalies) parts.push('outcomes=anomalies');
        if (filterState.modifiers.full) parts.push('disclosure=FULL');
        if (filterState.context) parts.push('contexts=' + encodeURIComponent(filterState.context));
        if (filterState.agency) parts.push('agencies=' + encodeURIComponent(filterState.agency));
        return parts.join('&');
    }

    function apiCall(url, signal) {
        return fetch(url, { signal: signal, credentials: 'same-origin' })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
    }

    function fetchData() {
        if (!map.getSource || !map.getSource('atlas-regions')) return;
        var kind = apiKind();
        var filterQS = serializeFilters();
        var key = kind + '|' + filterQS;
        if (key === lastFetchKey) return;
        lastFetchKey = key;

        if (inflight) inflight.abort();
        inflight = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        var signal = inflight ? inflight.signal : undefined;

        apiCall('/api/atlas/geo/jurisdictions?kind=' + kind + '&' + filterQS, signal)
            .then(function (data) {
                var feats = (data.regions || []).map(regionFeature);
                var src = map.getSource('atlas-regions');
                if (src) src.setData({ type: 'FeatureCollection', features: feats });
                setElsewhere(data.elsewhere, (data.unplaced || []).length, data.truncated);
                toggleEmptyHint(feats.length === 0 && !(data.unplaced || []).length);
                hideAtlasError();
            })
            .catch(function (err) {
                if (err.name !== 'AbortError') { lastFetchKey = null; showAtlasError(err); }
            });

        apiCall('/api/atlas/stats?' + filterQS, signal)
            .then(updateStats)
            .catch(function (err) { if (err.name !== 'AbortError') { /* HUD stale; non-fatal */ } });
    }

    function shown(n, suffix) {
        return (n === null || n === undefined) ? 'fewer than ' + MIN_CELL : fmtCount(n) + (suffix || '');
    }

    function regionFeature(r) {
        var withheld = r.n_total === null || r.n_total === undefined;
        var fr = (!withheld && r.n_failure !== null && r.n_failure !== undefined) ? r.n_failure / r.n_total : 0;
        return {
            type: 'Feature',
            geometry: { type: 'Point', coordinates: [r.lon, r.lat] },
            properties: {
                juris: r.jurisdiction, name: r.name || r.jurisdiction,
                count: withheld ? 0 : r.n_total, withheld: withheld,
                label: r.jurisdiction + (withheld ? '' : ' ' + fmtCount(r.n_total)),
                failRate: fr,
                countText: withheld ? 'withheld' : fmtCount(r.n_total),
                failText: shown(r.n_failure), zkText: shown(r.n_zk)
            }
        };
    }

    function fmtCount(n) { return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k' : String(n); }

    // =========================================================================
    // HUD
    // =========================================================================
    function setText(sel, val) { var el = document.querySelector(sel); if (el) el.textContent = String(val); }
    function updateStats(s) {
        if (!s) return;
        // The post-quantum figure is the live signatures' share, a property of the population
        // the server rendered; the window's own share of quantum-resistant verifications is a
        // different number, so it does not replace it under the same label.
        setText('[data-atlas-active-tokens]', shown(s.n_active_tokens));
        setText('[data-atlas-zk-pct]', s.zk_pct === null ? 'withheld' : s.zk_pct + '%');
        setText('[data-atlas-failures]', shown(s.n_failures));
        setText('[data-atlas-full-disclosures]', shown(s.n_full));
    }

    // The legend line for what the map does not draw: the small jurisdictions, folded into one
    // count, and any the reference data cannot place.
    function setElsewhere(elsewhere, nUnplaced, truncated) {
        var el = document.querySelector('[data-atlas-unplaceable]');
        if (!el) return;
        var parts = [];
        // Always said, even when there is nothing elsewhere: a zero would say what a withheld
        // count does not.
        parts.push('Jurisdictions with fewer than ' + MIN_CELL + ' each, not drawn: '
                   + shown(elsewhere) + ' together');
        if (nUnplaced > 0) {
            parts.push(nUnplaced + ' jurisdiction' + (nUnplaced === 1 ? '' : 's') + ' without a reference point');
        }
        // At the regions cap the quietest jurisdictions are counted in the totals and drawn nowhere.
        if (truncated) parts.push('only the busiest jurisdictions are drawn');
        el.hidden = parts.length === 0;
        el.textContent = parts.join(' · ');
    }

    // =========================================================================
    // Error + empty chips
    // =========================================================================
    var errorChip = document.querySelector('[data-atlas-error]');
    var emptyChip = document.querySelector('[data-atlas-empty]');
    function showAtlasError(err) {
        if (!errorChip) return;
        errorChip.hidden = false;
        var detail = errorChip.querySelector('[data-atlas-error-detail]');
        if (detail) {
            var msg = (err && err.message) || '';
            // A 500 from /api/atlas/* almost always means the database's atlas functions are out
            // of date (a signature changed in the repo but the running DB has the old one).
            detail.textContent = /HTTP 5\d\d/.test(msg)
                ? 'server error (' + msg + '). The atlas database functions may be '
                  + 'out of date, reload the schema (./polaris_mac_launch.sh up, or '
                  + 'reset to fully reload).'
                : (msg ? 'network or server problem (' + msg + ').' : 'connection problem.');
        }
    }
    function hideAtlasError() { if (errorChip) errorChip.hidden = true; }
    function toggleEmptyHint(isEmpty) { if (emptyChip) emptyChip.hidden = !isEmpty; }

    var retryBtn = document.querySelector('[data-atlas-retry]');
    if (retryBtn) retryBtn.addEventListener('click', function () {
        hideAtlasError(); lastFetchKey = null; fetchData(); loadStrip();
    });

    // =========================================================================
    // Cursor / readouts
    // =========================================================================
    var cursorEl = document.getElementById('atlas-hud-cursor');
    function fmtCoord(v, pos, neg) { return Math.abs(v).toFixed(2) + '°' + (v >= 0 ? pos : neg); }
    map.on('mousemove', function (e) {
        if (cursorEl) cursorEl.textContent = fmtCoord(e.lngLat.lat, 'N', 'S') + ' ' + fmtCoord(e.lngLat.lng, 'E', 'W');
    });
    mapEl.addEventListener('mouseleave', function () { if (cursorEl) cursorEl.textContent = '- -'; });

    function syncReadouts() {
        setText('#atlas-hud-heading', Math.round((map.getBearing() + 360) % 360).toString().padStart(3, '0') + '°');
        setText('#atlas-hud-pitch', (map.getPitch() >= 0 ? '+' : '') + Math.round(map.getPitch()) + '°');
        var z = map.getZoom();
        setText('#atlas-hud-zoom', z.toFixed(2) + 'x');
    }
    map.on('move', syncReadouts);

    // =========================================================================
    // The strip: the window's volume over time, from the same series the Overview draws. A
    // withheld bucket draws as a short grey tick, not as a zero.
    // =========================================================================
    var stripEl = document.querySelector('[data-atlas-timeline]');
    function loadStrip() {
        if (!stripEl) return;
        apiCall('/api/atlas/series?buckets=60&kind=' + apiKind() + '&' + serializeFilters())
            .then(renderStrip).catch(function () { /* non-fatal */ });
    }
    function renderStrip(data) {
        if (!stripEl) return;
        var pts = (data && data.points) || [];
        var max = pts.reduce(function (m, p) { return Math.max(m, p.n_total || 0); }, 1);
        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('class', 'atlas-timeline-svg');
        svg.setAttribute('viewBox', '0 0 240 28');
        svg.setAttribute('preserveAspectRatio', 'none');
        var n = Math.max(pts.length, 1);
        pts.forEach(function (p, i) {
            var withheld = p.n_total === null || p.n_total === undefined;
            var h = withheld ? 2 : Math.max(2, Math.round(24 * p.n_total / max));
            var w = 240 / n;
            var bar = document.createElementNS(svgNS, 'rect');
            bar.setAttribute('x', (i * w + 0.5).toFixed(2));
            bar.setAttribute('y', (26 - h).toFixed(2));
            bar.setAttribute('width', Math.max(0.5, w - 1).toFixed(2));
            bar.setAttribute('height', h);
            bar.setAttribute('fill', withheld ? TONE_COLORS.withheld
                : ((p.n_failure || 0) > 0 ? TONE_COLORS.alert : TONE_COLORS.cluster));
            bar.setAttribute('opacity', '0.7');
            svg.appendChild(bar);
        });
        stripEl.replaceChildren(svg);
    }

    // =========================================================================
    // Filters
    // =========================================================================
    function refetchAll() { lastFetchKey = null; fetchData(); loadStrip(); }

    function refreshFilterUI() {
        document.querySelectorAll('[data-atlas-view]').forEach(function (b) {
            var on = b.dataset.atlasView === filterState.view;
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
        });
        document.querySelectorAll('[data-atlas-window]').forEach(function (b) {
            var on = b.dataset.atlasWindow === filterState.window;
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
        });
        document.querySelectorAll('[data-atlas-modifier]').forEach(function (b) {
            var on = !!filterState.modifiers[b.dataset.atlasModifier];
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        document.querySelectorAll('[data-atlas-context]').forEach(function (b) {
            var on = filterState.context === b.dataset.atlasContext;
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
        });
        document.querySelectorAll('[data-atlas-agency]').forEach(function (b) {
            var on = filterState.agency === b.dataset.atlasAgency;
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-checked', on ? 'true' : 'false');
        });
    }

    document.querySelectorAll('[data-atlas-view]').forEach(function (b) {
        b.addEventListener('click', function () {
            filterState.view = b.dataset.atlasView === 'lifecycle' ? 'lifecycle' : 'verification';
            refreshFilterUI(); refetchAll();
        });
    });
    document.querySelectorAll('[data-atlas-window]').forEach(function (b) {
        b.addEventListener('click', function () {
            filterState.window = b.dataset.atlasWindow; refreshFilterUI(); refetchAll();
        });
    });
    document.querySelectorAll('[data-atlas-modifier]').forEach(function (b) {
        b.addEventListener('click', function () {
            var n = b.dataset.atlasModifier;
            filterState.modifiers[n] = !filterState.modifiers[n];
            refreshFilterUI(); refetchAll();
        });
    });
    // Pick one or none: a second click clears the choice.
    document.querySelectorAll('[data-atlas-context]').forEach(function (b) {
        b.addEventListener('click', function () {
            var c = b.dataset.atlasContext;
            filterState.context = filterState.context === c ? null : c;
            refreshFilterUI(); refetchAll();
        });
    });
    document.querySelectorAll('[data-atlas-agency]').forEach(function (b) {
        b.addEventListener('click', function () {
            var a = b.dataset.atlasAgency;
            filterState.agency = filterState.agency === a ? null : a;
            refreshFilterUI(); refetchAll();
        });
    });

    var projBtn = document.querySelector('[data-atlas-projection]');
    if (projBtn) projBtn.addEventListener('click', function () {
        projection = (projection === 'globe') ? 'flat' : 'globe';
        projBtn.classList.toggle('toolbar-chip-active', projection === 'globe');
        projBtn.setAttribute('aria-pressed', projection === 'globe' ? 'true' : 'false');
        applyProjection();
    });

    // =========================================================================
    // Controls, zoom / reset / spin / fullscreen
    // =========================================================================
    var zin = document.querySelector('[data-atlas-zoom-in]');
    var zout = document.querySelector('[data-atlas-zoom-out]');
    if (zin)  zin.addEventListener('click', function () { map.zoomIn({ duration: 300 }); });
    if (zout) zout.addEventListener('click', function () { map.zoomOut({ duration: 300 }); });

    var resetBtn = document.querySelector('[data-atlas-reset]');
    if (resetBtn) resetBtn.addEventListener('click', function () {
        map.flyTo({ center: HOME.center, zoom: HOME.zoom, bearing: 0, pitch: 0, speed: 1.1 });
    });

    // Spin: slowly rotate the globe by easing the center longitude. Off by default and off
    // under reduced motion; any drag interrupts it.
    var spinning = false, spinRAF = null;
    var spinBtn = document.querySelector('[data-atlas-spin]');
    function spinStep() {
        if (!spinning) return;
        if (!map.isMoving() && map.getZoom() < 4) {
            var c = map.getCenter();
            map.setCenter([c.lng + 0.12, c.lat]);
        }
        spinRAF = requestAnimationFrame(spinStep);
    }
    function setSpin(on) {
        spinning = on && !reducedMotion;
        if (spinBtn) {
            spinBtn.classList.toggle('toolbar-chip-active', spinning);
            spinBtn.textContent = spinning ? 'Pause' : 'Spin';
        }
        if (spinning) spinStep(); else if (spinRAF) cancelAnimationFrame(spinRAF);
    }
    if (spinBtn) spinBtn.addEventListener('click', function () { setSpin(!spinning); });
    map.on('dragstart', function () { if (spinning) setSpin(false); });

    // Fullscreen: the whole console takes the display ('f' or the chip).
    var shellEl = document.querySelector('.atlas-shell');
    var fsBtn = document.querySelector('[data-atlas-fullscreen]');
    function toggleFullscreen() {
        if (!shellEl) return;
        if (document.fullscreenElement || document.webkitFullscreenElement) {
            (document.exitFullscreen || document.webkitExitFullscreen).call(document);
        } else {
            (shellEl.requestFullscreen || shellEl.webkitRequestFullscreen).call(shellEl);
        }
    }
    function syncFs() {
        if (!fsBtn) return;
        var on = !!(document.fullscreenElement || document.webkitFullscreenElement);
        fsBtn.classList.toggle('toolbar-chip-active', on);
        fsBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
        fsBtn.textContent = on ? '✕ Exit' : '⛶ Full';
        setTimeout(function () { map.resize(); }, 60);
    }
    if (fsBtn) fsBtn.addEventListener('click', toggleFullscreen);
    document.addEventListener('fullscreenchange', syncFs);
    document.addEventListener('webkitfullscreenchange', syncFs);

    document.addEventListener('keydown', function (e) {
        if (e.target && /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) return;
        if (e.key === 'f' || e.key === 'F') { toggleFullscreen(); }
    });

    // =========================================================================
    // LIVE refresh + Z-clock
    // =========================================================================
    function liveRefresh() {
        if (document.hidden) return;
        lastFetchKey = null; fetchData(); loadStrip();
    }
    setInterval(liveRefresh, 60000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) liveRefresh(); });
    // Live simulation: the console's sim loop fires this after each batch.
    window.addEventListener('polaris:atlas-refresh', function () { liveRefresh(); });

    var timeEl = document.getElementById('atlas-hud-time');
    function tickClock() {
        if (!timeEl) return;
        var d = new Date();
        function p(n) { return n < 10 ? '0' + n : '' + n; }
        var mo = ['JAN','FEB','MAR','APR','MAY','JUN','JUL','AUG','SEP','OCT','NOV','DEC'];
        timeEl.textContent = mo[d.getUTCMonth()] + ' ' + p(d.getUTCDate()) + ' ' + d.getUTCFullYear()
            + ' / ' + p(d.getUTCHours()) + ':' + p(d.getUTCMinutes()) + ':' + p(d.getUTCSeconds()) + 'Z';
    }
    tickClock(); setInterval(tickClock, 1000);
    }   // end boot()

    // Boot now if the Map tab is the landing view, else defer until it is first shown.
    if (mapEl.offsetParent !== null) boot();
    else window.addEventListener('polaris:atlas-map-show', boot);
})();

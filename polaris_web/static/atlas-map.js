// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// =============================================================================
// Polaris Atlas, MapLibre street-level console (v9.146)
//
// Replaces the bespoke D3 orthographic globe with a MapLibre GL basemap that
// zooms from a 3D globe down to street level (CARTO dark-matter free vector
// tiles, self-hosted MapLibre engine, no Mapbox token). The data architecture
// is unchanged: events are fetched per-viewport from /api/atlas/* (server-side
// spatial aggregation, capped by C8), so this scales the same way the globe
// did. ZERO_KNOWLEDGE events are never plotted, the server excludes them from
// every spatial layer (C6). The basemap is cartography, not new exposure.
//
// Read before editing:
//   ../../docs/reference/SCALING.md          (viewport-aggregation architecture)
//   ../../docs/design/atlas-scaling.md          (what NOT to change without measuring)
// =============================================================================
(function () {
    'use strict';

    var mapEl = document.getElementById('atlas-map');
    if (!mapEl || !window.maplibregl) return;

    // v9.248 (the analytical console): the Atlas opens on the Overview tab, so
    // the map container starts hidden. A GL canvas cannot size itself inside a
    // display:none container, and an always-live map is wasted work on a page
    // that may never open the Map tab. So the whole map boots LAZILY: now if
    // the container is already visible (map is the landing view), otherwise the
    // first time atlas-console.js reveals the Map tab (polaris:atlas-map-show).
    function boot() {
        if (boot.done) return;
        boot.done = true;

    var reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    // The basemap style comes from the deployment (POLARIS_ATLAS_BASEMAP_STYLE_URL,
    // rendered onto the map element by the view). The default is CARTO
    // dark-matter: free vector basemap, no API key, a dark palette that matches
    // the console. A self-hosted style keeps every request inside the estate.
    // The CSP relaxation for the configured origin is scoped to /atlas only
    // (see security.apply_security_headers).
    var STYLE_URL = mapEl.getAttribute('data-basemap-style')
        || 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json';

    // -- Tone palette (shared with the legend) --------------------------------
    // Cyan is the colour of an aggregate. The map draws counts only: a region
    // or a hexagon, never a single event (lab/strategy/009), and a
    // ZERO_KNOWLEDGE verification is counted but never placed (C6).
    var TONE_COLORS = { cluster: '#5dd6ff', alert: '#ff7478' };
    var EMPTY_FC = { type: 'FeatureCollection', features: [] };

    // -- Unified filter state (mirrors the v8.3 model the API speaks) ---------
    var filterState = {
        view:      'verification',
        window:    'all',
        modifiers: { anomalies: false, full: false },
        contexts:  [],
        agencies:  []
    };

    // =========================================================================
    // Map init
    // =========================================================================
    // Default view: centered on the data, not the empty mid-Atlantic. The
    // notional events are US-based, so opening over North America at a
    // continent zoom means the verification clusters are visible on load
    // instead of sitting at the globe's limb. (HOME is also the Reset target.)
    var HOME = { center: [-96, 39], zoom: 3.2, bearing: 0, pitch: 0 };

    var map = new maplibregl.Map({
        container: 'atlas-map',
        style: STYLE_URL,
        center: HOME.center,
        zoom: HOME.zoom,
        minZoom: 0.4,
        maxZoom: 18,
        dragRotate: true,
        attributionControl: false
    });
    // OSM/CARTO attribution (ODbL requires it) goes top-right, the one stage
    // corner with no HUD, so it never overlaps the PQ/ZK readout bottom-right.
    map.addControl(new maplibregl.AttributionControl({ compact: true }), 'top-right');
    // No NavigationControl: the command bar already carries zoom +/- / Reset /
    // Spin / Fullscreen, and the control was overlapping the bottom-right HUD.
    // Expose the map for ops/debug console use (read-only basemap object; the
    // data layers are driven by the fetch coordinator, not this handle).
    try { window.atlasMap = map; } catch (e) { /* noop */ }

    // v9.253 (Map v2): the map is aggregation-first. mapMode selects the layer
    // shown: 'regions' (jurisdiction rollup, the DEFAULT) or 'density' (hexbin).
    // The drill to single events went with lab/strategy/009. Projection defaults to FLAT; the
    // globe becomes an opt-in toggle rather than the always-on view, so the
    // console opens on a legible thematic map, not a spinning sphere.
    var mapMode = 'regions';
    var projection = 'flat';
    function applyProjection() {
        try { map.setProjection({ type: projection === 'globe' ? 'globe' : 'mercator' }); }
        catch (e) { /* older engine: mercator only */ }
    }

    map.on('style.load', function () {
        applyProjection();
        // Globe atmosphere glow, tuned to the console palette.
        try {
            map.setSky({
                'sky-color': '#0a1421', 'horizon-color': '#0e1a2b',
                'fog-color': '#050a12', 'fog-ground-blend': 0.5,
                'sky-horizon-blend': 0.6, 'atmosphere-blend': 0.7
            });
        } catch (e) { /* older style spec */ }
        addEventLayers();
        updateModeUI();
        updateLegendForMode();
        scheduleFetch();
        loadTimeline();
        syncReadouts();
    });

    map.on('error', function (e) {
        // Basemap/tile/glyph errors are non-fatal and often transient (a single
        // tile 404, a font-range miss). They must NOT raise the data-feed chip,
        // which is reserved for actual /api/atlas fetch failures, otherwise a
        // momentary CARTO hiccup reads as "ATLAS FEED INTERRUPTED". Log only.
        if (e && e.error) console.warn('Atlas basemap warning:', e.error.message || e.error);
    });

    // =========================================================================
    // Aggregate layers: regions (the default) and the density surface
    // =========================================================================
    function addEventLayers() {
        if (map.getSource('atlas-regions')) return;

        // --- Density layer (v9.253): a hexbin surface of located activity. ----
        // Filled hexagons graduated by count give an honest density read at
        // continental scale where thousands of raw points would be a smear.
        map.addSource('atlas-hexes', { type: 'geojson', data: EMPTY_FC });
        map.addLayer({
            id: 'atlas-hex-fill', type: 'fill', source: 'atlas-hexes',
            paint: {
                'fill-color': ['interpolate', ['linear'], ['get', 'dens'],
                    0, '#0d2233', 0.25, '#134a63', 0.5, '#1f7fa6', 0.75, '#39b6d8', 1, '#8ef0ff'],
                'fill-opacity': 0.55
            }
        });
        map.addLayer({
            id: 'atlas-hex-stroke', type: 'line', source: 'atlas-hexes',
            paint: { 'line-color': '#8ef0ff', 'line-width': 0.6, 'line-opacity': 0.35 }
        });

        // --- Regions layer (v9.253): the DEFAULT. Proportional symbols at each
        // jurisdiction's activity centroid, sized by volume, tinted red when the
        // failure rate runs high. The count INCLUDES zero-knowledge events; the
        // position never does (C6, enforced in atlas_geo_jurisdictions). --------
        map.addSource('atlas-regions', { type: 'geojson', data: EMPTY_FC });
        map.addLayer({
            id: 'atlas-region-fill', type: 'circle', source: 'atlas-regions',
            paint: {
                'circle-radius': ['interpolate', ['linear'], ['get', 'count'],
                    1, 10, 100, 20, 1000, 32, 10000, 46, 100000, 60],
                'circle-color': ['case', ['>=', ['get', 'failRate'], 0.15], TONE_COLORS.alert, TONE_COLORS.cluster],
                'circle-opacity': 0.20,
                'circle-stroke-width': 1.6,
                'circle-stroke-color': ['case', ['>=', ['get', 'failRate'], 0.15], TONE_COLORS.alert, TONE_COLORS.cluster],
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

        // Zoom in: a region opens the density surface around it; a hexagon zooms
        // the surface. Neither opens an event: there is none to open.
        map.on('click', 'atlas-region-fill', function (e) {
            zoomToDensity(e.features[0].geometry.coordinates, 6);
        });
        map.on('click', 'atlas-hex-fill', function (e) {
            var g = e.features[0].geometry.coordinates[0];
            zoomToDensity(g[0], Math.max(6, map.getZoom() + 2));
        });
        ['atlas-region-fill', 'atlas-hex-fill'].forEach(function (id) {
            map.on('mouseenter', id, function () { map.getCanvas().style.cursor = 'pointer'; });
            map.on('mouseleave', id, function () { map.getCanvas().style.cursor = ''; });
        });
    }

    // =========================================================================
    // Per-viewport fetch (the scaling architecture: server aggregates, the
    // client only ever holds what is on screen)
    // =========================================================================
    var lastFetchKey = null, inflight = null, fetchTimer = null;

    function currentBbox() {
        var b = map.getBounds();
        return [
            Math.max(-89.9, b.getSouth()), Math.max(-179.9, b.getWest()),
            Math.min(89.9, b.getNorth()), Math.min(179.9, b.getEast())
        ];
    }
    function apiKind() { return filterState.view === 'lifecycle' ? 'lifecycle' : 'verification'; }

    function serializeFilters() {
        var parts = ['window=' + encodeURIComponent(filterState.window)];
        if (filterState.modifiers.anomalies) parts.push('outcomes=anomalies');
        if (filterState.modifiers.full) parts.push('disclosure=FULL');
        if (filterState.contexts.length) {
            parts.push('contexts=' + filterState.contexts.map(encodeURIComponent).join(','));
        }
        if (filterState.agencies.length) {
            parts.push('agencies=' + filterState.agencies.join(','));
        }
        return parts.join('&');
    }

    function apiCall(url, signal) {
        return fetch(url, { signal: signal, credentials: 'same-origin' })
            .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); });
    }

    function scheduleFetch() {
        if (fetchTimer) clearTimeout(fetchTimer);
        fetchTimer = setTimeout(fetchData, 200);
    }

    // Hex size (circumradius, degrees) by zoom, so a Density hex is a sensible
    // bin at each scale. The client renders with the SAME size it sends, so the
    // lattice tiles perfectly.
    function chooseHexSize(z) {
        if (z >= 12) return 0.03;
        if (z >= 10) return 0.08;
        if (z >= 8)  return 0.25;
        if (z >= 6)  return 0.7;
        if (z >= 4)  return 1.6;
        if (z >= 2)  return 3.5;
        return 6;
    }

    // fetchData dispatches by mapMode. Each mode owns its dedup key, its layer,
    // and its legend; the HUD stats fetch (viewport totals) runs in every mode.
    function fetchData() {
        if (!map.getSource || !map.getSource('atlas-regions')) return;
        var bbox = currentBbox();
        var kind = apiKind();
        var filterQS = serializeFilters();
        var bboxParam = bbox.join(',');
        var b3 = bbox.map(function (v) { return v.toFixed(3); }).join(',');

        var key;
        if (mapMode === 'regions') key = 'regions|' + kind + '|' + filterQS;         // not viewport-bound
        else                       key = 'density|' + kind + '|' + b3 + '|' + chooseHexSize(map.getZoom()) + '|' + filterQS;
        if (key === lastFetchKey) return;
        lastFetchKey = key;

        if (inflight) inflight.abort();
        inflight = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        var signal = inflight ? inflight.signal : undefined;

        clearLayersExcept(mapMode);
        if (mapMode === 'regions') fetchRegions(kind, filterQS, signal);
        else                       fetchDensity(bboxParam, kind, filterQS, signal);

        apiCall('/api/atlas/stats?bbox=' + encodeURIComponent(bboxParam) + '&' + filterQS, signal)
            .then(updateStats)
            .catch(function (err) { if (err.name !== 'AbortError') { /* HUD stale; non-fatal */ } });
    }

    // -- Regions mode (DEFAULT): jurisdiction proportional symbols. Not --------
    // viewport-bound; shows every jurisdiction. Counts include ZK, positions
    // never do; the legend surfaces the ZK-only, unplaceable count (C6). -------
    function fetchRegions(kind, filterQS, signal) {
        apiCall('/api/atlas/geo/jurisdictions?kind=' + kind + '&' + filterQS, signal)
            .then(function (data) {
                var feats = (data.regions || []).map(regionFeature);
                var src = map.getSource('atlas-regions');
                if (src) src.setData({ type: 'FeatureCollection', features: feats });
                setUnplaceable(data.n_unplaceable || 0, data.n_unplaceable_events || 0);
                toggleEmptyHint(feats.length === 0 && (data.n_unplaceable || 0) === 0);
                hideAtlasError();
            })
            .catch(function (err) {
                if (err.name !== 'AbortError') { lastFetchKey = null; showAtlasError(err); }
            });
    }

    // -- Density mode: a hexbin surface of located, non-ZK activity. -----------
    function fetchDensity(bboxParam, kind, filterQS, signal) {
        var size = chooseHexSize(map.getZoom());
        apiCall('/api/atlas/hexbin?bbox=' + encodeURIComponent(bboxParam) +
                '&size=' + size + '&kind=' + kind + '&' + filterQS, signal)
            .then(function (data) {
                var hexes = data.hexes || [];
                var maxN = 1;
                hexes.forEach(function (h) { if (h.n_total > maxN) maxN = h.n_total; });
                var feats = hexes.map(function (h) { return hexFeature(h, size, maxN); });
                var src = map.getSource('atlas-hexes');
                if (src) src.setData({ type: 'FeatureCollection', features: feats });
                toggleEmptyHint(feats.length === 0);
                hideAtlasError();
            })
            .catch(function (err) {
                if (err.name !== 'AbortError') { lastFetchKey = null; showAtlasError(err); }
            });
    }

    // Empty a source. On mode switch the stale layer must clear so two
    // aggregates never paint at once.
    function clearLayersExcept(mode) {
        if (mode !== 'regions' && map.getSource('atlas-regions')) map.getSource('atlas-regions').setData(EMPTY_FC);
        if (mode !== 'density' && map.getSource('atlas-hexes'))   map.getSource('atlas-hexes').setData(EMPTY_FC);
    }

    // -- Aggregate feature builders (Regions + Density) -----------------------
    function regionFeature(r) {
        var fr = r.n_total ? (r.n_failure / r.n_total) : 0;
        return {
            type: 'Feature',
            geometry: { type: 'Point', coordinates: [r.centroid_lon, r.centroid_lat] },
            properties: {
                juris: r.jurisdiction, count: r.n_total, label: r.jurisdiction + ' ' + fmtCount(r.n_total),
                failRate: fr, zk: r.n_zk || 0, located: r.n_located || 0
            }
        };
    }
    function hexPolygon(lon, lat, size) {
        var ring = [];
        for (var i = 0; i < 6; i++) {
            var a = Math.PI / 180 * (60 * i + 30);   // pointy-top vertices
            ring.push([lon + size * Math.cos(a), lat + size * Math.sin(a)]);
        }
        ring.push(ring[0]);
        return [ring];
    }
    function hexFeature(h, size, maxN) {
        // dens is a 0..1 density on a sqrt scale so a few hot hexes do not wash
        // the rest to the floor colour.
        var dens = maxN > 0 ? Math.sqrt(h.n_total / maxN) : 0;
        return {
            type: 'Feature',
            geometry: { type: 'Polygon', coordinates: hexPolygon(h.lon, h.lat, size) },
            properties: { count: h.n_total, failN: h.n_failure || 0, dens: dens }
        };
    }

    // Switch the active layer. Zoom-in and the mode chips both route through here.
    function setMode(mode) {
        if (mode !== 'regions' && mode !== 'density') return;
        mapMode = mode;
        updateModeUI();
        updateLegendForMode();
        refetchAll();
    }
    function zoomToDensity(center, zoom) {
        mapMode = 'density';
        updateModeUI();
        updateLegendForMode();
        map.flyTo({ center: center, zoom: Math.max(map.getZoom(), zoom || 6), speed: 1.1 });
        refetchAll();   // moveend will also fire; the dedup key absorbs the double
    }

    function fmtCount(n) { return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k' : String(n); }

    // =========================================================================
    // HUD stats
    // =========================================================================
    function setText(sel, val) { var el = document.querySelector(sel); if (el) el.textContent = String(val); }
    function updateStats(s) {
        if (!s) return;
        setText('[data-atlas-active-tokens]', s.n_active_tokens);
        setText('[data-atlas-pq-pct]', s.pq_pct + '%');
        setText('[data-atlas-zk-pct]', s.zk_pct + '%');
        setText('[data-atlas-failures]', s.n_failures);
        setText('[data-atlas-full-disclosures]', s.n_full);
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
            // A 500 from /api/atlas/* almost always means the database's atlas
            // functions are out of date (a signature changed in the repo but the
            // running DB still has the old one). Tell the operator how to fix it.
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
        hideAtlasError(); lastFetchKey = null; scheduleFetch(); loadTimeline();
    });

    // =========================================================================
    // Cursor / readouts
    // =========================================================================
    // Cursor lat/lon + heading/pitch/zoom readouts
    var cursorEl = document.getElementById('atlas-hud-cursor');
    function fmtCoord(v, pos, neg) {
        var dp = map.getZoom() >= 8 ? 4 : 2;
        return Math.abs(v).toFixed(dp) + '°' + (v >= 0 ? pos : neg);
    }
    map.on('mousemove', function (e) {
        if (cursorEl) cursorEl.textContent = fmtCoord(e.lngLat.lat, 'N', 'S') + ' ' + fmtCoord(e.lngLat.lng, 'E', 'W');
    });
    mapEl.addEventListener('mouseleave', function () { if (cursorEl) cursorEl.textContent = '- -'; });

    function syncReadouts() {
        setText('#atlas-hud-heading', Math.round((map.getBearing() + 360) % 360).toString().padStart(3, '0') + '°');
        setText('#atlas-hud-pitch', (map.getPitch() >= 0 ? '+' : '') + Math.round(map.getPitch()) + '°');
        var z = map.getZoom();
        setText('#atlas-hud-zoom', (z >= 10 ? z.toFixed(1) : z.toFixed(2)) + 'x');
    }
    map.on('move', syncReadouts);
    map.on('moveend', scheduleFetch);

    // =========================================================================
    // Timeline histogram (status bar)
    // =========================================================================
    var timelineEl = document.querySelector('[data-atlas-timeline]');
    function loadTimeline() {
        if (!timelineEl) return;
        var bbox = currentBbox();
        var url = '/api/atlas/timeline?bbox=' + encodeURIComponent(bbox.join(',')) +
                  '&buckets=60&kind=' + apiKind() + '&' + serializeFilters();
        apiCall(url).then(renderTimeline).catch(function () { /* non-fatal */ });
    }
    function renderTimeline(data) {
        if (!timelineEl) return;
        var pts = (data && data.points) || [];
        var max = pts.reduce(function (m, p) { return Math.max(m, p.n_total || 0); }, 1);
        var svgNS = 'http://www.w3.org/2000/svg';
        var svg = document.createElementNS(svgNS, 'svg');
        svg.setAttribute('class', 'atlas-timeline-svg');
        svg.setAttribute('viewBox', '0 0 240 28');
        svg.setAttribute('preserveAspectRatio', 'none');
        var n = Math.max(pts.length, 1);
        pts.forEach(function (p, i) {
            var h = Math.max(1, Math.round(24 * (p.n_total || 0) / max));
            var w = 240 / n;
            var bar = document.createElementNS(svgNS, 'rect');
            bar.setAttribute('x', (i * w + 0.5).toFixed(2));
            bar.setAttribute('y', (26 - h).toFixed(2));
            bar.setAttribute('width', Math.max(0.5, w - 1).toFixed(2));
            bar.setAttribute('height', h);
            bar.setAttribute('fill', (p.n_anomaly || 0) > 0 ? TONE_COLORS.alert : TONE_COLORS.cluster);
            bar.setAttribute('opacity', '0.7');
            svg.appendChild(bar);
        });
        timelineEl.replaceChildren(svg);
    }

    // =========================================================================
    // Filters, chips drive filterState; every change resets the fetch key
    // =========================================================================
    function refetchAll() { lastFetchKey = null; scheduleFetch(); loadTimeline(); }

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
            var on = filterState.contexts.indexOf(b.dataset.atlasContext) >= 0;
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        document.querySelectorAll('[data-atlas-agency]').forEach(function (b) {
            var on = filterState.agencies.indexOf(b.dataset.atlasAgency) >= 0;
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
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
    document.querySelectorAll('[data-atlas-context]').forEach(function (b) {
        b.addEventListener('click', function () {
            var c = b.dataset.atlasContext, i = filterState.contexts.indexOf(c);
            if (i >= 0) filterState.contexts.splice(i, 1); else filterState.contexts.push(c);
            refreshFilterUI(); refetchAll();
        });
    });
    document.querySelectorAll('[data-atlas-agency]').forEach(function (b) {
        b.addEventListener('click', function () {
            var a = b.dataset.atlasAgency, i = filterState.agencies.indexOf(a);
            if (i >= 0) filterState.agencies.splice(i, 1); else filterState.agencies.push(a);
            refreshFilterUI(); refetchAll();
        });
    });

    // -- Map v2 (v9.253): layer-mode segmented control + projection toggle -----
    document.querySelectorAll('[data-atlas-mapmode]').forEach(function (b) {
        b.addEventListener('click', function () { setMode(b.dataset.atlasMapmode); });
    });
    function updateModeUI() {
        document.querySelectorAll('[data-atlas-mapmode]').forEach(function (b) {
            var on = b.dataset.atlasMapmode === mapMode;
            b.classList.toggle('toolbar-chip-active', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
    }
    var projBtn = document.querySelector('[data-atlas-projection]');
    if (projBtn) projBtn.addEventListener('click', function () {
        projection = (projection === 'globe') ? 'flat' : 'globe';
        projBtn.classList.toggle('toolbar-chip-active', projection === 'globe');
        projBtn.setAttribute('aria-pressed', projection === 'globe' ? 'true' : 'false');
        applyProjection();
    });

    // Legend + the ZK-only "counted, not placed" readout are mode-specific.
    function updateLegendForMode() {
        document.querySelectorAll('[data-legend-mode]').forEach(function (el) {
            el.hidden = (el.getAttribute('data-legend-mode') !== mapMode);
        });
    }
    function setUnplaceable(nJur, nEvents) {
        var el = document.querySelector('[data-atlas-unplaceable]');
        if (!el) return;
        if (nJur > 0) {
            el.hidden = false;
            el.textContent = nJur + ' jurisdiction' + (nJur === 1 ? '' : 's') + ' counted, not placed ('
                           + fmtCount(nEvents) + ' zero-knowledge event' + (nEvents === 1 ? '' : 's') + ')';
        } else {
            el.hidden = true;
        }
    }

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

    // Spin: slowly rotate the globe by easing the center longitude. Off by
    // default (continuous tile + data refetch is heavy); user-toggled. Any
    // drag interrupts it.
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

    // Fullscreen, the whole console takes the display ('f' or the chip).
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
        lastFetchKey = null; scheduleFetch();
        loadTimeline();
    }
    setInterval(liveRefresh, 60000);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) liveRefresh(); });
    // Live simulation (P2.14 S4): the console's sim loop fires this after each
    // batch so the map lights up immediately, not only on the 60 s cadence.
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

    // Boot now if the Map tab is the landing view (container already laid out),
    // else defer until it is first shown. atlas-console.js dispatches the event
    // after a frame, so the container is measurable when boot() runs.
    if (mapEl.offsetParent !== null) boot();
    else window.addEventListener('polaris:atlas-map-show', boot);
})();

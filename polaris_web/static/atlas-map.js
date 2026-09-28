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
    // Cyan is the colour of an aggregate, not of a disclosure level. A
    // ZERO_KNOWLEDGE verification is never plotted at all (C6, enforced in
    // polaris_sql/11_atlas.sql for both the cluster and the point layer), so a
    // cyan marker cannot mean zero-knowledge: it means "a cluster of events".
    var TONE_COLORS = {
        cluster: '#5dd6ff', selective: '#b094eb', full: '#ffc861', alert: '#ff7478'
    };
    var EMPTY_FC = { type: 'FeatureCollection', features: [] };

    // -- Unified filter state (mirrors the v8.3 model the API speaks) ---------
    var filterState = {
        view:      'verification',
        window:    'all',
        modifiers: { pq: false, anomalies: false, full: false },
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

    var renderMode = 'cluster';
    // v9.253 (Map v2): the map is aggregation-first. mapMode selects the layer
    // shown — 'regions' (jurisdiction rollup, the DEFAULT) | 'density' (hexbin)
    // | 'points' (the cluster->point drill). Projection defaults to FLAT; the
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
        loadEventFeed();
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
    // Event source + layers (clusters as sized circles, points as reticles)
    // =========================================================================
    function addEventLayers() {
        if (map.getSource('atlas-events')) return;
        map.addSource('atlas-events', {
            type: 'geojson',
            data: { type: 'FeatureCollection', features: [] }
        });

        var toneColor = ['match', ['get', 'tone'],
            'alert', TONE_COLORS.alert, 'full', TONE_COLORS.full,
            'selective', TONE_COLORS.selective, 'cluster', TONE_COLORS.cluster,
            TONE_COLORS.cluster];

        map.addLayer({
            id: 'atlas-clusters', type: 'circle', source: 'atlas-events',
            filter: ['==', ['get', 'isCluster'], true],
            paint: {
                'circle-radius': ['interpolate', ['linear'], ['get', 'count'],
                    1, 9, 10, 16, 100, 26, 1000, 38, 100000, 54],
                'circle-color': toneColor, 'circle-opacity': 0.22,
                'circle-stroke-width': 1.5, 'circle-stroke-color': toneColor,
                'circle-stroke-opacity': 0.9
            }
        });
        map.addLayer({
            id: 'atlas-cluster-count', type: 'symbol', source: 'atlas-events',
            filter: ['==', ['get', 'isCluster'], true],
            layout: {
                'text-field': ['get', 'countLabel'], 'text-size': 11,
                'text-font': ['Open Sans Bold'], 'text-allow-overlap': true
            },
            paint: { 'text-color': '#eaf4ff', 'text-halo-color': '#050a12', 'text-halo-width': 1 }
        });
        map.addLayer({
            id: 'atlas-points', type: 'circle', source: 'atlas-events',
            filter: ['!=', ['get', 'isCluster'], true],
            paint: {
                'circle-radius': ['interpolate', ['linear'], ['zoom'], 4, 5, 14, 9],
                'circle-color': toneColor, 'circle-opacity': 0.95,
                'circle-stroke-width': 2, 'circle-stroke-color': '#050a12'
            }
        });

        map.on('click', 'atlas-clusters', function (e) {
            map.flyTo({ center: e.features[0].geometry.coordinates,
                        zoom: Math.min(18, map.getZoom() + 2.2), speed: 1.1 });
        });
        map.on('click', 'atlas-points', function (e) { selectFeature(e.features[0]); });
        ['atlas-clusters', 'atlas-points'].forEach(function (id) {
            map.on('mouseenter', id, function () { map.getCanvas().style.cursor = 'pointer'; });
            map.on('mouseleave', id, function () { map.getCanvas().style.cursor = ''; });
        });

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

        // Drill: a click on any aggregate flies in and drops to the Points view.
        map.on('click', 'atlas-region-fill', function (e) {
            drillToPoints(e.features[0].geometry.coordinates, 6);
        });
        map.on('click', 'atlas-hex-fill', function (e) {
            var g = e.features[0].geometry.coordinates[0];
            drillToPoints(g[0], Math.max(6, map.getZoom() + 2));
        });
        ['atlas-region-fill', 'atlas-hex-fill'].forEach(function (id) {
            map.on('mouseenter', id, function () { map.getCanvas().style.cursor = 'pointer'; });
            map.on('mouseleave', id, function () { map.getCanvas().style.cursor = ''; });
        });

        // --- Subject-focus layers (v9.148): one investigated subject's path ---
        // A gold trajectory connecting their disclosed events in time order, on
        // top of (and replacing) the operational clusters. ZK events are never
        // here, the server withholds them.
        map.addSource('atlas-subject', { type: 'geojson', data: { type: 'FeatureCollection', features: [] } });
        map.addSource('atlas-subject-path', { type: 'geojson', data: { type: 'FeatureCollection', features: [] } });
        map.addLayer({
            id: 'atlas-subject-line', type: 'line', source: 'atlas-subject-path',
            paint: { 'line-color': '#e8be64', 'line-width': 2, 'line-opacity': 0.7, 'line-dasharray': [2, 1.5] }
        });
        map.addLayer({
            id: 'atlas-subject-points', type: 'circle', source: 'atlas-subject',
            paint: {
                'circle-radius': ['interpolate', ['linear'], ['zoom'], 3, 6, 14, 11],
                'circle-color': ['match', ['get', 'tone'],
                    'alert', TONE_COLORS.alert, 'full', TONE_COLORS.full,
                    'selective', TONE_COLORS.selective, '#e8be64'],
                'circle-stroke-width': 2.5, 'circle-stroke-color': '#e8be64', 'circle-opacity': 0.95
            }
        });
        map.addLayer({
            id: 'atlas-subject-seq', type: 'symbol', source: 'atlas-subject',
            layout: { 'text-field': ['get', 'seq'], 'text-size': 10, 'text-font': ['Open Sans Bold'],
                      'text-offset': [0, -1.3], 'text-allow-overlap': true },
            paint: { 'text-color': '#ffe9b0', 'text-halo-color': '#050a12', 'text-halo-width': 1 }
        });
        map.on('click', 'atlas-subject-points', function (e) { selectFeature(e.features[0]); });
        map.on('mouseenter', 'atlas-subject-points', function () { map.getCanvas().style.cursor = 'pointer'; });
        map.on('mouseleave', 'atlas-subject-points', function () { map.getCanvas().style.cursor = ''; });
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
    function chooseGrid(z) {
        if (z >= 14) return 0.01;  /* ~1 km: street-level pinpointing */
        if (z >= 12) return 0.02;
        if (z >= 10) return 0.05;
        if (z >= 8)  return 0.2;
        if (z >= 6)  return 0.5;
        if (z >= 5)  return 1;
        if (z >= 3)  return 2;
        if (z >= 1.5) return 5;
        return 10;
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

    // Hex size (circumradius, degrees) by zoom — mirrors chooseGrid's ramp so a
    // Density hex is a sensible bin at each scale. The client renders with the
    // SAME size it sends, so the lattice tiles perfectly.
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
        if (!map.getSource || !map.getSource('atlas-events')) return;
        if (focusedSubject) return;   // subject-focus owns the map; no operational fetch
        var bbox = currentBbox();
        var kind = apiKind();
        var filterQS = serializeFilters();
        var bboxParam = bbox.join(',');
        var b3 = bbox.map(function (v) { return v.toFixed(3); }).join(',');

        var key;
        if (mapMode === 'regions')      key = 'regions|' + kind + '|' + filterQS;         // not viewport-bound
        else if (mapMode === 'density') key = 'density|' + kind + '|' + b3 + '|' + chooseHexSize(map.getZoom()) + '|' + filterQS;
        else                            key = 'points|'  + kind + '|' + b3 + '|' + chooseGrid(map.getZoom()) + '|' + filterQS;
        if (key === lastFetchKey) return;
        lastFetchKey = key;

        if (inflight) inflight.abort();
        inflight = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        var signal = inflight ? inflight.signal : undefined;

        clearLayersExcept(mapMode);
        if (mapMode === 'regions')      fetchRegions(kind, filterQS, signal);
        else if (mapMode === 'density') fetchDensity(bboxParam, kind, filterQS, signal);
        else                            fetchPoints(bboxParam, kind, filterQS, signal);

        apiCall('/api/atlas/stats?bbox=' + encodeURIComponent(bboxParam) + '&' + filterQS, signal)
            .then(updateStats)
            .catch(function (err) { if (err.name !== 'AbortError') { /* HUD stale; non-fatal */ } });
    }

    // -- Points mode: the existing cluster->point drill (aggregate at a --------
    // distance, individual reticles once a cell holds few enough events). ------
    function fetchPoints(bboxParam, kind, filterQS, signal) {
        var grid = chooseGrid(map.getZoom());
        apiCall('/api/atlas/clusters?bbox=' + encodeURIComponent(bboxParam) +
                '&grid=' + grid + '&kind=' + kind + '&' + filterQS, signal)
            .then(function (data) {
                if (data.count <= 30 && map.getZoom() >= 5) {
                    return apiCall('/api/atlas/points?bbox=' + encodeURIComponent(bboxParam) +
                                   '&kind=' + kind + '&limit=500&' + filterQS, signal)
                        .then(function (pts) {
                            renderMode = 'point';
                            setFeatures((pts.points || []).map(function (p) { return pointFeature(p, kind); }));
                        });
                }
                renderMode = 'cluster';
                setFeatures((data.clusters || []).map(function (c) { return clusterFeature(c, kind); }));
            })
            .catch(function (err) {
                if (err.name !== 'AbortError') { lastFetchKey = null; showAtlasError(err); }
            });
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
        if (mode !== 'points'  && map.getSource('atlas-events'))  map.getSource('atlas-events').setData(EMPTY_FC);
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

    // Switch the active layer. Drill and the mode chips both route through here.
    function setMode(mode) {
        if (mode !== 'regions' && mode !== 'density' && mode !== 'points') return;
        mapMode = mode;
        updateModeUI();
        updateLegendForMode();
        refetchAll();
    }
    function drillToPoints(center, zoom) {
        mapMode = 'points';
        updateModeUI();
        updateLegendForMode();
        map.flyTo({ center: center, zoom: Math.max(map.getZoom(), zoom || 6), speed: 1.1 });
        refetchAll();   // moveend will also fire; the dedup key absorbs the double
    }

    function setFeatures(features) {
        var src = map.getSource('atlas-events');
        if (src) src.setData({ type: 'FeatureCollection', features: features });
        applyPointFilter();
        toggleEmptyHint(features.length === 0);
        hideAtlasError();
    }

    // +PQ modifier filters individual reticles to post-quantum-signed events
    // (clusters are aggregates and keep showing; the HUD carries the PQ %).
    function applyPointFilter() {
        if (!map.getLayer || !map.getLayer('atlas-points')) return;
        var base = ['!=', ['get', 'isCluster'], true];
        map.setFilter('atlas-points',
            filterState.modifiers.pq ? ['all', base, ['==', ['get', 'pq'], true]] : base);
    }

    // -- Feature builders -----------------------------------------------------
    function fmtCount(n) { return n >= 1000 ? (n / 1000).toFixed(n >= 10000 ? 0 : 1) + 'k' : String(n); }

    function clusterFeature(c, kind) {
        var alert = (c.n_failure || 0) + (c.n_revoked || 0) + (c.n_lost || 0);
        var tone = alert > 0 ? 'alert' : 'cluster';
        return {
            type: 'Feature',
            geometry: { type: 'Point', coordinates: [c.lon, c.lat] },
            properties: {
                isCluster: true, tone: tone, count: c.n_total,
                countLabel: fmtCount(c.n_total),
                meta: kind === 'verification'
                    ? ((c.n_failure || 0) + ' failures · ' + (c.n_full || 0) + ' FULL')
                    : ((c.n_revoked || 0) + ' revoked · ' + (c.n_lost || 0) + ' lost'),
                kind: kind
            }
        };
    }

    function pointFeature(p, kind) {
        var tone;
        if (kind === 'verification') {
            // The precise-point layer receives SELECTIVE and FULL only: the
            // query drops ZERO_KNOWLEDGE rows (C6). An unexpected one is drawn
            // in the aggregate colour rather than mislabelled as a disclosure,
            // and announced, because it would mean the server broke C6.
            if (p.disclosure_level === 'ZERO_KNOWLEDGE') {
                console.warn('Atlas: a zero-knowledge verification reached the point layer; C6 expects none.');
            }
            tone = p.outcome && p.outcome !== 'SUCCESS' ? 'alert'
                 : (p.disclosure_level === 'FULL' ? 'full'
                 : (p.disclosure_level === 'SELECTIVE' ? 'selective' : 'cluster'));
        } else {
            tone = ['REVOKED', 'LOST', 'EXPIRED', 'DEVICE_REVOKED'].indexOf(p.event_type) >= 0
                 ? 'alert' : 'selective';
        }
        return {
            type: 'Feature',
            geometry: { type: 'Point', coordinates: [p.lon, p.lat] },
            properties: {
                isCluster: false, tone: tone, kind: kind,
                event_id: p.event_id, token_id: p.token_id || null,
                holder: p.holder_name || null, agency: p.agency_name || null,
                algorithm: p.algorithm_name || null, pq: !!p.pq,
                context: p.context_type || null, outcome: p.outcome || null,
                disclosure: p.disclosure_level || null, eventType: p.event_type || null,
                reason: p.reason_code || null, timestamp: p.event_timestamp || null,
                location: p.requestor_location || null
            }
        };
    }

    // =========================================================================
    // Node console (dock tab "console", auto-activated on selection)
    // =========================================================================
    var detail = document.getElementById('atlas-globe-detail');

    function activateDockTab(name) {
        document.querySelectorAll('[data-dock-tab]').forEach(function (b) {
            b.classList.toggle('dock-tab-active', b.dataset.dockTab === name);
        });
        document.querySelectorAll('[data-dock-panel]').forEach(function (p) {
            p.classList.toggle('dock-panel-active', p.dataset.dockPanel === name);
        });
    }
    document.querySelectorAll('[data-dock-tab]').forEach(function (b) {
        b.addEventListener('click', function () { activateDockTab(b.dataset.dockTab); });
    });

    function row(label, value) {
        if (value === null || value === undefined || value === '') return null;
        var d = document.createElement('div');
        d.className = 'detail-row';
        var k = document.createElement('span'); k.className = 'detail-k'; k.textContent = label;
        var v = document.createElement('span'); v.className = 'detail-v'; v.textContent = value;
        d.appendChild(k); d.appendChild(v); return d;
    }

    function selectFeature(f) {
        if (!detail) return;
        activateDockTab('console');
        var pr = f.properties || {};
        detail.replaceChildren();

        var kicker = document.createElement('span');
        kicker.className = 'detail-kicker';
        kicker.textContent = (pr.kind === 'lifecycle' ? 'LIFECYCLE EVENT' : 'VERIFICATION EVENT')
                             + ' / ' + (pr.eventType || pr.context || 'EVENT') + '-' + (pr.event_id || '');
        detail.appendChild(kicker);

        var title = document.createElement('strong');
        title.textContent = pr.kind === 'lifecycle'
            ? (pr.eventType || 'Lifecycle') + ' · token #' + (pr.token_id || '?')
            : (pr.context || 'Verification') + ' verification';
        detail.appendChild(title);

        var c = (f.geometry && f.geometry.coordinates) || null;
        var coordText = c
            ? Math.abs(c[1]).toFixed(4) + '°' + (c[1] >= 0 ? 'N' : 'S') + '  '
              + Math.abs(c[0]).toFixed(4) + '°' + (c[0] >= 0 ? 'E' : 'W')
            : null;
        [
            row('Event', pr.kind === 'lifecycle' ? (pr.eventType || 'lifecycle') : (pr.context || 'verification')),
            row('Event ID', pr.event_id),
            row('Token', pr.token_id ? '#' + pr.token_id : null),
            row('Holder', pr.holder),
            row('Agency', pr.agency),
            row('Algorithm', pr.algorithm ? pr.algorithm + (pr.pq ? '  · PQ' : '  · classical') : null),
            row('Outcome', pr.outcome),
            row('Disclosure', pr.disclosure),
            row('Reason', pr.reason),
            row('Location', pr.location),
            row('Coordinates', coordText),
            row('When', pr.timestamp)
        ].forEach(function (r) { if (r) detail.appendChild(r); });

        if (pr.token_id) {
            var actions = document.createElement('div');
            actions.className = 'detail-actions';
            var link = document.createElement('a');
            link.className = 'detail-link';
            link.href = '/tokens/' + pr.token_id;
            link.textContent = 'Open token detail →';
            actions.appendChild(link);
            // Download everything the operator may see for this token (gated +
            // audit-logged server-side; ZK verifications carry no token link so
            // they are not in the export).
            var dl = document.createElement('a');
            dl.className = 'detail-link';
            dl.href = '/api/tokens/' + pr.token_id + '/export';
            dl.setAttribute('download', '');
            dl.textContent = '⤓ Download token data (JSON)';
            actions.appendChild(dl);
            detail.appendChild(actions);
        }
        if (c) map.flyTo({ center: c, zoom: Math.max(map.getZoom(), 9), speed: 0.9 });
    }

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
    // Event feed (dock) + cursor / readouts / clock
    // =========================================================================
    var feedEl = document.querySelector('[data-atlas-event-feed]');
    var feedLoading = false, feedCursor = null;

    function feedRow(ev) {
        var li = document.createElement('li');
        li.className = 'atlas-feed-row tone-' + (ev.tone || 'selective');
        var badge = document.createElement('span');
        badge.className = 'atlas-feed-badge';
        badge.textContent = (ev.kind === 'lifecycle' ? (ev.event_type || 'LIFECYCLE') : (ev.context_type || 'VERIFICATION'));
        var body = document.createElement('span');
        body.className = 'atlas-feed-body';
        body.textContent = ev.holder_name || (ev.token_id ? 'token #' + ev.token_id : '(zero-knowledge)');
        var sub = document.createElement('span');
        sub.className = 'atlas-feed-sub';
        sub.textContent = (ev.agency_name || '') + (ev.requestor_location ? ' · ' + ev.requestor_location : '');
        var stamp = document.createElement('time');
        stamp.className = 'atlas-feed-stamp';
        stamp.textContent = ev.event_timestamp || '';
        li.appendChild(badge); li.appendChild(stamp); li.appendChild(body); li.appendChild(sub);
        if (ev.lat != null && ev.lon != null) {
            li.style.cursor = 'pointer';
            li.addEventListener('click', function () {
                map.flyTo({ center: [ev.lon, ev.lat], zoom: Math.max(map.getZoom(), 9), speed: 0.9 });
            });
        }
        return li;
    }

    function loadEventFeed() {
        if (feedLoading || !feedEl) return;
        feedLoading = true;
        var url = '/api/atlas/events?limit=50' + (feedCursor ? '&cursor=' + encodeURIComponent(feedCursor) : '');
        apiCall(url).then(function (data) {
            (data.events || []).forEach(function (ev) { feedEl.appendChild(feedRow(ev)); });
            feedCursor = data.next_cursor;
            feedLoading = false;
            var c = document.querySelector('[data-atlas-feed-count]');
            if (c) c.textContent = String(feedEl.children.length);
        }).catch(function () { feedLoading = false; });
    }

    if (feedEl) {
        feedEl.innerHTML = '';
        var rail = feedEl.closest('[data-atlas-event-feed-scroll]') || feedEl;
        rail.addEventListener('scroll', function () {
            if (rail.scrollTop + rail.clientHeight >= rail.scrollHeight - 80 && feedCursor) loadEventFeed();
        });
    }

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
    // Subject focus (v9.148), single-subject investigation (admin/auditor).
    // Search a person, drop everything else, plot only their disclosed events
    // as a gold path of "what they did". ZK verifications are withheld by the
    // server and reported as a count. This is governed (gated + audit-logged
    // server-side), not population profiling.
    // =========================================================================
    var focusedSubject = null;
    var searchInput = document.querySelector('[data-atlas-subject-search]');
    var resultsEl = document.querySelector('[data-atlas-subject-results]');
    var bannerEl = document.querySelector('[data-atlas-subject-banner]');

    function setOperationalLayers(visible) {
        ['atlas-clusters', 'atlas-cluster-count', 'atlas-points',
         'atlas-region-fill', 'atlas-region-count', 'atlas-hex-fill', 'atlas-hex-stroke'].forEach(function (id) {
            if (map.getLayer(id)) map.setLayoutProperty(id, 'visibility', visible ? 'visible' : 'none');
        });
    }

    function subjectFeature(ev, kind, seq) {
        var tone;
        if (kind === 'verification') {
            tone = ev.outcome && ev.outcome !== 'SUCCESS' ? 'alert'
                 : (ev.disclosure_level === 'FULL' ? 'full' : 'selective');
        } else {
            tone = ['REVOKED', 'LOST', 'EXPIRED'].indexOf(ev.event_type) >= 0 ? 'alert' : 'selective';
        }
        return {
            type: 'Feature', geometry: { type: 'Point', coordinates: [ev.lon, ev.lat] },
            properties: {
                isCluster: false, kind: kind, tone: tone, seq: String(seq),
                event_id: ev.event_id, token_id: ev.token_id || null,
                agency: ev.agency_name || null, context: ev.context_type || null,
                outcome: ev.outcome || null, disclosure: ev.disclosure_level || null,
                eventType: ev.event_type || null, reason: ev.reason_code || null,
                timestamp: ev.event_timestamp || null, location: ev.requestor_location || null
            }
        };
    }

    function focusSubject(id, name) {
        apiCall('/api/atlas/subject?individual_id=' + encodeURIComponent(id))
            .then(function (data) {
                focusedSubject = data.individual;
                if (inflight) inflight.abort();
                // Combine verifications AND lifecycle events (issuance/activation/
                // revocation), ordered in time, the real "what they did" path. A
                // subject may have only a lifecycle event (e.g. just an ISSUED
                // activation and no verifications yet); it must still plot and the
                // map must still zoom to it.
                var all = []
                    .concat((data.verifications || []).map(function (ev) { return { ev: ev, kind: 'verification' }; }))
                    .concat((data.lifecycle || []).map(function (ev) { return { ev: ev, kind: 'lifecycle' }; }));
                all.sort(function (a, b) {
                    return (a.ev.event_timestamp || '') < (b.ev.event_timestamp || '') ? -1 : 1;
                });
                var feats = [], coords = [];
                all.forEach(function (item, i) {
                    feats.push(subjectFeature(item.ev, item.kind, i + 1));
                    coords.push([item.ev.lon, item.ev.lat]);
                });
                map.getSource('atlas-subject').setData({ type: 'FeatureCollection', features: feats });
                map.getSource('atlas-subject-path').setData(coords.length >= 2
                    ? { type: 'FeatureCollection', features: [{ type: 'Feature',
                        geometry: { type: 'LineString', coordinates: coords }, properties: {} }] }
                    : { type: 'FeatureCollection', features: [] });
                setOperationalLayers(false);
                // In focus mode the banner is the single source of truth; the
                // separate empty-hint chip stays hidden so the two never overlap.
                toggleEmptyHint(false);

                // Banner, accurate count, ZK note. "located" counts what is on
                // the map (non-ZK verifications + lifecycle events).
                if (bannerEl) {
                    bannerEl.hidden = false;
                    var nm = document.querySelector('[data-atlas-subject-name]');
                    var st = document.querySelector('[data-atlas-subject-stats]');
                    if (nm) nm.textContent = data.individual.legal_name + '  #' + data.individual.individual_id
                                             + '  · ' + (data.individual.jurisdiction || '');
                    if (st) {
                        st.textContent = data.located === 0
                            ? '0 located events · activity is entirely zero-knowledge (C2)'
                            : (data.located + ' located event' + (data.located === 1 ? '' : 's')
                               + ' · zero-knowledge activity is unattributable (C2)');
                    }
                }

                // Frame the subject's events.
                if (coords.length === 1) {
                    map.flyTo({ center: coords[0], zoom: 12, duration: 900 });
                    selectFeature(feats[0]);   // a single event: open its details immediately
                } else if (coords.length > 1) {
                    var b = coords.reduce(function (bb, c) { return bb.extend(c); },
                        new maplibregl.LngLatBounds(coords[0], coords[0]));
                    map.fitBounds(b, { padding: 90, maxZoom: 14, duration: 900 });
                }
                hideResults();
                if (searchInput) searchInput.value = name || data.individual.legal_name;
            })
            .catch(function (err) {
                if (err.name !== 'AbortError') console.warn('Subject focus failed:', err);
            });
    }

    function clearFocus() {
        focusedSubject = null;
        if (map.getSource('atlas-subject')) map.getSource('atlas-subject').setData({ type: 'FeatureCollection', features: [] });
        if (map.getSource('atlas-subject-path')) map.getSource('atlas-subject-path').setData({ type: 'FeatureCollection', features: [] });
        setOperationalLayers(true);
        if (bannerEl) bannerEl.hidden = true;
        if (searchInput) searchInput.value = '';
        if (emptyChip) emptyChip.hidden = true;
        lastFetchKey = null;
        scheduleFetch();
    }

    function hideResults() { if (resultsEl) { resultsEl.hidden = true; resultsEl.replaceChildren(); } }

    var searchTimer = null;
    if (searchInput) {
        searchInput.addEventListener('input', function () {
            var q = searchInput.value.trim();
            if (searchTimer) clearTimeout(searchTimer);
            if (q.length < 2) { hideResults(); return; }
            searchTimer = setTimeout(function () {
                apiCall('/api/atlas/subjects/search?q=' + encodeURIComponent(q))
                    .then(function (data) {
                        if (!resultsEl) return;
                        resultsEl.replaceChildren();
                        (data.results || []).forEach(function (r) {
                            var b = document.createElement('button');
                            b.type = 'button';
                            b.className = 'subject-result';
                            b.textContent = r.legal_name + '  · ' + (r.jurisdiction || '') + '  #' + r.individual_id;
                            b.addEventListener('click', function () { focusSubject(r.individual_id, r.legal_name); });
                            resultsEl.appendChild(b);
                        });
                        if (!(data.results || []).length) {
                            var none = document.createElement('div');
                            none.className = 'subject-result subject-result-none';
                            none.textContent = 'no match';
                            resultsEl.appendChild(none);
                        }
                        resultsEl.hidden = false;
                    }).catch(function () { hideResults(); });
            }, 220);
        });
        searchInput.addEventListener('keydown', function (e) { if (e.key === 'Escape') hideResults(); });
    }
    var clearBtn = document.querySelector('[data-atlas-subject-clear]');
    if (clearBtn) clearBtn.addEventListener('click', clearFocus);

    // =========================================================================
    // Controls, zoom / reset / spin / fullscreen
    // =========================================================================
    var zin = document.querySelector('[data-atlas-zoom-in]');
    var zout = document.querySelector('[data-atlas-zoom-out]');
    if (zin)  zin.addEventListener('click', function () { map.zoomIn({ duration: 300 }); });
    if (zout) zout.addEventListener('click', function () { map.zoomOut({ duration: 300 }); });

    var resetBtn = document.querySelector('[data-atlas-reset]');
    if (resetBtn) resetBtn.addEventListener('click', function () {
        if (focusedSubject) clearFocus();   // Reset also exits subject focus
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
        // feed: prepend-refresh is heavier; reload from top.
        if (feedEl) { feedEl.innerHTML = ''; feedCursor = null; loadEventFeed(); }
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

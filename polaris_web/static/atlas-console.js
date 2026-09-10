/* ===========================================================================
 * atlas-console.js  —  the Atlas analytical console shell + Overview view.
 * Roadmap P2.3 (v9.248, the analytical-console rebuild).
 *
 * Owns:
 *   1. the view tabs (Overview / Map), booting the MapLibre map LAZILY the
 *      first time the Map tab is shown (a hidden container cannot size a GL
 *      canvas, and an always-live map is wasted work on a page that opens on
 *      the Overview);
 *   2. the Overview view: a bounded, NON-geographic analytics surface built
 *      from /api/atlas/series (volume time-series) + /api/atlas/breakdown
 *      (top-K roll-ups) + the server-rendered point-in-time figures.
 *
 * Every chart is hand-rolled inline SVG or CSS bars, built programmatically
 * (createElement / createElementNS / textContent) — never innerHTML with
 * markup — so `script-src 'self'` (C5) stays strict and no charting CDN is
 * needed. Zero-knowledge events are counted in every figure but never located
 * (C6): the server aggregates enforce that; the console only ever shows counts.
 * ======================================================================== */
(function () {
  'use strict';

  var shell = document.querySelector('.atlas-shell');
  if (!shell) return;

  // ---- tiny helpers --------------------------------------------------------
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  var SVGNS = 'http://www.w3.org/2000/svg';

  function el(tag, attrs, children) {
    var n = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === 'class') n.className = attrs[k];
      else if (k === 'text') n.textContent = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    if (children) children.forEach(function (c) { if (c) n.appendChild(c); });
    return n;
  }
  function svg(tag, attrs) {
    var n = document.createElementNS(SVGNS, tag);
    if (attrs) for (var k in attrs) n.setAttribute(k, attrs[k]);
    return n;
  }
  function fmtInt(n) {
    n = Number(n) || 0;
    if (n >= 1e9) return (n / 1e9).toFixed(1).replace(/\.0$/, '') + 'B';
    if (n >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
    if (n >= 1e3) return (n / 1e3).toFixed(1).replace(/\.0$/, '') + 'k';
    return String(n);
  }
  function fmtPct(x) { return (Math.round(x * 10) / 10) + '%'; }

  function apiCall(url) {
    return fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
      });
  }

  // =========================================================================
  // View tabs (Overview / Map) + lazy map boot
  // =========================================================================
  var mapBooted = false;
  function showView(name) {
    $$('[data-atlas-view-tab]').forEach(function (t) {
      var on = t.getAttribute('data-atlas-view-tab') === name;
      t.classList.toggle('atlas-tab-active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    $$('[data-atlas-view-panel]').forEach(function (p) {
      p.hidden = p.getAttribute('data-atlas-view-panel') !== name;
    });
    if (name === 'map') {
      // Boot the map on first reveal, then keep it resized on every return.
      // rAF so the panel is laid out (measurable) before MapLibre boots/measures.
      requestAnimationFrame(function () {
        window.dispatchEvent(new CustomEvent('polaris:atlas-map-show'));
        if (window.atlasMap && window.atlasMap.resize) window.atlasMap.resize();
      });
      mapBooted = true;
    }
    // The global filter bar drives Overview + Breakdown; the map has its own
    // controls until its redesign, so hide the bar there.
    var gb = document.querySelector('[data-atlas-globalbar]');
    if (gb) gb.hidden = (name === 'map');
    // Reload the shown analytical view so a filter set on another tab applies.
    if (name === 'breakdown') loadBreakdown();
    else if (name === 'records') loadRecords(true);
    else if (name === 'trends') loadTrends();
    else if (name === 'overview' && typeof loadOverview === 'function') loadOverview();
    try { history.replaceState(null, '', '#' + name); } catch (e) { /* ignore */ }
  }
  $$('[data-atlas-view-tab]').forEach(function (t) {
    t.addEventListener('click', function () { showView(t.getAttribute('data-atlas-view-tab')); });
  });
  // Deep-link support: #map opens the map tab directly.
  if ((location.hash || '').replace('#', '') === 'map') showView('map');

  // =========================================================================
  // Global filter state: ONE query drives the Overview and the Breakdown
  // (coordinated, cross-filtered views). Stream, time window, and the facets
  // (context / outcome / disclosure / agency) all live here and serialize into
  // the same server params every atlas aggregate already accepts, so filtering
  // stays a bounded server-side operation at any scale. The map keeps its own
  // controls until its redesign ship.
  // =========================================================================
  var gfilters = {
    stream: 'verification', window: 'all',
    contexts: [], outcomes: [], disclosure: [], agencies: []   // agencies: [{id,name}]
  };
  var FACET_PARAM = { context: 'contexts', outcome: 'outcomes', disclosure: 'disclosure' };

  function gfilterQuery() {
    var p = ['window=' + encodeURIComponent(gfilters.window), 'kind=' + encodeURIComponent(gfilters.stream)];
    if (gfilters.contexts.length)   p.push('contexts=' + gfilters.contexts.map(encodeURIComponent).join(','));
    if (gfilters.outcomes.length)   p.push('outcomes=' + gfilters.outcomes.map(encodeURIComponent).join(','));
    if (gfilters.disclosure.length) p.push('disclosure=' + gfilters.disclosure.map(encodeURIComponent).join(','));
    if (gfilters.agencies.length)   p.push('agencies=' + gfilters.agencies.map(function (a) { return a.id; }).join(','));
    return p.join('&');
  }
  // A facet's own menu counts every OTHER active facet but not itself (standard
  // faceting: you can still see and add the other values of this dimension).
  function facetContextQuery(exceptFacet) {
    var t = 'window=' + encodeURIComponent(gfilters.window) + '&kind=' + encodeURIComponent(gfilters.stream);
    if (exceptFacet !== 'context'    && gfilters.contexts.length)   t += '&contexts=' + gfilters.contexts.map(encodeURIComponent).join(',');
    if (exceptFacet !== 'outcome'    && gfilters.outcomes.length)   t += '&outcomes=' + gfilters.outcomes.map(encodeURIComponent).join(',');
    if (exceptFacet !== 'disclosure' && gfilters.disclosure.length) t += '&disclosure=' + gfilters.disclosure.map(encodeURIComponent).join(',');
    if (exceptFacet !== 'agency'     && gfilters.agencies.length)   t += '&agencies=' + gfilters.agencies.map(function (a) { return a.id; }).join(',');
    return t;
  }

  // =========================================================================
  // Overview state + controls
  // =========================================================================
  var overview = $('[data-atlas-view-panel="overview"]');
  if (!overview) return;

  // Overview reads the global filter state (stream / window / facets).
  var state = gfilters;
  var TONE = { total: '#38bdf8', fail: '#f87171', zk: '#a78bfa' };

  // The breakdown panels each view shows, per stream. A panel names its mount
  // (data-ov-breakdown), its title, and the SQL dimension to request.
  var PANELS = {
    verification: [
      { key: 'context',    title: 'By context',   dim: 'context' },
      { key: 'agency',     title: 'Top agencies', dim: 'agency' },
      { key: 'disclosure', title: 'Disclosure mix', dim: 'disclosure', mix: true },
      { key: 'outcome',    title: 'Outcome mix',  dim: 'outcome' }
    ],
    lifecycle: [
      { key: 'context',    title: 'By event type', dim: 'event_type' },
      { key: 'agency',     title: 'By actor agency', dim: 'agency' }
    ]
  };

  // (Stream + window are driven by the global filter bar, wired below.)
  var retry = $('[data-ov-retry]', overview);
  if (retry) retry.addEventListener('click', loadOverview);

  // =========================================================================
  // Chart primitives (all CSP-clean: programmatic SVG / DOM)
  // =========================================================================

  // A filled area for the primary series with a stroked overlay for failures.
  function renderHero(mount, points) {
    mount.textContent = '';
    if (!points || !points.length) {
      mount.appendChild(el('div', { class: 'ov-empty', text: 'No events in this window.' }));
      return;
    }
    var W = 820, H = 220, padL = 8, padR = 8, padT = 12, padB = 22;
    var iW = W - padL - padR, iH = H - padT - padB;
    var maxV = 1;
    points.forEach(function (p) { if (p.n_total > maxV) maxV = p.n_total; });
    var n = points.length;
    function X(i) { return padL + (n === 1 ? iW / 2 : (i / (n - 1)) * iW); }
    function Y(v) { return padT + iH - (v / maxV) * iH; }

    // role="img" without a name announces "graphic" and nothing else, which is what a
    // screen-reader operator got from this chart. The label is built from the data so it
    // says what the picture says, rather than being a static string that goes stale. (P6.5)
    var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'ov-hero-svg',
      preserveAspectRatio: 'none', role: 'img',
      'aria-label': 'Verification volume over time: ' + n + ' interval'
        + (n === 1 ? '' : 's') + ', peak ' + fmtInt(maxV) + ' per interval' });

    // horizontal gridlines at 0/50/100% of max
    [0, 0.5, 1].forEach(function (f) {
      var y = padT + iH - f * iH;
      s.appendChild(svg('line', { x1: padL, y1: y, x2: W - padR, y2: y, class: 'ov-gridline' }));
      s.appendChild(svg('text', { x: padL + 2, y: y - 3, class: 'ov-axis' })).textContent =
        f === 0 ? '' : fmtInt(Math.round(maxV * f));
    });

    // area path for n_total
    var d = 'M ' + X(0) + ' ' + Y(points[0].n_total);
    for (var i = 1; i < n; i++) d += ' L ' + X(i) + ' ' + Y(points[i].n_total);
    var area = d + ' L ' + X(n - 1) + ' ' + (padT + iH) + ' L ' + X(0) + ' ' + (padT + iH) + ' Z';
    s.appendChild(svg('path', { d: area, class: 'ov-area' }));
    s.appendChild(svg('path', { d: d, class: 'ov-line' }));

    // failure overlay (only if any)
    var anyFail = points.some(function (p) { return p.n_failure > 0; });
    if (anyFail) {
      var fd = 'M ' + X(0) + ' ' + Y(points[0].n_failure);
      for (var j = 1; j < n; j++) fd += ' L ' + X(j) + ' ' + Y(points[j].n_failure);
      s.appendChild(svg('path', { d: fd, class: 'ov-line-fail' }));
    }
    mount.appendChild(s);

    // date range under the chart
    var range = el('div', { class: 'ov-hero-range' });
    range.appendChild(el('span', { text: shortTs(points[0].ts) }));
    range.appendChild(el('span', { text: shortTs(points[n - 1].ts) }));
    mount.appendChild(range);
  }

  function shortTs(ts) {
    if (!ts) return '';
    // ts is 'YYYY-MM-DDTHH:MM:SS'; show date, plus time only for sub-day ranges.
    return ts.slice(0, 10);
  }

  function renderSparkline(mount, values, tone) {
    mount.textContent = '';
    if (!values || !values.length) return;
    var W = 100, H = 26, max = 1;
    values.forEach(function (v) { if (v > max) max = v; });
    var n = values.length;
    var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'ov-spark-svg', preserveAspectRatio: 'none' });
    function X(i) { return n === 1 ? W / 2 : (i / (n - 1)) * W; }
    function Y(v) { return H - 2 - (v / max) * (H - 4); }
    var d = 'M ' + X(0) + ' ' + Y(values[0]);
    for (var i = 1; i < n; i++) d += ' L ' + X(i) + ' ' + Y(values[i]);
    var p = svg('path', { d: d, fill: 'none', stroke: tone || TONE.total, 'stroke-width': '1.5' });
    s.appendChild(p);
    mount.appendChild(s);
  }

  // Horizontal bars: fill width is n_total / max, split into success + failure.
  function renderBars(mount, cats, onClick) {
    mount.textContent = '';
    if (!cats || !cats.length) {
      mount.appendChild(el('div', { class: 'ov-empty', text: 'No data in this window.' }));
      return;
    }
    var max = 1;
    cats.forEach(function (c) { if (c.n_total > max) max = c.n_total; });
    cats.forEach(function (c) {
      var row = el('div', { class: 'ov-bar-row' + (onClick ? ' ov-bar-row-click' : '') });
      if (onClick) {
        row.title = 'Filter to ' + c.label;
        row.addEventListener('click', function () { onClick(c.label); });
      }
      row.appendChild(el('span', { class: 'ov-bar-label', title: c.label, text: c.label }));
      var track = el('span', { class: 'ov-bar-track' });
      var okN = Math.max(0, c.n_total - c.n_failure);
      var ok = el('span', { class: 'ov-bar-fill' });
      ok.style.width = (100 * okN / max) + '%';
      track.appendChild(ok);
      if (c.n_failure > 0) {
        var bad = el('span', { class: 'ov-bar-fill ov-bar-fill-fail',
          title: c.n_failure + ' non-success' });
        bad.style.width = (100 * c.n_failure / max) + '%';
        track.appendChild(bad);
      }
      row.appendChild(track);
      row.appendChild(el('span', { class: 'ov-bar-val', text: fmtInt(c.n_total) }));
      mount.appendChild(row);
    });
  }

  // A single stacked bar of category shares (for the disclosure mix).
  function renderMix(mount, cats) {
    mount.textContent = '';
    if (!cats || !cats.length) return;
    var total = 0;
    cats.forEach(function (c) { total += c.n_total; });
    if (!total) return;
    var mixTone = { ZERO_KNOWLEDGE: TONE.zk, SELECTIVE: '#38bdf8', FULL: '#fbbf24' };
    var bar = el('div', { class: 'ov-mix-bar' });
    var legend = el('div', { class: 'ov-mix-legend' });
    cats.forEach(function (c) {
      var pct = 100 * c.n_total / total;
      var seg = el('span', { class: 'ov-mix-seg', title: c.label + ' ' + fmtPct(pct) });
      seg.style.width = pct + '%';
      seg.style.background = mixTone[c.label] || '#64748b';
      bar.appendChild(seg);
      var li = el('span', { class: 'ov-mix-li' });
      var dot = el('i', { class: 'ov-mix-dot' }); dot.style.background = mixTone[c.label] || '#64748b';
      li.appendChild(dot);
      li.appendChild(el('span', { text: prettyLabel(c.label) + ' ' + fmtPct(pct) }));
      legend.appendChild(li);
    });
    mount.appendChild(bar);
    mount.appendChild(legend);
  }

  function prettyLabel(s) {
    return String(s).replace(/_/g, ' ').toLowerCase().replace(/^./, function (m) { return m.toUpperCase(); });
  }

  // =========================================================================
  // Overview data load
  // =========================================================================
  function setKpi(key, text) {
    var n = $('[data-ov-kpi="' + key + '"]', overview);
    if (n) n.textContent = text;
  }
  function setSub(key, text) {
    var n = $('[data-ov-kpi-sub="' + key + '"]', overview);
    if (n) n.textContent = text;
  }
  function showError(msg) {
    var box = $('[data-ov-error]', overview);
    if (!box) return;
    box.hidden = false;
    var d = $('[data-ov-error-detail]', overview);
    if (d) d.textContent = msg || 'Could not load analytics.';
  }
  function hideError() {
    var box = $('[data-ov-error]', overview);
    if (box) box.hidden = true;
  }

  var loadSeq = 0;
  function loadOverview() {
    var seq = ++loadSeq;
    hideError();
    configurePanels();
    var q = gfilterQuery();

    // 1) the volume series drives the hero + the volume/failure/zk KPIs.
    apiCall('/api/atlas/series?' + q + '&buckets=48').then(function (data) {
      if (seq !== loadSeq) return;
      var pts = data.points || [];
      renderHero($('[data-ov-hero]', overview), pts);
      var vol = 0, fail = 0, zk = 0;
      pts.forEach(function (p) { vol += p.n_total; fail += p.n_failure; zk += p.n_zk; });
      setKpi('volume', fmtInt(vol));
      setSub('volume', windowLabel(data));
      setKpi('failure-rate', vol ? fmtPct(100 * fail / vol) : '0%');
      setSub('failure-rate', fmtInt(fail) + ' non-success');
      if (state.stream === 'verification') setKpi('zk', vol ? fmtPct(100 * zk / vol) : '0%');
      renderSparkline($('[data-ov-spark="volume"]', overview), pts.map(function (p) { return p.n_total; }), TONE.total);
      renderSparkline($('[data-ov-spark="failure"]', overview), pts.map(function (p) { return p.n_failure; }), TONE.fail);
      if (state.stream === 'verification')
        renderSparkline($('[data-ov-spark="zk"]', overview), pts.map(function (p) { return p.n_zk; }), TONE.zk);
      var scope = $('[data-ov-scope]', overview);
      if (scope) scope.textContent = pts.length ? (shortTs(pts[0].ts) + ' → ' + shortTs(pts[pts.length - 1].ts)) : '';
    }).catch(function (e) { if (seq === loadSeq) showError('Volume series failed: ' + e.message); });

    // 2) the breakdown panels.
    PANELS[state.stream].forEach(function (panel) {
      var mount = $('[data-ov-breakdown="' + panel.key + '"]', overview);
      if (!mount) return;
      apiCall('/api/atlas/breakdown?' + q + '&dimension=' + panel.dim + '&limit=12').then(function (data) {
        if (seq !== loadSeq) return;
        var cats = data.categories || [];
        // Cross-filtering: a value-based facet dimension's bars filter the whole
        // console on click (agency needs an id, so it is not click-to-filter here).
        var onClick = FACET_PARAM[panel.dim]
          ? function (label) { toggleFacetValue(panel.dim, label); }
          : null;
        renderBars(mount, cats, onClick);
        if (panel.mix) {
          var mixMount = $('[data-ov-mix="disclosure"]', overview);
          if (mixMount) renderMix(mixMount, cats);
        }
      }).catch(function (e) { if (seq === loadSeq) showError('Breakdown failed: ' + e.message); });
    });
  }

  function windowLabel(data) {
    if (state.window === 'all') return 'all recorded';
    return 'last ' + state.window;
  }

  // Show only the panels this stream has data for; retitle the shared mounts.
  function configurePanels() {
    var active = PANELS[state.stream];
    var byKey = {};
    active.forEach(function (p) { byKey[p.key] = p; });
    $$('[data-ov-panel]', overview).forEach(function (card) {
      var key = card.getAttribute('data-ov-panel');
      var p = byKey[key];
      card.hidden = !p;
      if (p) {
        var title = $('.ov-card-title', card);
        if (title) title.textContent = p.title;
        var mixMount = $('[data-ov-mix]', card);
        if (mixMount) mixMount.hidden = !p.mix;
      }
    });
    // the hero title + zk KPI visibility follow the stream
    var ht = $('[data-ov-hero-title]', overview);
    if (ht) ht.textContent = state.stream === 'verification' ? 'Verification volume' : 'Lifecycle volume';
    var zkCard = $('[data-ov-kpi="zk"]', overview);
    if (zkCard) {
      var card = zkCard.closest('.ov-kpi');
      if (card) card.hidden = state.stream !== 'verification';
    }
  }

  // =========================================================================
  // Breakdown view (v9.249): slice one dimension, then cross-tab it against
  // outcome and disclosure so an anomalous profile stands out.
  // =========================================================================
  var bd = $('[data-atlas-view-panel="breakdown"]');
  var bdState = { dim: 'agency', metric: 'volume', search: '' };  // stream/window are global
  var BD_DIMS = {
    verification: [
      { key: 'agency', label: 'Agency' }, { key: 'context', label: 'Context' },
      { key: 'jurisdiction', label: 'Jurisdiction' }, { key: 'algorithm', label: 'Algorithm' }
    ],
    lifecycle: [{ key: 'agency', label: 'Agency' }]
  };
  var BD_XTABS = {
    verification: [
      { col: 'outcome', title: 'Profile by outcome' },
      { col: 'disclosure', title: 'Profile by disclosure' }
    ],
    lifecycle: [{ col: 'event_type', title: 'Profile by event type' }]
  };
  var COL_TONE = {
    SUCCESS: '#5fd9a2', FAILURE: '#f87171', EXPIRED: '#fbbf24', UNAUTHORIZED: '#f87171',
    ZERO_KNOWLEDGE: '#a78bfa', SELECTIVE: '#38bdf8', FULL: '#fbbf24'
  };
  function hexA(hex, a) {
    var n = parseInt(hex.slice(1), 16);
    return 'rgba(' + ((n >> 16) & 255) + ',' + ((n >> 8) & 255) + ',' + (n & 255) + ',' + a.toFixed(3) + ')';
  }

  function bdSetChips(attr, value, root) {
    $$('[' + attr + ']', root || bd).forEach(function (c) {
      var on = c.getAttribute(attr) === value;
      c.classList.toggle('toolbar-chip-active', on);
      c.setAttribute('aria-checked', on ? 'true' : 'false');
    });
  }
  function bdBuildDimPicker() {
    var group = $('[data-bd-dim-group]', bd);
    if (!group) return;
    group.textContent = '';
    BD_DIMS[gfilters.stream].forEach(function (d) {
      var b = el('button', { class: 'toolbar-chip', type: 'button', role: 'radio',
        'data-bd-dim': d.key, 'aria-checked': 'false', text: d.label });
      b.addEventListener('click', function () {
        bdState.dim = d.key; bdSetChips('data-bd-dim', d.key); bdClearSearch(); loadBreakdown();
      });
      group.appendChild(b);
    });
    // keep a valid selection when switching streams
    if (!BD_DIMS[gfilters.stream].some(function (d) { return d.key === bdState.dim; }))
      bdState.dim = BD_DIMS[gfilters.stream][0].key;
    bdSetChips('data-bd-dim', bdState.dim);
  }
  if (bd) {
    // (Stream + window are global, wired in the global filter bar below.)
    $$('[data-bd-metric]', bd).forEach(function (c) {
      c.addEventListener('click', function () {
        bdState.metric = c.getAttribute('data-bd-metric');
        bdSetChips('data-bd-metric', bdState.metric);
        if (bdLastCats) renderRankedTable($('[data-bd-ranked]', bd), bdLastCats, bdState.metric);
      });
    });
    var bdRetry = $('[data-bd-retry]', bd);
    if (bdRetry) bdRetry.addEventListener('click', loadBreakdown);
    var bdSearchEl = $('[data-bd-search]', bd);
    if (bdSearchEl) {
      var bdSearchTimer = null;
      bdSearchEl.addEventListener('input', function () {
        clearTimeout(bdSearchTimer);
        bdSearchTimer = setTimeout(function () {
          bdState.search = bdSearchEl.value.trim();
          loadRanked();   // only the list re-fetches; the cross-tabs are unaffected by a label filter
        }, 220);
      });
    }
    bdBuildDimPicker();
  }

  function bdClearSearch() {
    bdState.search = '';
    var elx = $('[data-bd-search]', bd);
    if (elx) elx.value = '';
  }

  function renderRankedTable(mount, cats, metric) {
    if (!mount) return;
    mount.textContent = '';
    if (!cats || !cats.length) { mount.appendChild(el('div', { class: 'ov-empty', text: 'No data in this window.' })); return; }
    var total = cats.reduce(function (a, c) { return a + c.n_total; }, 0) || 1;
    var maxV = Math.max.apply(null, cats.map(function (c) { return c.n_total; })) || 1;
    var sorted = cats.slice().sort(function (a, b) {
      if (metric === 'failure') {
        var ra = a.n_total ? a.n_failure / a.n_total : 0, rb = b.n_total ? b.n_failure / b.n_total : 0;
        return (rb - ra) || (b.n_total - a.n_total);
      }
      return b.n_total - a.n_total;
    });
    var head = el('div', { class: 'bd-row bd-row-head' });
    head.appendChild(el('span', { class: 'bd-row-label', text: 'Category' }));
    head.appendChild(el('span', { class: 'bd-row-barhead', text: 'Volume' }));
    head.appendChild(el('span', { class: 'bd-row-vol', text: '#' }));
    head.appendChild(el('span', { class: 'bd-row-rate', text: 'Fail %' }));
    head.appendChild(el('span', { class: 'bd-row-share', text: 'Share' }));
    mount.appendChild(head);
    sorted.forEach(function (c) {
      var rate = c.n_total ? c.n_failure / c.n_total : 0;
      var row = el('div', { class: 'bd-row' });
      row.appendChild(el('span', { class: 'bd-row-label', title: c.label, text: c.label }));
      var track = el('span', { class: 'ov-bar-track' });
      var ok = el('span', { class: 'ov-bar-fill' }); ok.style.width = (100 * (c.n_total - c.n_failure) / maxV) + '%'; track.appendChild(ok);
      if (c.n_failure > 0) { var bad = el('span', { class: 'ov-bar-fill ov-bar-fill-fail' }); bad.style.width = (100 * c.n_failure / maxV) + '%'; track.appendChild(bad); }
      row.appendChild(track);
      row.appendChild(el('span', { class: 'bd-row-vol', text: fmtInt(c.n_total) }));
      row.appendChild(el('span', { class: 'bd-row-rate' + (rate >= 0.15 ? ' bd-rate-high' : ''), text: fmtPct(100 * rate) }));
      row.appendChild(el('span', { class: 'bd-row-share', text: fmtPct(100 * c.n_total / total) }));
      mount.appendChild(row);
    });
  }

  function renderMatrix(mount, data) {
    if (!mount) return;
    mount.textContent = '';
    if (!data || !data.rows.length || !data.cols.length) {
      mount.appendChild(el('div', { class: 'ov-empty', text: 'No data in this window.' })); return;
    }
    var lut = {};
    data.cells.forEach(function (c) { lut[c.row + '\u0000' + c.col] = c.n; });
    var grid = el('div', { class: 'bd-matrix-grid' });
    grid.style.gridTemplateColumns = 'minmax(84px,1.3fr) repeat(' + data.cols.length + ', 1fr) auto';
    grid.appendChild(el('span', { class: 'bd-mx-corner' }));
    data.cols.forEach(function (col) { grid.appendChild(el('span', { class: 'bd-mx-colhead', title: col, text: prettyLabel(col) })); });
    grid.appendChild(el('span', { class: 'bd-mx-colhead bd-mx-total', text: 'Total' }));
    data.rows.forEach(function (r) {
      grid.appendChild(el('span', { class: 'bd-mx-rowhead', title: r.label, text: r.label }));
      data.cols.forEach(function (col) {
        var n = lut[r.label + '\u0000' + col] || 0;
        var share = r.total ? n / r.total : 0;
        var cell = el('span', { class: 'bd-mx-cell', text: n ? fmtInt(n) : '·',
          title: r.label + ' · ' + prettyLabel(col) + ': ' + fmtInt(n) + ' (' + fmtPct(100 * share) + ' of row)' });
        cell.style.background = n ? hexA(COL_TONE[col] || '#8da6c4', 0.10 + 0.60 * share) : 'transparent';
        if (share >= 0.5 && n) cell.classList.add('bd-mx-strong');
        grid.appendChild(cell);
      });
      grid.appendChild(el('span', { class: 'bd-mx-cell bd-mx-total', text: fmtInt(r.total) }));
    });
    mount.appendChild(grid);
  }

  function bdShowError(msg) {
    var box = $('[data-bd-error]', bd); if (!box) return;
    box.hidden = false; var d = $('[data-bd-error-detail]', bd); if (d) d.textContent = msg;
  }

  var bdRankedSeq = 0, bdXtabSeq = 0, bdLastCats = null;

  // The ranked dimension list. Re-fetched on its own for search (a label filter
  // narrows the list without touching the cross-tabs), so thousands of agencies
  // stay findable and the list scrolls inside its own card.
  function loadRanked() {
    if (!bd) return;
    var seq = ++bdRankedSeq;
    var box = $('[data-bd-error]', bd); if (box) box.hidden = true;
    var dim = bdState.dim;
    var title = $('[data-bd-ranked-title]', bd);
    if (title) title.textContent = 'By ' + dim;
    var q = gfilterQuery()
          + '&dimension=' + dim + '&limit=40'
          + (bdState.search ? '&search=' + encodeURIComponent(bdState.search) : '');
    apiCall('/api/atlas/breakdown?' + q).then(function (data) {
      if (seq !== bdRankedSeq) return;
      bdLastCats = data.categories || [];
      renderRankedTable($('[data-bd-ranked]', bd), bdLastCats, bdState.metric);
      var foot = $('[data-bd-count]', bd);
      if (foot) {
        var n = bdLastCats.length, s = bdState.search;
        var plural = n === 1 ? dim : dim.replace(/y$/, 'ie') + 's';
        if (n === 0) foot.textContent = s ? 'No ' + dim + ' matches "' + s + '".' : 'No data in this window.';
        else if (data.truncated) foot.textContent = 'Top ' + n + ' by volume' + (s ? ' matching "' + s + '"' : '') + ' — refine the filter to narrow';
        else foot.textContent = n + ' ' + plural + (s ? ' matching "' + s + '"' : '');
      }
    }).catch(function (e) { if (seq === bdRankedSeq) bdShowError('Breakdown failed: ' + e.message); });
  }

  function loadBreakdown() {
    if (!bd) return;
    loadRanked();
    var seq = ++bdXtabSeq;
    var dim = bdState.dim;
    var q = gfilterQuery();
    var xtabs = BD_XTABS[gfilters.stream];
    ['outcome', 'disclosure'].forEach(function (colKey) {
      var card = $('[data-bd-xtab-card="' + colKey + '"]', bd);
      var conf = xtabs.filter(function (x) { return x.col === colKey; })[0];
      // for lifecycle, reuse the 'outcome' card slot to show the event_type matrix
      if (!conf && colKey === 'outcome' && gfilters.stream === 'lifecycle') conf = xtabs[0];
      if (card) card.hidden = !conf;
      if (!conf) return;
      var mount = $('[data-bd-crosstab="' + colKey + '"]', bd);
      var tEl = $('[data-bd-xtab-title="' + colKey + '"]', bd);
      if (tEl) tEl.textContent = conf.title;
      apiCall('/api/atlas/crosstab?' + q + '&row=' + dim + '&col=' + conf.col + '&limit=20').then(function (data) {
        if (seq !== bdXtabSeq) return;
        renderMatrix(mount, data);
      }).catch(function (e) { if (seq === bdXtabSeq) bdShowError('Cross-tab failed: ' + e.message); });
    });
  }

  // =========================================================================
  // Records view (v9.252): the drill from aggregates into the actual events —
  // a keyset-paginated, filter-aware grid that scales to millions of rows.
  // =========================================================================
  var rec = $('[data-atlas-view-panel="records"]');
  var REC_COLS = {
    verification: [
      { key: 'ts', label: 'Time' }, { key: 'agency', label: 'Agency' },
      { key: 'category', label: 'Context' }, { key: 'outcome', label: 'Outcome', tone: true },
      { key: 'disclosure', label: 'Disclosure', tone: true }, { key: 'subject', label: 'Subject' },
      { key: 'location', label: 'Location' }
    ],
    lifecycle: [
      { key: 'ts', label: 'Time' }, { key: 'agency', label: 'Actor' },
      { key: 'category', label: 'Event type', tone: true }, { key: 'outcome', label: 'Reason' },
      { key: 'subject', label: 'Subject' }
    ]
  };
  var REC_TONE = {
    SUCCESS: '#5fd9a2', FAILURE: '#f87171', EXPIRED: '#fbbf24', UNAUTHORIZED: '#f87171',
    ZERO_KNOWLEDGE: '#a78bfa', SELECTIVE: '#38bdf8', FULL: '#fbbf24',
    REVOKED: '#f87171', LOST: '#f87171', ISSUED: '#38bdf8', ACTIVATED: '#5fd9a2'
  };
  var recCursor = null, recTotal = 0, recLoading = false;

  function recEnsureTable() {
    var wrap = $('[data-rec-grid]', rec);
    var body = $('[data-rec-body]', rec);
    if (body) return body;   // already built for this stream
    wrap.textContent = '';
    var cols = REC_COLS[gfilters.stream];
    var table = el('table', { class: 'rec-grid' });
    var thead = el('thead'); var htr = el('tr');
    cols.forEach(function (c) { htr.appendChild(el('th', { text: c.label })); });
    thead.appendChild(htr); table.appendChild(thead);
    body = el('tbody', { 'data-rec-body': '' });
    table.appendChild(body); wrap.appendChild(table);
    return body;
  }
  function recRow(r, cols) {
    var tr = el('tr', { class: 'rec-row rec-tone-' + (r.tone || '') });
    cols.forEach(function (c) {
      var v = r[c.key];
      var td = el('td', { class: 'rec-td rec-td-' + c.key });
      if (c.key === 'ts') td.textContent = (v || '').replace('T', '  ');
      else if (c.tone && v) {
        var dot = el('i', { class: 'rec-dot' }); dot.style.background = REC_TONE[v] || '#8da6c4';
        td.appendChild(dot); td.appendChild(el('span', { text: prettyLabel(v) }));
      } else td.textContent = (v == null || v === '') ? '·' : v;
      if (c.key === 'subject' && v === '(zero-knowledge)') td.classList.add('rec-td-zk');
      tr.appendChild(td);
    });
    return tr;
  }

  function loadRecords(reset) {
    if (!rec || recLoading) return;
    recLoading = true;
    var recErr = $('[data-rec-error]', rec); if (recErr) recErr.hidden = true;
    if (reset) {
      recCursor = null; recTotal = 0;
      $('[data-rec-grid]', rec).textContent = '';   // rebuild for the (possibly new) stream
    }
    var body = recEnsureTable();
    var cols = REC_COLS[gfilters.stream];
    var status = $('[data-rec-status]', rec); if (status) status.textContent = 'Loading…';
    var url = '/api/atlas/records?' + gfilterQuery() + '&limit=60' + (recCursor ? '&cursor=' + encodeURIComponent(recCursor) : '');
    apiCall(url).then(function (data) {
      recLoading = false;
      (data.records || []).forEach(function (r) { body.appendChild(recRow(r, cols)); });
      recTotal += (data.records || []).length;
      recCursor = data.next_cursor || null;
      var more = $('[data-rec-more]', rec); if (more) more.hidden = !recCursor;
      var cnt = $('[data-rec-count]', rec); if (cnt) cnt.textContent = recTotal + (recCursor ? '+ records' : ' records') + ' · newest first';
      if (status) status.textContent = recTotal === 0 ? 'No records match the current filter.' : (recCursor ? '' : 'End of records.');
    }).catch(function (e) {
      recLoading = false;
      if (recErr) { recErr.hidden = false; var d = $('[data-rec-error-detail]', rec); if (d) d.textContent = 'Records failed: ' + e.message; }
      if (status) status.textContent = '';
    });
  }
  if (rec) {
    var recMore = $('[data-rec-more]', rec);
    if (recMore) recMore.addEventListener('click', function () { loadRecords(false); });
    var recRetry = $('[data-rec-retry]', rec);
    if (recRetry) recRetry.addEventListener('click', function () { loadRecords(true); });
  }

  // =========================================================================
  // Global filter bar: stream + window + facets, applied to every view.
  // =========================================================================
  var gbar = $('[data-atlas-globalbar]');

  function setGfChips(attr, value) {
    if (!gbar) return;
    $$('[' + attr + ']', gbar).forEach(function (c) {
      var on = c.getAttribute(attr) === value;
      c.classList.toggle('toolbar-chip-active', on);
      c.setAttribute('aria-checked', on ? 'true' : 'false');
    });
  }

  // Reload whichever analytical view is visible (coordinated views).
  function applyFilters() {
    renderGfChips();
    if (overview && !overview.hidden) loadOverview();
    else if (bd && !bd.hidden) loadBreakdown();
    else if (rec && !rec.hidden) loadRecords(true);
  }

  // The context/outcome/disclosure facets apply to verifications only; on the
  // lifecycle stream only the agency facet is meaningful.
  function configureFacets() {
    var isVerif = gfilters.stream === 'verification';
    ['context', 'outcome', 'disclosure'].forEach(function (facet) {
      var det = $('.gf-facet[data-gf-facet="' + facet + '"]', gbar);
      if (det) { det.hidden = !isVerif; if (!isVerif) det.open = false; }
    });
    if (!isVerif) { gfilters.contexts = []; gfilters.outcomes = []; gfilters.disclosure = []; }
  }

  if (gbar) {
    $$('[data-gf-stream]', gbar).forEach(function (c) {
      c.addEventListener('click', function () {
        gfilters.stream = c.getAttribute('data-gf-stream');
        setGfChips('data-gf-stream', gfilters.stream);
        configureFacets();
        if (typeof bdBuildDimPicker === 'function') { bdClearSearch(); bdBuildDimPicker(); }
        applyFilters();
      });
    });
    $$('[data-gf-window]', gbar).forEach(function (c) {
      c.addEventListener('click', function () {
        gfilters.window = c.getAttribute('data-gf-window');
        setGfChips('data-gf-window', gfilters.window);
        applyFilters();
      });
    });

    // context / outcome / disclosure facets: values + counts via the breakdown.
    $$('.gf-facet[data-gf-facet]', gbar).forEach(function (det) {
      var facet = det.getAttribute('data-gf-facet');
      if (facet === 'agency') return;
      det.addEventListener('toggle', function () { if (det.open) loadFacetMenu(det, facet); });
    });

    // agency facet: a server typeahead with counts (survives thousands).
    var agencyDet = $('.gf-facet-agency', gbar);
    if (agencyDet) {
      var agInput = $('[data-gf-agency-search]', agencyDet);
      var agResults = $('[data-gf-agency-results]', agencyDet);
      var agTimer = null;
      agencyDet._load = function () {
        var qv = (agInput.value || '').trim();
        apiCall('/api/atlas/facet/agencies?' + facetContextQuery('agency')
                + (qv ? '&q=' + encodeURIComponent(qv) : '') + '&limit=20').then(function (data) {
          agResults.textContent = '';
          (data.results || []).forEach(function (a) {
            var on = gfilters.agencies.some(function (x) { return x.id === a.agency_id; });
            var row = facetOptRow(on, a.name, a.n_total, function () {
              toggleAgency(a.agency_id, a.name); agencyDet._load();
            });
            agResults.appendChild(row);
          });
          if (!(data.results || []).length) agResults.appendChild(el('div', { class: 'gf-facet-empty', text: 'No agencies.' }));
        }).catch(function () { agResults.textContent = 'Could not load agencies.'; });
      };
      agencyDet.addEventListener('toggle', function () { if (agencyDet.open) agencyDet._load(); });
      agInput.addEventListener('input', function () { clearTimeout(agTimer); agTimer = setTimeout(agencyDet._load, 220); });
    }

    var gfClear = $('[data-gf-clear]');
    if (gfClear) gfClear.addEventListener('click', function () {
      gfilters.contexts = []; gfilters.outcomes = []; gfilters.disclosure = []; gfilters.agencies = [];
      applyFilters();
    });
  }

  function facetOptRow(on, label, count, onClick) {
    var row = el('button', { class: 'gf-facet-opt' + (on ? ' gf-facet-opt-on' : ''), type: 'button' });
    row.appendChild(el('span', { class: 'gf-facet-check', text: on ? '☑' : '☐' }));
    row.appendChild(el('span', { class: 'gf-facet-optlabel', title: label, text: label }));
    row.appendChild(el('span', { class: 'gf-facet-optcount', text: fmtInt(count) }));
    row.addEventListener('click', onClick);
    return row;
  }
  function loadFacetMenu(det, facet) {
    var menu = $('[data-gf-facet-menu]', det);
    if (!menu) return;
    menu.textContent = 'Loading…';
    apiCall('/api/atlas/breakdown?' + facetContextQuery(facet) + '&dimension=' + facet + '&limit=40').then(function (data) {
      menu.textContent = '';
      var selected = gfilters[FACET_PARAM[facet]];
      (data.categories || []).forEach(function (c) {
        menu.appendChild(facetOptRow(selected.indexOf(c.label) >= 0, prettyLabel(c.label), c.n_total, function () {
          toggleFacetValue(facet, c.label); loadFacetMenu(det, facet);
        }));
      });
      if (!(data.categories || []).length) menu.appendChild(el('div', { class: 'gf-facet-empty', text: 'No values.' }));
    }).catch(function () { menu.textContent = 'Could not load.'; });
  }
  function toggleFacetValue(facet, value) {
    var arr = gfilters[FACET_PARAM[facet]];
    var i = arr.indexOf(value);
    if (i >= 0) arr.splice(i, 1); else arr.push(value);
    applyFilters();
  }
  function toggleAgency(id, name) {
    var i = -1;
    gfilters.agencies.forEach(function (a, idx) { if (a.id === id) i = idx; });
    if (i >= 0) gfilters.agencies.splice(i, 1); else gfilters.agencies.push({ id: id, name: name });
    applyFilters();
  }
  function updateFacetBadges() {
    if (!gbar) return;
    $$('.gf-facet[data-gf-facet]', gbar).forEach(function (det) {
      var facet = det.getAttribute('data-gf-facet');
      var n = facet === 'agency' ? gfilters.agencies.length : gfilters[FACET_PARAM[facet]].length;
      var badge = $('[data-gf-facet-count]', det);
      if (badge) { badge.textContent = n ? String(n) : ''; badge.hidden = !n; }
    });
  }
  function renderGfChips() {
    updateFacetBadges();
    var box = $('[data-gf-chips]');
    if (!box) return;
    box.textContent = '';
    var any = false;
    function chip(label, onRemove) {
      any = true;
      var c = el('span', { class: 'gf-chip' });
      c.appendChild(el('span', { class: 'gf-chip-label', title: label, text: label }));
      var x = el('button', { class: 'gf-chip-x', type: 'button', 'aria-label': 'Remove ' + label, text: '×' });
      x.addEventListener('click', onRemove);
      c.appendChild(x); box.appendChild(c);
    }
    ['context', 'outcome', 'disclosure'].forEach(function (facet) {
      gfilters[FACET_PARAM[facet]].slice().forEach(function (v) {
        chip(facet + ': ' + prettyLabel(v), function () { toggleFacetValue(facet, v); });
      });
    });
    gfilters.agencies.slice().forEach(function (a) {
      chip(a.name, function () { toggleAgency(a.id, a.name); });
    });
    var clear = $('[data-gf-clear]');
    if (clear) clear.hidden = !any;
  }

  // =========================================================================
  // TRENDS (ship 7): temporal-rhythm heatmap + composition-over-time stack.
  // Both are bounded server-side aggregates (atlas_heatmap / atlas_series_stacked),
  // hand-rolled SVG so script-src 'self' stays strict (C5), non-geographic so a
  // zero-knowledge verification is counted but never located (C6).
  // =========================================================================
  var trends = $('[data-atlas-view-panel="trends"]');
  var trendsDim = 'context';
  var trendsSeq = 0;
  var DOW = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  var STACK_COLORS = ['#5ac8fa', '#a78bfa', '#f5c451', '#ff6b6b', '#4ade80',
                      '#f472b6', '#38bdf8', '#fb923c'];
  var STACK_OTHER = '#64748b';

  function stackColor(label, i) { return label === 'Other' ? STACK_OTHER : STACK_COLORS[i % STACK_COLORS.length]; }

  function loadTrends() {
    if (!trends) return;
    var seq = ++trendsSeq;
    var q = gfilterQuery();
    var err = $('[data-trends-error]', trends);
    if (err) err.hidden = true;
    apiCall('/api/atlas/heatmap?' + q).then(function (data) {
      if (seq !== trendsSeq) return;
      renderHeatmap($('[data-trends-heatmap]', trends), data.cells || []);
    }).catch(function (e) { if (seq === trendsSeq) showTrendsError('Heatmap failed: ' + e.message); });
    apiCall('/api/atlas/stacked?' + q + '&dimension=' + trendsDim + '&buckets=48').then(function (data) {
      if (seq !== trendsSeq) return;
      renderStacked($('[data-trends-stacked]', trends), data);
      renderTrendsLegend($('[data-trends-legend]', trends), data.labels || []);
    }).catch(function (e) { if (seq === trendsSeq) showTrendsError('Composition failed: ' + e.message); });
  }

  function showTrendsError(msg) {
    var err = $('[data-trends-error]', trends);
    if (!err) return;
    var d = $('[data-trends-error-detail]', err);
    if (d) d.textContent = msg;
    err.hidden = false;
  }

  function renderHeatmap(mount, cells) {
    if (!mount) return;
    mount.textContent = '';
    if (!cells.length) { mount.appendChild(el('div', { class: 'ov-empty', text: 'No events in this window.' })); return; }
    var grid = {}, maxN = 1;
    cells.forEach(function (c) { grid[c.dow + ':' + c.hour] = c; if (c.n > maxN) maxN = c.n; });
    var padL = 34, padT = 16, cw = 30, ch = 20, W = padL + 24 * cw + 8, H = padT + 7 * ch + 8;
    var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'trends-hm-svg', preserveAspectRatio: 'xMinYMin meet', role: 'img' });
    for (var h = 0; h < 24; h += 3)
      s.appendChild(svg('text', { x: padL + h * cw + cw / 2, y: padT - 4, class: 'ov-axis', 'text-anchor': 'middle' })).textContent = h + 'h';
    for (var d = 1; d <= 7; d++) {
      s.appendChild(svg('text', { x: padL - 6, y: padT + (d - 1) * ch + ch / 2 + 3, class: 'ov-axis', 'text-anchor': 'end' })).textContent = DOW[d - 1];
      for (var hr = 0; hr < 24; hr++) {
        var cell = grid[d + ':' + hr], n = cell ? cell.n : 0;
        var r = svg('rect', {
          x: padL + hr * cw + 1, y: padT + (d - 1) * ch + 1, width: cw - 2, height: ch - 2, rx: 2,
          class: 'trends-hm-cell', fill: n ? '#79e6b3' : '#1b2733',
          'fill-opacity': n ? (0.12 + 0.88 * (n / maxN)).toFixed(3) : 1
        });
        var tt = svg('title'); tt.textContent = DOW[d - 1] + ' ' + (hr < 10 ? '0' + hr : hr) + ':00 — ' + fmtInt(n) + ' event' + (n === 1 ? '' : 's') + (cell && cell.n_failure ? ' (' + fmtInt(cell.n_failure) + ' failed)' : '');
        r.appendChild(tt); s.appendChild(r);
      }
    }
    mount.appendChild(s);
  }

  function renderStacked(mount, data) {
    if (!mount) return;
    mount.textContent = '';
    var labels = (data && data.labels) || [], points = (data && data.points) || [];
    if (!labels.length || !points.length) { mount.appendChild(el('div', { class: 'ov-empty', text: 'No events in this window.' })); return; }
    var W = 820, H = 240, padL = 8, padR = 8, padT = 12, padB = 22, iW = W - padL - padR, iH = H - padT - padB;
    var totals = points.map(function (p) { var t = 0; labels.forEach(function (l) { t += (p.values[l] || 0); }); return t; });
    var maxT = Math.max(1, Math.max.apply(null, totals));
    var n = points.length;
    function X(i) { return padL + (n === 1 ? iW / 2 : (i / (n - 1)) * iW); }
    function Y(v) { return padT + iH - (v / maxT) * iH; }
    // Named from the data, for the same reason as the hero chart above. (P6.5)
    var s = svg('svg', { viewBox: '0 0 ' + W + ' ' + H, class: 'ov-hero-svg',
      preserveAspectRatio: 'none', role: 'img',
      'aria-label': 'Events over time by type: ' + labels.length + ' series ('
        + labels.join(', ') + ') across ' + n + ' interval' + (n === 1 ? '' : 's')
        + ', peak ' + fmtInt(maxT) + ' per interval' });
    [0, 0.5, 1].forEach(function (f) {
      var y = padT + iH - f * iH;
      s.appendChild(svg('line', { x1: padL, y1: y, x2: W - padR, y2: y, class: 'ov-gridline' }));
      s.appendChild(svg('text', { x: padL + 2, y: y - 3, class: 'ov-axis' })).textContent = f === 0 ? '' : fmtInt(Math.round(maxT * f));
    });
    // cumulative baselines, bottom band first, so each area sits on the last
    var below = points.map(function () { return 0; });
    labels.forEach(function (label, li) {
      var top = points.map(function (p, i) { return below[i] + (p.values[label] || 0); });
      var d = 'M ' + X(0) + ' ' + Y(top[0]);
      for (var i = 1; i < n; i++) d += ' L ' + X(i) + ' ' + Y(top[i]);
      for (var j = n - 1; j >= 0; j--) d += ' L ' + X(j) + ' ' + Y(below[j]);
      d += ' Z';
      s.appendChild(svg('path', { d: d, class: 'trends-band', fill: stackColor(label, li), 'fill-opacity': '0.82' }));
      below = top;
    });
    mount.appendChild(s);
    var range = el('div', { class: 'ov-hero-range' });
    range.appendChild(el('span', { text: shortTs(points[0].ts) }));
    range.appendChild(el('span', { text: shortTs(points[n - 1].ts) }));
    mount.appendChild(range);
  }

  function renderTrendsLegend(mount, labels) {
    if (!mount) return;
    mount.textContent = '';
    labels.forEach(function (label, i) {
      var item = el('span', { class: 'trends-legend-item' });
      // A tiny SVG swatch keeps the colour out of an inline style (strict CSP).
      var box = svg('svg', { width: 10, height: 10, viewBox: '0 0 10 10', class: 'trends-legend-swatch' });
      box.appendChild(svg('rect', { x: 0, y: 0, width: 10, height: 10, rx: 2, fill: stackColor(label, i) }));
      item.appendChild(box);
      item.appendChild(el('span', { class: 'trends-legend-label', text: prettyLabel(label) }));
      mount.appendChild(item);
    });
  }

  $$('[data-trends-dim]', trends || document).forEach(function (b) {
    b.addEventListener('click', function () {
      trendsDim = b.getAttribute('data-trends-dim');
      $$('[data-trends-dim]', trends).forEach(function (o) {
        var on = o === b;
        o.classList.toggle('toolbar-chip-active', on);
        o.setAttribute('aria-checked', on ? 'true' : 'false');
      });
      loadTrends();
    });
  });
  var tRetry = $('[data-trends-retry]', trends || document);
  if (tRetry) tRetry.addEventListener('click', loadTrends);

  // initial paint
  configureFacets();
  renderGfChips();
  loadOverview();

  // LIVE refresh (shared cadence with the map). Skip when the tab is hidden.
  setInterval(function () {
    if (document.hidden) return;
    if (!overview.hidden) loadOverview();
    else if (bd && !bd.hidden) loadBreakdown();
    else if (trends && !trends.hidden) loadTrends();
  }, 60000);

  // =========================================================================
  // Live simulation mode (P2.14 S4). Present only when the server rendered the
  // control (SIM_MODE, dev/demo only). The browser drives the stream: each tick
  // POSTs a bounded batch of notional activity to /api/sim/tick (which writes
  // through the real verification path) and then refreshes the active view, so
  // the operator watches the nation's activity accumulate. Client-driven by
  // design — no server-side background thread, which is what the multi-worker
  // gunicorn model needs.
  // =========================================================================
  (function initSim() {
    var host = $('[data-atlas-sim]');
    if (!host) return;                       // SIM_MODE off: no control rendered
    var btn = $('[data-atlas-sim-toggle]', host);
    var label = $('[data-atlas-sim-label]', host);
    var countEl = $('[data-atlas-sim-count]', host);
    var csrf = host.getAttribute('data-sim-csrf') || '';
    var timer = null, streamed = 0, inflight = false;

    function refreshActive() {
      if (!overview.hidden) loadOverview();
      else if (bd && !bd.hidden) loadBreakdown();
      else if (trends && !trends.hidden) loadTrends();
      else if (rec && !rec.hidden) loadRecords(true);
      // Nudge the map to repaint if it is the active view and booted.
      window.dispatchEvent(new CustomEvent('polaris:atlas-refresh'));
    }

    function setRunning(on) {
      host.classList.toggle('atlas-sim-on', on);
      btn.setAttribute('aria-pressed', on ? 'true' : 'false');
      if (label) label.textContent = on ? 'Simulating' : 'Simulate';
    }

    function tick() {
      if (inflight || document.hidden) return;   // pause when backgrounded
      inflight = true;
      var body = 'count=40&lifecycle=1&csrf_token=' + encodeURIComponent(csrf);
      fetch('/api/sim/tick', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: body
      }).then(function (r) {
        return r.json().then(function (j) { return { ok: r.ok, status: r.status, body: j }; });
      }).then(function (res) {
        inflight = false;
        if (!res.ok) {
          // 409 = no substrate yet; stop and tell the operator what to run.
          stop();
          if (countEl) {
            countEl.hidden = false;
            countEl.textContent = res.body && res.body.hint ? res.body.hint : ('sim error ' + res.status);
          }
          return;
        }
        streamed += (res.body.streamed || 0);
        if (countEl) {
          countEl.hidden = false;
          countEl.textContent = fmtInt(streamed) + ' streamed · ' + fmtInt(res.body.total_events || 0) + ' total';
        }
        refreshActive();
      }).catch(function () { inflight = false; });
    }

    function start() {
      if (timer) return;
      setRunning(true);
      tick();                                 // immediate first batch
      timer = setInterval(tick, 2500);
    }
    function stop() {
      if (timer) { clearInterval(timer); timer = null; }
      setRunning(false);
    }

    btn.addEventListener('click', function () { timer ? stop() : start(); });
  })();
})();

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* ========================================================================
 * athena-console.js — the Athena authority-and-constitution console (v9.266).
 *
 * Read-only operator surface for polaris_sql/16_athena.sql. The Constitution
 * and Trust tabs are server-rendered; this script owns tab switching and the
 * three interactive drill-downs that call the Athena functions:
 *   - Authority chain      GET /api/athena/authority-chain?agency&algorithm
 *   - Deprecation blast     GET /api/athena/affected-by-algorithm?algorithm
 *   - Proof / disclosure    GET /api/athena/explain-proof?context
 *
 * Every result is built programmatically (createElement / textContent) — never
 * innerHTML with markup — so `script-src 'self'` (C5) stays strict. No person
 * data is ever fetched or shown: the endpoints read only the person-free Athena
 * layer.
 * ==================================================================== */
(function () {
  'use strict';

  var shell = document.querySelector('.athena-shell');
  if (!shell) return;

  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }

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

  function apiCall(url) {
    return fetch(url, { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
      .then(function (r) {
        return r.json().then(function (body) {
          if (!r.ok) throw new Error(body && body.error ? body.error : 'HTTP ' + r.status);
          return body;
        });
      });
  }

  function setBusy(mount, msg) {
    mount.textContent = '';
    mount.appendChild(el('p', { class: 'athena-busy', text: msg || 'Loading…' }));
  }
  function setError(mount, err) {
    mount.textContent = '';
    mount.appendChild(el('p', { class: 'athena-error', text: 'Could not resolve: ' + err.message }));
  }

  // ---- tab switching -------------------------------------------------------
  function showTab(name) {
    $$('[data-athena-tab]').forEach(function (t) {
      var on = t.getAttribute('data-athena-tab') === name;
      t.classList.toggle('athena-tab-active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    $$('[data-athena-panel]').forEach(function (p) {
      p.hidden = p.getAttribute('data-athena-panel') !== name;
    });
  }
  $$('[data-athena-tab]').forEach(function (t) {
    t.addEventListener('click', function () { showTab(t.getAttribute('data-athena-tab')); });
  });

  // ---- authority chain -----------------------------------------------------
  function renderChain(mount, data) {
    mount.textContent = '';
    var authed = !!data.authorized;
    mount.appendChild(el('div', { class: 'athena-verdict ' + (authed ? 'athena-verdict-yes' : 'athena-verdict-no') }, [
      el('span', { class: 'athena-verdict-dot' }),
      el('span', { text: authed ? 'Authorized to issue' : 'Not authorized to issue' })
    ]));
    var ol = el('ol', { class: 'athena-chain' });
    (data.steps || []).forEach(function (s) {
      ol.appendChild(el('li', { class: 'athena-chain-step' }, [
        el('span', { class: 'athena-chain-rel', text: s.relation }),
        el('span', { class: 'athena-chain-detail', text: s.detail }),
        el('span', { class: 'athena-chain-src', text: s.source })
      ]));
    });
    mount.appendChild(ol);
    if (!(data.steps || []).length) {
      mount.appendChild(el('p', { class: 'athena-empty', text: 'No chain resolved (unknown agency or algorithm).' }));
    }
  }

  function runChain() {
    var mount = $('[data-athena-chain]');
    var agency = $('[data-athena-agency]').value;
    var algorithm = $('[data-athena-algorithm]').value;
    setBusy(mount);
    apiCall('/api/athena/authority-chain?agency=' + encodeURIComponent(agency) +
            '&algorithm=' + encodeURIComponent(algorithm))
      .then(function (d) { renderChain(mount, d); })
      .catch(function (e) { setError(mount, e); });
  }

  // ---- deprecation blast radius -------------------------------------------
  var BLAST_GROUPS = [
    { key: 'authorized_agency', label: 'Agencies authorized on it' },
    { key: 'served_context', label: 'Contexts it currently serves' },
    { key: 'successor_algorithm', label: 'Post-quantum successors' }
  ];

  function renderBlast(mount, data) {
    mount.textContent = '';
    var impacts = data.impacts || {};
    var any = false;
    BLAST_GROUPS.forEach(function (g) {
      var rows = impacts[g.key] || [];
      if (!rows.length) return;
      any = true;
      var group = el('div', { class: 'athena-blast-group' }, [
        el('h4', { class: 'athena-blast-title' }, [
          el('span', { text: g.label }),
          el('span', { class: 'athena-count', text: String(rows.length) })
        ])
      ]);
      var ul = el('ul', { class: 'athena-blast-list' });
      rows.forEach(function (r) {
        ul.appendChild(el('li', {}, [
          el('span', { class: 'athena-blast-ref', text: r.ref_label }),
          el('span', { class: 'athena-blast-detail', text: r.detail })
        ]));
      });
      group.appendChild(ul);
      mount.appendChild(group);
    });
    if (!any) mount.appendChild(el('p', { class: 'athena-empty', text: 'Nothing depends on this algorithm.' }));
  }

  function runBlast() {
    var mount = $('[data-athena-blast]');
    var algorithm = $('[data-athena-blast-algorithm]').value;
    setBusy(mount);
    apiCall('/api/athena/affected-by-algorithm?algorithm=' + encodeURIComponent(algorithm))
      .then(function (d) { renderBlast(mount, d); })
      .catch(function (e) { setError(mount, e); });
  }

  // ---- proof / disclosure policy ------------------------------------------
  function renderProof(mount, data) {
    mount.textContent = '';
    if (!data.found) {
      mount.appendChild(el('p', { class: 'athena-empty', text: 'No such context.' }));
      return;
    }
    mount.appendChild(el('div', { class: 'athena-proof-req' }, [
      el('span', { class: 'athena-chip', text: data.context_type }),
      el('span', { class: 'athena-chip', text: 'min security level ' + data.min_security_level }),
      el('span', { class: 'athena-chip', text: data.requires_biometric ? 'biometric required' : 'no biometric' })
    ]));
    var list = el('div', { class: 'athena-disclosures' });
    (data.disclosures || []).forEach(function (d) {
      list.appendChild(el('div', { class: 'athena-disclosure athena-disclosure-' + d.level.toLowerCase() }, [
        el('span', { class: 'athena-disclosure-level', text: d.level.replace(/_/g, ' ') }),
        el('span', { class: 'athena-disclosure-note', text: d.note })
      ]));
    });
    mount.appendChild(list);
  }

  function runProof() {
    var mount = $('[data-athena-proof]');
    var context = $('[data-athena-context]').value;
    setBusy(mount);
    apiCall('/api/athena/explain-proof?context=' + encodeURIComponent(context))
      .then(function (d) { renderProof(mount, d); })
      .catch(function (e) { setError(mount, e); });
  }

  // ---- wire the controls ---------------------------------------------------
  var chainBtn = $('[data-athena-chain-run]');
  if (chainBtn) chainBtn.addEventListener('click', runChain);
  var blastBtn = $('[data-athena-blast-run]');
  if (blastBtn) blastBtn.addEventListener('click', runBlast);
  var proofBtn = $('[data-athena-proof-run]');
  if (proofBtn) proofBtn.addEventListener('click', runProof);
})();

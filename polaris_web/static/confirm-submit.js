// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* polaris_web/static/confirm-submit.js
 *
 * Generic form-behavior helpers loaded on every page via base.html.
 * Two opt-in patterns, both attribute-driven so templates declare
 * behavior without inline JS:
 *
 *   1. `<form data-confirm="…">`, submit shows window.confirm() and
 *      cancels if the user declines. Replaces inline
 *      `onsubmit="return confirm('…')"` in:
 *      - templates/agencies_list.html (delete agency)
 *      - templates/individuals_list.html (delete individual)
 *      - templates/tokens_detail.html (delete token)
 *
 *   2. `<input|select … data-submit-on-change>`, change event
 *      auto-submits the parent form. Replaces inline
 *      `onchange="this.form.submit()"` in:
 *      - templates/individuals_enrollment.html (jurisdiction filter)
 *
 * v8.46: externalized for CSP `script-src 'self'` compliance. The
 * message is read from the form's `data-confirm` attribute; Jinja
 * autoescaping handles HTML safety in the rendered attribute value.
 *
 * No external dependencies.
 */
(function () {
    // Pattern 1: data-confirm on forms
    var confirmForms = document.querySelectorAll('form[data-confirm]');
    confirmForms.forEach(function (form) {
        form.addEventListener('submit', function (event) {
            var message = form.dataset.confirm || 'Are you sure?';
            if (!window.confirm(message)) {
                event.preventDefault();
            }
        });
    });

    // Pattern 2: data-submit-on-change on form controls
    var autoSubmits = document.querySelectorAll('[data-submit-on-change]');
    autoSubmits.forEach(function (el) {
        el.addEventListener('change', function () {
            if (el.form) {
                el.form.submit();
            }
        });
    });
})();

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* polaris_web/static/verifications-form.js
 *
 * Disclosure-level constraint hint for /verifications/new.
 *
 * Polaris C2 invariant: ZERO_KNOWLEDGE verifications MUST have
 * token_id IS NULL. C6 enforces this server-side; this script
 * provides client-side guidance, disabling the token-id select
 * and updating the hint text, so operators see the constraint
 * before submitting rather than after a server-side 400.
 *
 * v8.46: externalized from verifications_form.html inline <script>
 * and inline `onchange=` attribute. The onchange listener is now
 * attached via addEventListener, since `onchange=` is also blocked
 * under `script-src 'self'`.
 *
 * No external dependencies.
 */
(function () {
    var disclosureSel = document.getElementById('disclosure_level');
    var tokenSel = document.getElementById('token_id');
    var hint = document.getElementById('token-hint');

    if (!disclosureSel || !tokenSel || !hint) {
        return; // page does not have the form; nothing to do
    }

    function updateTokenField() {
        var disc = disclosureSel.value;
        if (disc === 'ZERO_KNOWLEDGE') {
            tokenSel.value = '';
            tokenSel.disabled = true;
            hint.textContent = 'ZERO_KNOWLEDGE: token_id MUST be NULL. '
                + 'Field disabled.';
        } else if (disc === 'FULL') {
            tokenSel.disabled = false;
            hint.textContent = 'FULL: token_id required. '
                + 'Selecting "(none)" will be rejected by the constraint.';
        } else {
            tokenSel.disabled = false;
            hint.textContent = 'SELECTIVE: token_id is optional.';
        }
    }

    disclosureSel.addEventListener('change', updateTokenField);
    updateTokenField();
})();

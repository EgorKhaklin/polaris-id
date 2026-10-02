// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* polaris_web/static/verifications-form.js
 *
 * The disclosure hint for /verifications/new.
 *
 * Polaris C2: a ZERO_KNOWLEDGE verification stores no credential. The server enforces it (the
 * form handler drops the credential for zero-knowledge, and chk_disclosure_token_consistency
 * refuses anything else); this script shows the operator the rule before they submit. When a
 * credential was found (lookup.py), its number rides in a hidden field, which zero-knowledge
 * disables so that it is not sent at all.
 *
 * CSP C5: loaded with defer from the template, no inline script. No dependencies.
 */
(function () {
    var disclosure = document.getElementById('disclosure_level');
    var token = document.getElementById('token_id');     // absent when no credential was found
    var hint = document.getElementById('token-hint');

    if (!disclosure || !hint) {
        return; // page does not have the form; nothing to do
    }

    function update() {
        var level = disclosure.value;
        if (token) {
            token.disabled = (level === 'ZERO_KNOWLEDGE');
        }
        if (level === 'ZERO_KNOWLEDGE') {
            hint.textContent = token
                ? 'Zero-knowledge: the credential above is not recorded with this event.'
                : 'Zero-knowledge: no credential is recorded with this event.';
        } else if (level === 'FULL') {
            hint.textContent = token
                ? 'Full disclosure: the event names the credential above.'
                : 'A full disclosure names its credential: find it above first.';
        } else {
            hint.textContent = token
                ? 'Selective disclosure: the event names the credential above.'
                : 'A selective disclosure that names no credential is recorded only as refused.';
        }
    }

    disclosure.addEventListener('change', update);
    update();
})();

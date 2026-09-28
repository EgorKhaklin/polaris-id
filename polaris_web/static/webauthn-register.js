// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* v8.97: WebAuthn enrollment (settings page).
   Position B of a recorded decision.

   Required DOM:
       button#waEnrollBtn (data-csrf-token attribute)
       input#waLabel       (device label, optional)
       div#waStatus
       div#waError
   Triggers navigator.credentials.create() against the options served by
   /auth/webauthn/register/begin, then POSTs the result to
   /auth/webauthn/register/finish. On success, reloads the page so the
   new credential appears in the enrolled-list table.
*/

(function () {
    'use strict';

    var btn    = document.getElementById('waEnrollBtn');
    var label  = document.getElementById('waLabel');
    var status = document.getElementById('waStatus');
    var errBox = document.getElementById('waError');
    if (!btn || !status || !errBox) return;

    var csrf = btn.getAttribute('data-csrf-token') || '';

    /* ---------- base64url helpers ---------- */
    function b64urlToBytes(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) { s += '='; }
        var bin = atob(s);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
        return out;
    }
    function bytesToB64url(buf) {
        var bytes = new Uint8Array(buf);
        var bin = '';
        for (var i = 0; i < bytes.length; i++) { bin += String.fromCharCode(bytes[i]); }
        var s = btoa(bin);
        return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function setStatus(msg) { status.textContent = msg; }
    function setError(msg)  { errBox.textContent = msg; errBox.classList.add('webauthn-error-visible'); }
    function clearError()   { errBox.textContent = ''; errBox.classList.remove('webauthn-error-visible'); }

    function beginCeremony() {
        clearError();
        if (!window.PublicKeyCredential) {
            setError('WebAuthn is not supported in this browser.');
            return;
        }
        btn.disabled = true;
        setStatus('Requesting registration challenge from server…');

        var deviceLabel = (label && label.value) ? label.value.trim() : '';

        fetch('/auth/webauthn/register/begin', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-CSRFToken': csrf
            }
        }).then(function (r) {
            if (!r.ok) { throw new Error('server refused challenge (HTTP ' + r.status + ')'); }
            return r.json();
        }).then(function (options) {
            setStatus('Touch your security key, or follow your platform authenticator prompt…');
            return runCreate(options);
        }).then(function (attestation) {
            setStatus('Verifying attestation…');
            attestation.device_label = deviceLabel;
            return fetch('/auth/webauthn/register/finish', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'X-CSRFToken': csrf
                },
                body: JSON.stringify(attestation)
            });
        }).then(function (r) {
            return r.json().then(function (body) { return { ok: r.ok, body: body }; });
        }).then(function (res) {
            if (!res.ok || !res.body || res.body.error) {
                setError('Enrollment failed: ' + (res.body && res.body.error ? res.body.error : 'unknown error'));
                btn.disabled = false;
                setStatus('Press the button to retry.');
                return;
            }
            setStatus('Credential enrolled. Reloading…');
            window.location.reload();
        }).catch(function (e) {
            setError(String(e && e.message ? e.message : e));
            btn.disabled = false;
            setStatus('Press the button to retry.');
        });
    }

    function runCreate(options) {
        var pub = options.publicKey || options;
        var prepared = {
            challenge: b64urlToBytes(pub.challenge),
            rp: pub.rp,
            user: {
                id: b64urlToBytes(pub.user.id),
                name: pub.user.name,
                displayName: pub.user.displayName
            },
            pubKeyCredParams: pub.pubKeyCredParams,
            timeout: pub.timeout,
            attestation: pub.attestation,
            authenticatorSelection: pub.authenticatorSelection,
            excludeCredentials: (pub.excludeCredentials || []).map(function (c) {
                return {
                    id: b64urlToBytes(c.id),
                    type: c.type,
                    transports: c.transports
                };
            }),
            extensions: pub.extensions
        };

        return navigator.credentials.create({ publicKey: prepared })
            .then(function (cred) {
                if (!cred) { throw new Error('no credential returned'); }
                var r = cred.response;
                return {
                    id: cred.id,
                    rawId: bytesToB64url(cred.rawId),
                    type: cred.type,
                    response: {
                        attestationObject: bytesToB64url(r.attestationObject),
                        clientDataJSON:    bytesToB64url(r.clientDataJSON),
                        transports: r.getTransports ? r.getTransports() : undefined
                    },
                    clientExtensionResults: cred.getClientExtensionResults
                        ? cred.getClientExtensionResults() : {}
                };
            });
    }

    btn.addEventListener('click', beginCeremony);
})();

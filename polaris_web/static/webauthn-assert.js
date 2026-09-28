// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* v8.97: WebAuthn assertion (login second factor).
   Position B of a recorded decision.

   Required DOM:
       button#waVerifyBtn
       div#waStatus
       div#waError
   Triggers navigator.credentials.get() against the challenge served by
   /auth/webauthn/assert/begin, then POSTs the result to
   /auth/webauthn/assert/finish. On success the server returns
   {ok: true, redirect: "/path"} and we navigate.
*/

(function () {
    'use strict';

    var btn    = document.getElementById('waVerifyBtn');
    var status = document.getElementById('waStatus');
    var errBox = document.getElementById('waError');
    if (!btn || !status || !errBox) return;

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
        setStatus('Requesting challenge from server…');

        fetch('/auth/webauthn/assert/begin', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Accept': 'application/json' }
        }).then(function (r) {
            if (!r.ok) { throw new Error('server refused challenge (HTTP ' + r.status + ')'); }
            return r.json();
        }).then(function (options) {
            setStatus('Touch your security key or use your platform authenticator…');
            return runGet(options);
        }).then(function (assertion) {
            setStatus('Verifying assertion…');
            return fetch('/auth/webauthn/assert/finish', {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify(assertion)
            });
        }).then(function (r) {
            return r.json().then(function (body) { return { ok: r.ok, body: body }; });
        }).then(function (res) {
            if (!res.ok || !res.body || res.body.error) {
                setError('Verification failed: ' + (res.body && res.body.error ? res.body.error : 'unknown error'));
                btn.disabled = false;
                setStatus('Press the button to retry.');
                return;
            }
            setStatus('Verified. Redirecting…');
            window.location.assign(res.body.redirect || '/dashboard');
        }).catch(function (e) {
            setError(String(e && e.message ? e.message : e));
            btn.disabled = false;
            setStatus('Press the button to retry.');
        });
    }

    function runGet(options) {
        var pub = options.publicKey || options;
        var challenge = pub.challenge;
        var allow = pub.allowCredentials || [];
        var prepared = {
            challenge: b64urlToBytes(challenge),
            timeout: pub.timeout,
            rpId: pub.rpId,
            userVerification: pub.userVerification,
            allowCredentials: allow.map(function (c) {
                return {
                    id: b64urlToBytes(c.id),
                    type: c.type,
                    transports: c.transports
                };
            })
        };

        return navigator.credentials.get({ publicKey: prepared })
            .then(function (cred) {
                if (!cred) { throw new Error('no credential returned'); }
                var r = cred.response;
                return {
                    id: cred.id,
                    rawId: bytesToB64url(cred.rawId),
                    type: cred.type,
                    response: {
                        authenticatorData: bytesToB64url(r.authenticatorData),
                        clientDataJSON:    bytesToB64url(r.clientDataJSON),
                        signature:         bytesToB64url(r.signature),
                        userHandle: r.userHandle ? bytesToB64url(r.userHandle) : null
                    },
                    clientExtensionResults: cred.getClientExtensionResults
                        ? cred.getClientExtensionResults() : {}
                };
            });
    }

    btn.addEventListener('click', beginCeremony);
})();

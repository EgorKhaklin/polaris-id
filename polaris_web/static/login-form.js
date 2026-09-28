// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* Client-side login validation, in place of the browser's own popup.
   Required markup: <form class="login-form" novalidate> with #username and
   #password inputs and a <div id="loginError" class="login-error">. The server
   validates the same fields again; this only saves a round trip. */

(function () {
    'use strict';

    var form = document.querySelector('.login-form');
    if (!form) return;
    var err = document.getElementById('loginError');
    var u   = document.getElementById('username');
    var p   = document.getElementById('password');
    if (!err || !u || !p) return;

    function setError(msg, focusEl) {
        err.textContent = msg;
        err.classList.add('login-error-visible');
        if (focusEl) {
            focusEl.classList.add('input-invalid');
            try { focusEl.focus(); } catch (e) { /* ignore */ }
        }
    }

    function clearError() {
        err.textContent = '';
        err.classList.remove('login-error-visible');
        u.classList.remove('input-invalid');
        p.classList.remove('input-invalid');
    }

    u.addEventListener('input', clearError);
    p.addEventListener('input', clearError);

    form.addEventListener('submit', function (e) {
        clearError();
        var uv = u.value.trim();
        var pv = p.value;
        if (!uv) {
            e.preventDefault();
            setError('Enter your username.', u);
            return;
        }
        if (!/^[a-z0-9._-]{3,50}$/.test(uv)) {
            e.preventDefault();
            setError('A username is 3 to 50 characters: lower-case letters, digits, dot, underscore or hyphen.', u);
            return;
        }
        if (!pv) {
            e.preventDefault();
            setError('Enter your password.', p);
            return;
        }
    });
})();

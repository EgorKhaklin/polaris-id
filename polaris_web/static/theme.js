// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* theme.js: apply the viewer's stored console theme before the first paint.
   Loaded from <head> as an external file (CSP C5 forbids inline script). 'light' and 'dark' set
   data-theme on <html>; 'system', or nothing stored, leaves it unset so prefers-color-scheme
   decides. shell.js owns the control that changes it. */
(function () {
    'use strict';
    try {
        var t = window.localStorage.getItem('polaris-theme');
        if (t === 'light' || t === 'dark') {
            document.documentElement.setAttribute('data-theme', t);
        }
    } catch (e) {
        /* storage unavailable: follow the system preference */
    }
})();

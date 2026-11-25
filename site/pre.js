// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* Runs before first paint: marks the page as scripted, and skips the loading screen after its first showing in a
   session or when the visitor asks for reduced motion. */
(function (d) {
    var c = d.documentElement.classList;
    c.add('js');
    try {
        if (sessionStorage.getItem('plr-pre') || matchMedia('(prefers-reduced-motion: reduce)').matches) {
            c.add('pre-skip');
        } else {
            c.add('lock');
        }
    } catch (e) {
        c.add('pre-skip');
    }
})(document);

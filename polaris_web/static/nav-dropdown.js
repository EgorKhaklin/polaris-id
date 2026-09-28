// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* polaris_web/static/nav-dropdown.js
 *
 * v8.35: coordinate the masthead nav <details> dropdowns so opening one
 * (SUBSTRATE or USE CASES) closes the others. Without this, both panels
 * can be open simultaneously and their absolute-positioned content
 * overlaps visually.
 *
 * Loaded externally (not inline) per CSP `script-src 'self'` policy.
 * No external dependencies.
 */
(function () {
    var menus = document.querySelectorAll('.primary-nav .nav-uc-menu');
    if (menus.length < 2) {
        return; // only one (or zero) dropdowns, nothing to coordinate
    }
    menus.forEach(function (menu) {
        menu.addEventListener('toggle', function () {
            if (!menu.open) {
                return; // only react to opens; ignore close events
            }
            menus.forEach(function (other) {
                if (other !== menu && other.open) {
                    other.open = false;
                }
            });
        });
    });

    /* Click-outside-to-close: if the user clicks anywhere that is NOT
     * inside an open nav-uc-menu, close all of them. Keeps the dropdown
     * UX consistent with conventional menu behavior. */
    document.addEventListener('click', function (event) {
        var clickedInside = event.target.closest('.nav-uc-menu');
        if (clickedInside) {
            return;
        }
        menus.forEach(function (menu) {
            if (menu.open) {
                menu.open = false;
            }
        });
    });
})();

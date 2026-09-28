// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* Flash handling.
 *
 * A success flash reports something that already happened, so it fades on its
 * own after a few seconds. An error or a warning is often the only report the
 * operator gets of a failed write or a deadline: it stays until dismissed.
 *
 * Scoped to .flash-region: several templates reuse the .flash classes for
 * permanent prerequisite notices that must not vanish under the operator.
 */

(function () {
    'use strict';

    var DISMISS_MS = 4500;
    var FADE_MS    = 600;

    function collapse(el) {
        el.style.transition =
            'opacity ' + FADE_MS + 'ms ease, ' +
            'max-height ' + FADE_MS + 'ms ease, ' +
            'margin ' + FADE_MS + 'ms ease, ' +
            'padding ' + FADE_MS + 'ms ease, ' +
            'border-width ' + FADE_MS + 'ms ease';
        el.style.maxHeight = el.offsetHeight + 'px';
        el.style.opacity = '0';
        requestAnimationFrame(function () {
            el.style.maxHeight = '0px';
            el.style.paddingTop = '0';
            el.style.paddingBottom = '0';
            el.style.marginTop = '0';
            el.style.marginBottom = '0';
            el.style.borderWidth = '0';
        });
        setTimeout(function () { el.remove(); }, FADE_MS + 50);
    }

    var flashes = document.querySelectorAll('.flash-region .flash');
    flashes.forEach(function (el) {
        var button = el.querySelector('.flash-dismiss');
        if (button) {
            button.addEventListener('click', function () { collapse(el); });
            return;
        }
        if (el.classList.contains('flash-success')) {
            setTimeout(function () { collapse(el); }, DISMISS_MS);
        }
    });
})();

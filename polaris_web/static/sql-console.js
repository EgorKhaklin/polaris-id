// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* polaris_web/static/sql-console.js
 *
 * Example-query click-to-paste for /sql.
 *
 * When the user clicks an example <pre> element, copy its textContent
 * into the #sql textarea so they can immediately edit + run it.
 *
 * v8.46: externalized from sql_console.html inline `onclick=`
 * attribute. The handler is now attached via addEventListener,
 * since inline `onclick=` is blocked under `script-src 'self'`.
 *
 * No external dependencies.
 */
(function () {
    var target = document.getElementById('sql');
    if (!target) {
        return; // page does not have the SQL console
    }
    var examples = document.querySelectorAll('.example-list .example-item pre');
    examples.forEach(function (pre) {
        pre.addEventListener('click', function () {
            target.value = pre.textContent;
            target.focus();
        });
    });
})();

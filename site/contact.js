// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// site/contact.js: the contact page's form. It sends nothing: it writes what the reader typed into a mailto link,
// so the button opens a draft in the reader's own mail app. Without this script the page still shows the
// addresses and the button opens an empty draft.
(function () {
    'use strict';
    var TO = 'egor@polaris-id.org';
    var box = document.getElementById('compose');
    var send = document.getElementById('send');
    var name = document.getElementById('f-name');
    var org = document.getElementById('f-org');
    var msg = document.getElementById('f-msg');
    var count = document.getElementById('f-count');
    var note = document.getElementById('note');
    var copy = document.getElementById('copy');
    if (!box || !send || !name || !org || !msg || !count) { return; }

    function draft() {
        var n = name.value.trim();
        var o = org.value.trim();
        var m = msg.value.trim();
        var who = [n, o].filter(Boolean).join(', ');
        var body = [m, who].filter(Boolean).join('\n\n');
        var href = 'mailto:' + TO + '?subject=' + encodeURIComponent('Polaris ID' + (o ? ': ' + o : ''));
        if (body) { href += '&body=' + encodeURIComponent(body.replace(/\r?\n/g, '\r\n')); }
        send.setAttribute('href', href);
        count.textContent = String(msg.value.length);
    }
    [name, org, msg].forEach(function (el) { el.addEventListener('input', draft); });
    box.hidden = false;
    if (note) { note.hidden = false; }
    draft();

    if (copy && navigator.clipboard && navigator.clipboard.writeText) {
        copy.hidden = false;
        copy.addEventListener('click', function () {
            navigator.clipboard.writeText(TO).then(function () {
                copy.textContent = 'Copied';
                setTimeout(function () { copy.textContent = 'Copy'; }, 1600);
            }, function () { /* the address stays on the page to select by hand */ });
        });
    }
})();

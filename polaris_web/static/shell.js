// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* shell.js: the console shell's behaviour (docs/design/console-design.md).

   - The theme control cycles system -> light -> dark and stores the choice per browser.
   - On narrow screens the sidebar is a drawer: the menu button opens it, Escape or a click
     outside closes it, and focus returns to the button.
   - The account menu (a <details>) closes on Escape and on a click outside it.
   - A table wider than its container scrolls inside it; while it does, the container takes a
     tab stop and a name, so a keyboard can reach the scroll (WCAG 2.1.1).

   External file, loaded with defer (CSP C5: no inline script). Required markup: base.html. */
(function () {
    'use strict';

    var root = document.documentElement;
    var ORDER = ['system', 'light', 'dark'];
    var LABEL = { system: 'Theme: system', light: 'Theme: light', dark: 'Theme: dark' };

    function storedTheme() {
        try {
            var t = window.localStorage.getItem('polaris-theme');
            return ORDER.indexOf(t) >= 0 ? t : 'system';
        } catch (e) {
            return 'system';
        }
    }

    function applyTheme(t) {
        if (t === 'light' || t === 'dark') {
            root.setAttribute('data-theme', t);
        } else {
            root.removeAttribute('data-theme');
        }
        try { window.localStorage.setItem('polaris-theme', t); } catch (e) { /* not stored */ }
        document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
            btn.setAttribute('aria-label', LABEL[t] + '. Change theme');
            btn.setAttribute('title', LABEL[t]);
        });
    }

    var current = storedTheme();
    applyTheme(current);
    document.querySelectorAll('[data-theme-toggle]').forEach(function (btn) {
        btn.addEventListener('click', function () {
            current = ORDER[(ORDER.indexOf(current) + 1) % ORDER.length];
            applyTheme(current);
        });
    });

    /* The navigation drawer (narrow screens) */
    var shell = document.querySelector('[data-shell]');
    var toggle = document.querySelector('[data-nav-toggle]');
    var sidebar = document.getElementById('sidebar');

    function setNav(open) {
        if (!shell || !toggle) return;
        if (open) {
            shell.setAttribute('data-nav-open', '');
            toggle.setAttribute('aria-expanded', 'true');
            var first = sidebar && sidebar.querySelector('a, button');
            if (first) first.focus();
        } else {
            shell.removeAttribute('data-nav-open');
            toggle.setAttribute('aria-expanded', 'false');
        }
    }

    if (toggle) {
        toggle.addEventListener('click', function () {
            setNav(!shell.hasAttribute('data-nav-open'));
        });
    }
    if (shell) {
        shell.addEventListener('click', function (event) {
            if (shell.hasAttribute('data-nav-open') && sidebar && !sidebar.contains(event.target)
                    && !toggle.contains(event.target)) {
                setNav(false);
            }
        });
    }

    /* Menus built on <details data-menu> */
    var menus = document.querySelectorAll('details[data-menu]');
    document.addEventListener('click', function (event) {
        menus.forEach(function (menu) {
            if (menu.open && !menu.contains(event.target)) menu.open = false;
        });
    });

    document.addEventListener('keydown', function (event) {
        if (event.key !== 'Escape') return;
        menus.forEach(function (menu) {
            if (menu.open) {
                menu.open = false;
                var summary = menu.querySelector('summary');
                if (summary) summary.focus();
            }
        });
        if (shell && shell.hasAttribute('data-nav-open')) {
            setNav(false);
            if (toggle) toggle.focus();
        }
    });

    /* Scrollable tables. Only a wrapper that overflows becomes focusable, and it gives the focus
       back up once it no longer overflows; one the markup made focusable itself is left alone. */
    function tableName(wrap) {
        var caption = wrap.querySelector('caption');
        if (caption && caption.textContent.trim()) return caption.textContent.trim();
        var panel = wrap.closest('section, details');
        var heading = panel && panel.querySelector('h2, h3, summary');
        return heading && heading.textContent.trim() ? heading.textContent.trim() : 'Table';
    }

    function markScrollable() {
        document.querySelectorAll('.table-wrap').forEach(function (wrap) {
            var overflowing = wrap.scrollWidth > wrap.clientWidth + 1;
            if (overflowing && !wrap.hasAttribute('tabindex')) {
                wrap.setAttribute('tabindex', '0');
                wrap.setAttribute('role', 'region');
                wrap.setAttribute('aria-label', tableName(wrap) + ' (scrolls sideways)');
                wrap.setAttribute('data-scroll-focus', '');
            } else if (!overflowing && wrap.hasAttribute('data-scroll-focus')) {
                ['tabindex', 'role', 'aria-label', 'data-scroll-focus'].forEach(function (a) {
                    wrap.removeAttribute(a);
                });
            }
        });
    }

    var pending = false;
    function scheduleMark() {
        if (pending) return;
        pending = true;
        window.requestAnimationFrame(function () { pending = false; markScrollable(); });
    }
    markScrollable();
    window.addEventListener('resize', scheduleMark);
    /* Widths settle when the web fonts arrive. */
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(scheduleMark);
    /* A <details> opening can reveal a table, and its toggle event does not bubble. */
    document.addEventListener('toggle', scheduleMark, true);
})();

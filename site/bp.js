// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/* The landing page's motion. Everything here is an enhancement: the page reads complete without it.
   - the loading screen counts what has really loaded (the card's frames), then lifts;
   - the card rises into place from its rendered frames, and settles back as the page scrolls on;
   - a lens over the card shows the same card with its body turned to glass;
   - the band pins while a tile opens to the full screen and the card comes apart, frame by frame;
   - words and blocks rise into place as they enter the screen. */
(function () {
    'use strict';

    var root = document.documentElement;
    var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    function $(s, r) { return (r || document).querySelector(s); }
    function $$(s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); }
    function clamp(v, a, b) { return v < a ? a : v > b ? b : v; }
    function lerp(a, b, t) { return a + (b - a) * t; }
    function smooth(t) { return t * t * (3 - 2 * t); }

    /* ---- words ---------------------------------------------------------- */
    $$('[data-split]').forEach(function (el) {
        var words = el.textContent.trim().split(/\s+/);
        el.textContent = '';
        words.forEach(function (word, i) {
            var outer = document.createElement('span');
            var inner = document.createElement('span');
            outer.className = 'w';
            inner.textContent = word;
            inner.style.transitionDelay = (i * 42) + 'ms';
            outer.appendChild(inner);
            el.appendChild(outer);
            if (i < words.length - 1) { el.appendChild(document.createTextNode(' ')); }
        });
        el.setAttribute('data-r', '');
    });

    /* ---- reveals -------------------------------------------------------- */
    var io = 'IntersectionObserver' in window ? new IntersectionObserver(function (entries) {
        entries.forEach(function (e) {
            if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); }
        });
    }, { rootMargin: '0px 0px -10% 0px' }) : null;
    $$('[data-r]').forEach(function (el) {
        if (el.closest('.hero')) { return; }
        var sibs = el.parentNode ? $$(':scope > [data-r]', el.parentNode) : [];
        if (sibs.length > 1 && !el.hasAttribute('data-split')) { el.style.transitionDelay = (sibs.indexOf(el) * 90) + 'ms'; }
        if (io) { io.observe(el); } else { el.classList.add('in'); }
    });

    /* ---- frame sequences ------------------------------------------------ */
    function Seq(canvas, dir, n) {
        this.canvas = canvas;
        this.ctx = canvas ? canvas.getContext('2d') : null;
        this.dir = dir;
        this.n = n;
        this.frames = [];
        this.loaded = 0;
        this.ready = false;
        this.started = false;
        this.cur = -1;
    }
    Seq.prototype.load = function (onProgress, onDone) {
        var self = this;
        if (this.started || !this.ctx) { return; }
        this.started = true;
        function settle() {
            self.loaded += 1;
            if (onProgress) { onProgress(self.loaded / self.n); }
            if (self.loaded === self.n) {
                self.ready = self.frames.every(function (f) { return f.naturalWidth > 0; });
                if (onDone) { onDone(self.ready); }
            }
        }
        for (var i = 0; i < this.n; i += 1) {
            var im = new Image();
            im.decoding = 'async';
            im.onload = settle;
            im.onerror = settle;
            im.src = this.dir + 'f-' + ('00' + i).slice(-3) + '.webp';
            this.frames.push(im);
        }
    };
    Seq.prototype.draw = function (i) {
        i = clamp(Math.round(i), 0, this.n - 1);
        if (!this.ready || i === this.cur) { return; }
        this.cur = i;
        this.ctx.drawImage(this.frames[i], 0, 0, this.canvas.width, this.canvas.height);
    };

    var hero = $('#hero');
    var stage = $('#stage');
    var still = $('#still');
    var xray = $('#xray');
    var stills = $$('.stage-still');
    var xrays = $$('.stage-xray');
    var lensRead = $('#lens-read');
    var wireEnd = $('#wire-end');
    var segTag = $('.seg-tag');
    var pager = $('#pager');
    var pagerI = $('#pager-i');
    var hatch = $$('#hatch i');
    var lens = $('#lens');
    var wireLine = $('#wire-line');
    var wireNode = $('#wire-node');
    var callout = $('#callout');
    var h1 = $('.h1');
    var band = $('#band');
    var tile = $('#tile');
    var bandStage = $('#band-stage');
    var bandLabel = $('.band-label');
    var closeSec = $('#close');
    var closeBg = $('#close-bg');
    var top = $('#top');
    var ARRIVE = 30;
    var EXPLODE = 32;
    var arrive = new Seq($('#seq-arrive'), 'card/arrive/', ARRIVE);
    var explode = new Seq($('#seq-explode'), 'card/explode/', EXPLODE);

    /* ---- smooth scrolling ----------------------------------------------- */
    var lenis = null;
    if (window.Lenis && !reduce) {
        try { lenis = new window.Lenis({ lerp: 0.1 }); } catch (e) { lenis = null; }
    }
    function scrollToEl(el) {
        if (lenis) { lenis.scrollTo(el, { duration: 1.4 }); } else { el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth' }); }
    }
    document.addEventListener('click', function (ev) {
        var a = ev.target.closest ? ev.target.closest('a[href^="#"]') : null;
        if (!a) { return; }
        var target = $(a.getAttribute('href'));
        if (!target) { return; }
        ev.preventDefault();
        closeMenu();
        scrollToEl(target);
    });

    /* ---- menu ----------------------------------------------------------- */
    var menu = $('#menu');
    var menuBtn = $('#menu-btn');
    if (menu) { menu.hidden = false; }
    function closeMenu() {
        root.classList.remove('menu-open');
        if (menuBtn) { menuBtn.setAttribute('aria-expanded', 'false'); }
        if (lenis && introDone) { lenis.start(); }
    }
    if (menuBtn) {
        menuBtn.addEventListener('click', function () {
            var open = !root.classList.contains('menu-open');
            root.classList.toggle('menu-open', open);
            menuBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
            if (lenis) { if (open) { lenis.stop(); } else { lenis.start(); } }
        });
    }
    if ($('#menu-close')) { $('#menu-close').addEventListener('click', closeMenu); }
    $$('#menu a').forEach(function (a) { a.addEventListener('click', closeMenu); });
    document.addEventListener('keydown', function (ev) { if (ev.key === 'Escape') { closeMenu(); } });

    /* ---- the card's two views ------------------------------------------- */
    var view = 'surface';
    $$('#seg button').forEach(function (b) {
        b.addEventListener('click', function () {
            view = b.getAttribute('data-view');
            $$('#seg button').forEach(function (o) {
                var on = o === b;
                o.classList.toggle('on', on);
                o.setAttribute('aria-pressed', on ? 'true' : 'false');
            });
            labels();
            if (hero) { hero.classList.toggle('inside', view === 'inside'); }
        });
    });

    /* ---- the lens ------------------------------------------------------- */
    /* x, y, r: the reticle in the frame (0..1); cx, cy, cr: the same on the screen, in px; px, py: the pointer */
    var L = { x: 0.4, y: 0.47, r: 0, px: 0, py: 0, cx: -1e4, cy: -1e4, cr: 0, hold: false, touch: false, id: -1, moved: -1e9 };
    /* The card's sides, in the order they are shown. stops: the two places the reticle rests on, in the frame
       (0..1 of its width and height); box: the card in the frame, the furthest the reticle can be taken;
       mm: the plane map from the frame to millimetres on the side shown, from its top left corner. All of it is
       read off the renders' own cameras (brand/card-blueprint, site-geom). pic: the side's name in the addresses
       of its pictures; the first side's pictures are in the page itself. */
    var VIEWS = [
        { stops: [[0.457, 0.427], [0.8318, 0.5995]], box: [0.363, 0.888, 0.262, 0.677], mm: [212.72, 24.731, -93.445, -3.7777, 175.17, -44.411, 0.020264, 0.4338] },
        { pic: 'back', stops: [[0.5207, 0.4363], [0.8423, 0.5308]], box: [0.345, 0.906, 0.219, 0.757], mm: [177.24, -50.148, -44.2, 41.616, 144.33, -63.126, -0.22373, 0.41659] },
        { pic: 'macro', stops: [[0.488, 0.4026], [0.75, 0.5889]], box: [0.286, 1.182, 0.055, 0.84], mm: [106.49, -24.51, -26.077, 18.389, 97.706, -22.669, -0.18506, 0.39438] }
    ];
    var GLIDE = 950;                 /* from one place to the next */
    var DWELL = 1700;                /* resting on a place */
    /* v: the side shown; s: which of its two places; moving: gliding there (from fx, fy, since t0), else resting since t0 */
    var C = { v: 0, s: 0, moving: false, t0: 0, fx: 0, fy: 0, held: false, hn: -1 };
    L.x = VIEWS[0].stops[0][0];
    L.y = VIEWS[0].stops[0][1];
    function pictureIn(im) { return !!im && im.complete && im.naturalWidth > 0; }
    /* how many sides can be shown: the first, and each next one whose two pictures have arrived */
    function sides() {
        var n = 1;
        while (n < VIEWS.length && pictureIn(stills[n]) && pictureIn(xrays[n])) { n += 1; }
        return n;
    }
    function labels() {
        $$('.callout-item').forEach(function (c) {
            var v = c.getAttribute('data-v');
            c.classList.toggle('on', c.getAttribute('data-for') === view && (v === null || +v === C.v));
        });
    }
    function glide(now) { C.moving = true; C.t0 = now; C.fx = L.x; C.fy = L.y; }
    function showView(v, now) {
        var n = sides();
        v = ((v % n) + n) % n;
        if (v !== C.v) {
            C.v = v;
            stills.forEach(function (im, i) { im.classList.toggle('on', i === v); });
            xrays.forEach(function (im, i) { im.classList.toggle('on', i === v); });
            labels();
            if (pagerI) { pagerI.textContent = '0' + (v + 1); }
        }
        C.s = 0;
        glide(now);
    }
    /* the other sides are fetched once the first has landed, and join the round when they are in. Their addresses
       are built here from the sides' names and the three widths, so the script takes no address from the page */
    var WIDTHS = [1600, 2560, 3840];
    function loadViews() {
        [[stills, 'hero'], [xrays, 'xray']].forEach(function (kind) {
            kind[0].forEach(function (im, i) {
                var side = VIEWS[i] && VIEWS[i].pic;
                if (!side || im.hasAttribute('src')) { return; }
                var base = 'card/view-' + side + '-' + kind[1] + '-';
                im.addEventListener('load', function () { if (pager && sides() > 1) { pager.hidden = false; } });
                im.srcset = WIDTHS.map(function (w) { return base + w + '.webp ' + w + 'w'; }).join(', ');
                im.src = base + WIDTHS[0] + '.webp';
            });
        });
    }
    if ($('#pager-prev')) { $('#pager-prev').addEventListener('click', function () { showView(C.v - 1, performance.now()); }); }
    if ($('#pager-next')) { $('#pager-next').addEventListener('click', function () { showView(C.v + 1, performance.now()); }); }
    function inLens(x, y) {
        var dx = x - L.cx;
        var dy = y - L.cy;
        return dx * dx + dy * dy <= L.cr * L.cr;
    }
    function letGo() { L.hold = false; L.touch = false; L.id = -1; }
    /* the card answers the pointer: it moves a little the other way, eased, and comes back when the pointer leaves */
    var PAR = { tx: 0, ty: 0, x: 0, y: 0 };
    var heroHud = $('.hero-hud');
    if (hero && !reduce && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
        /* read on the document: the header lies over the top of the first screen and would keep those moves */
        document.addEventListener('pointermove', function (ev) {
            if (ev.pointerType !== 'mouse') { return; }
            if ((window.scrollY || 0) > M.heroH * 0.6) { PAR.tx = 0; PAR.ty = 0; return; }
            PAR.tx = -(ev.clientX / Math.max(1, M.vw) - 0.5) * 2 * 0.7 * M.rem;
            PAR.ty = -(ev.clientY / Math.max(1, M.vh) - 0.5) * 2 * 0.45 * M.rem;
        });
        document.documentElement.addEventListener('pointerleave', function () { PAR.tx = 0; PAR.ty = 0; });
    }
    if (hero) {
        /* a mouse: the reticle follows it only while it is inside the reticle; outside, the reticle is let go */
        hero.addEventListener('pointermove', function (ev) {
            if (ev.pointerType !== 'mouse' || L.touch) { return; }
            if (inLens(ev.clientX, ev.clientY)) {
                L.hold = true;
                L.px = ev.clientX;
                L.py = ev.clientY;
                L.moved = performance.now();
            } else {
                L.hold = false;
            }
        });
        hero.addEventListener('pointerleave', function (ev) { if (ev.pointerType === 'mouse') { letGo(); } });
    }
    if (lens) {
        /* a finger: put on the reticle it carries it, and lets it go when lifted */
        lens.addEventListener('pointerdown', function (ev) {
            if (ev.pointerType === 'mouse') { return; }
            L.hold = true;
            L.touch = true;
            L.id = ev.pointerId;
            L.px = ev.clientX;
            L.py = ev.clientY;
            L.moved = performance.now();
            try { lens.setPointerCapture(ev.pointerId); } catch (e) { /* the finger is followed all the same */ }
            ev.preventDefault();
        });
        lens.addEventListener('pointermove', function (ev) {
            if (L.touch && ev.pointerId === L.id) { L.px = ev.clientX; L.py = ev.clientY; L.moved = performance.now(); }
        });
        ['pointerup', 'pointercancel', 'lostpointercapture'].forEach(function (name) {
            lens.addEventListener(name, function (ev) { if (L.touch && ev.pointerId === L.id) { letGo(); } });
        });
    }

    /* ---- the small sky marks: every star flickers but the pole star ------ */
    var skies = $$('.hud-stars').map(function (el) { return { el: el, stars: $$('i', el).slice(1), on: false }; });
    if (skies.length && !reduce && 'IntersectionObserver' in window) {
        var LEVELS = [0.12, 0.25, 0.42, 0.68, 1];
        var seen = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                skies.forEach(function (s) { if (s.el === e.target) { s.on = e.isIntersecting; } });
            });
        });
        skies.forEach(function (s) { seen.observe(s.el); });
        window.setInterval(function () {
            if (document.hidden) { return; }
            skies.forEach(function (s) {
                if (!s.on) { return; }
                s.stars.forEach(function (st) {
                    if (Math.random() < 0.2) { st.style.opacity = LEVELS[(Math.random() * LEVELS.length) | 0]; }
                });
            });
        }, 160);
    }

    /* ---- the word at the foot: gold dust under the pointer ---------------
       The word is drawn on a canvas and cut into small cells. A cell the pointer's reach has just taken in is
       thrown outward and springs back to its place; cells within reach are gold, and so is the dust in flight. */
    var footWord = $('#foot-word');
    if (footWord && !reduce && window.matchMedia('(hover: hover) and (pointer: fine)').matches) {
        (function () {
            var CELL = 7;
            var REACH = 150;
            var PAD = 64;                                   /* the canvas stands this far above and below the word */
            var art = footWord.querySelector('svg');
            var shape = art && art.querySelector('path') && window.Path2D ? new window.Path2D(art.querySelector('path').getAttribute('d')) : null;
            var vb = art ? art.viewBox.baseVal : null;
            var tone = window.getComputedStyle(footWord).color;
            var gold = window.getComputedStyle(document.documentElement).getPropertyValue('--gold').trim() || '#ddca9b';
            var canvas = document.createElement('canvas');
            var ctx = canvas.getContext('2d');
            var base = document.createElement('canvas');    /* the word at rest */
            var gilt = document.createElement('canvas');    /* the same word in gold */
            var w = 0;
            var h = 0;
            var dpr = 1;
            var n = 0;
            var hx; var hy; var cx; var cy; var vx; var vy; var near;
            var px = -1e4;
            var py = -1e4;
            var inside = 0;
            var reach = 0;
            var ready = false;
            var queued = false;
            if (!shape || !vb || !vb.width || !ctx) { return; }
            canvas.className = 'foot-dust';
            canvas.setAttribute('aria-hidden', 'true');
            footWord.appendChild(canvas);

            function drawWord(c, scale, color, box) {
                /* the page's own drawing of the word, at the place and size the page gave it */
                var g = c.getContext('2d');
                var at = art.getBoundingClientRect();
                var k = at.width / vb.width;
                g.setTransform(scale, 0, 0, scale, 0, 0);
                g.clearRect(0, 0, w, h);
                g.setTransform(scale * k, 0, 0, scale * k, scale * (at.left - box.left - vb.x * k), scale * (at.top - box.top + PAD - vb.y * k));
                g.fillStyle = color;
                g.fill(shape);
                g.setTransform(scale, 0, 0, scale, 0, 0);
            }

            function build() {
                ready = false;
                footWord.classList.remove('dusty');
                var box = footWord.getBoundingClientRect();
                w = Math.round(box.width);
                h = Math.round(box.height) + 2 * PAD;
                if (w < 40 || box.height < 12) { return; }
                dpr = Math.min(window.devicePixelRatio || 1, 2);
                [canvas, base, gilt].forEach(function (c) { c.width = w * dpr; c.height = h * dpr; });
                drawWord(base, dpr, tone, box);
                drawWord(gilt, dpr, gold, box);
                var probe = document.createElement('canvas');
                probe.width = w;
                probe.height = h;
                drawWord(probe, 1, '#fff', box);
                var data;
                try { data = probe.getContext('2d').getImageData(0, 0, w, h).data; } catch (err) { return; }
                var X = [];
                var Y = [];
                var x; var y; var xx; var yy; var a; var v;
                for (y = CELL / 2; y < h; y += CELL) {
                    for (x = CELL / 2; x < w; x += CELL) {
                        a = 0;
                        for (yy = y - CELL / 2; yy < y + CELL / 2; yy++) {
                            for (xx = x - CELL / 2; xx < x + CELL / 2; xx++) {
                                v = data[(Math.min(h - 1, yy | 0) * w + Math.min(w - 1, xx | 0)) * 4 + 3];
                                if (v > a) { a = v; }
                            }
                        }
                        if (a > 6) { X.push(x); Y.push(y); }
                    }
                }
                n = X.length;
                if (!n) { return; }
                hx = Float32Array.from(X);
                hy = Float32Array.from(Y);
                cx = Float32Array.from(X);
                cy = Float32Array.from(Y);
                vx = new Float32Array(n);
                vy = new Float32Array(n);
                near = new Uint8Array(n);
                ready = true;
                footWord.classList.add('dusty');
                footWord.setAttribute('data-cells', String(n));
                draw();
            }

            function draw() {
                queued = false;
                if (!ready) { return; }
                var box = footWord.getBoundingClientRect();
                var mx = px - box.left;
                var my = py - box.top + PAD;
                var half = CELL / 2;
                var alive;
                var i;
                reach += (inside - reach) * (inside > reach ? 0.22 : 0.1);
                if (reach < 0.004 && !inside) { reach = 0; }
                var R = REACH * reach;
                alive = reach > 0;
                ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
                ctx.clearRect(0, 0, w, h);
                ctx.drawImage(base, 0, 0, w, h);
                ctx.fillStyle = gold;
                for (i = 0; i < n; i++) {
                    var dx = hx[i] - mx;
                    var dy = hy[i] - my;
                    var d2 = dx * dx + dy * dy;
                    var taken = reach > 0 && d2 < R * R;
                    if (taken && !near[i]) {
                        /* thrown outward, a little to one side, harder the nearer it was */
                        var d = Math.sqrt(d2) || 1;
                        var turn = (Math.random() - 0.5) * 1.4;
                        var co = Math.cos(turn);
                        var si = Math.sin(turn);
                        var push = (3 + Math.random() * 9) * (1 - d / REACH * 0.4);
                        vx[i] += (dx / d * co - dy / d * si) * push;
                        vy[i] += (dx / d * si + dy / d * co) * push;
                    }
                    near[i] = taken ? 1 : 0;
                    var ox = cx[i] - hx[i];
                    var oy = cy[i] - hy[i];
                    if (ox * ox + oy * oy > 0.04 || vx[i] * vx[i] + vy[i] * vy[i] > 0.01) {
                        vx[i] = (vx[i] - ox * 0.045) * 0.9;
                        vy[i] = (vy[i] - oy * 0.045) * 0.9;
                        cx[i] += vx[i];
                        cy[i] += vy[i];
                        alive = true;
                    } else {
                        cx[i] = hx[i];
                        cy[i] = hy[i];
                    }
                    var off = Math.sqrt((cx[i] - hx[i]) * (cx[i] - hx[i]) + (cy[i] - hy[i]) * (cy[i] - hy[i]));
                    if (!taken && off < 1.2) { continue; }
                    ctx.clearRect(hx[i] - half, hy[i] - half, CELL, CELL);
                    if (off < 1.2) {
                        /* at home and within reach: the letter itself, in gold */
                        ctx.drawImage(gilt, (hx[i] - half) * dpr, (hy[i] - half) * dpr, CELL * dpr, CELL * dpr, hx[i] - half, hy[i] - half, CELL, CELL);
                    } else {
                        var sp = Math.sqrt(vx[i] * vx[i] + vy[i] * vy[i]);
                        if (sp > 2.2) { ctx.fillRect(cx[i] - 2 - sp * 0.6, cy[i] - 1, 4 + sp * 1.2, 2); } else { ctx.fillRect(cx[i] - 1.5, cy[i] - 1.5, 3, 3); }
                    }
                }
                if (alive) { queue(); }
            }

            function queue() {
                if (ready && !queued) { queued = true; window.requestAnimationFrame(draw); }
            }

            function look() {
                var box = footWord.getBoundingClientRect();
                inside = (px > box.left - 20 && px < box.right + 20 && py > box.top && py < box.bottom) ? 1 : 0;
                if (inside || reach) { queue(); }
            }

            document.addEventListener('pointermove', function (ev) {
                if (ev.pointerType === 'touch') { return; }
                px = ev.clientX;
                py = ev.clientY;
                look();
            }, { passive: true });
            window.addEventListener('scroll', function () { if (px > -1e3) { look(); } }, { passive: true });
            document.addEventListener('pointerleave', function () { inside = 0; queue(); });
            var again = 0;
            window.addEventListener('resize', function () {
                ready = false;
                window.clearTimeout(again);
                again = window.setTimeout(build, 200);
            });
            build();
            window.addEventListener('load', build);
        })();
    }

    /* ---- measurements --------------------------------------------------- */
    var M = { vw: 0, vh: 0, heroH: 1, bandTop: 0, bandH: 1, closeTop: 0, secs: [], portrait: false, gutter: 28, side: 28, rem: 16 };
    function measure() {
        M.vw = window.innerWidth;
        M.vh = window.innerHeight;
        M.portrait = M.vw < 600 || M.vw <= M.vh;            /* the same test as the styles' upright block */
        M.rem = parseFloat(getComputedStyle(root).fontSize) || 16;
        /* in a very wide window the gutter is a computed length and reads as no number: the plain one stands in */
        M.gutter = (parseFloat(getComputedStyle(root).getPropertyValue('--gutter')) || 1.75) * M.rem;
        /* where the words begin: the gutter, or the edge of the centred frame of a very wide window */
        M.side = (top && parseFloat(getComputedStyle(top).paddingLeft)) || M.gutter;
        if (hero) { M.heroH = hero.offsetHeight; }
        if (band) { M.bandTop = band.offsetTop; M.bandH = band.offsetHeight; }
        if (closeSec) { M.closeTop = closeSec.offsetTop; }
        M.secs = $$('main > section, .foot').map(function (s) {
            return { top: s.offsetTop, bottom: s.offsetTop + s.offsetHeight, paper: s.classList.contains('paper'), id: s.id };
        });
    }
    window.addEventListener('resize', measure);
    window.addEventListener('load', measure);
    measure();

    /* ---- the loading screen, then the card's arrival --------------------- */
    var pre = $('#pre');
    var preNum = $('#pre-num');
    var preFill = $('#pre-fill');
    var preArc = $('#pre-arc');
    var preTurn = $('#pre-turn');
    var preList = $$('#pre-list li');
    var skipPre = root.classList.contains('pre-skip') || !pre;
    var loadedPart = 0;
    var shown = 0;
    var t0 = performance.now();
    var lifted = false;
    var fullAt = 0;                  /* when the count reached its end */
    var introDone = false;
    var introAt = 0;
    var MIN_SHOW = 2100;
    var RAMP = 1500;                 /* the count never runs ahead of this, however fast the files come */
    var MAX_SHOW = 7000;
    var INTRO_MS = 1250;

    function stillReady(img) { return !img || (img.complete && img.naturalWidth > 0); }

    function startIntro() {
        if (!hero) { introDone = true; return; }
        hero.classList.add('shown');
        if (h1) { h1.classList.add('in'); }
        if (arrive.ready && !reduce && !skipPre) {
            hero.classList.add('seq');
            arrive.draw(0);
            introAt = performance.now();
        } else {
            endIntro();
        }
    }
    function endIntro() {
        introDone = true;
        introAt = 0;
        if (hero) { hero.classList.remove('seq'); hero.classList.add('near'); hero.classList.add('live'); }
        C.t0 = performance.now();
        window.setTimeout(loadViews, 700);
        window.setTimeout(function () { explode.load(null, function (ok) { if (ok && band) { band.classList.add('ready'); explode.draw(0); } }); }, 600);
    }
    function lift() {
        if (lifted) { return; }
        lifted = true;
        root.classList.add('pre-done');
        root.classList.remove('lock');
        try { sessionStorage.setItem('plr-pre', '1'); } catch (e) { /* private mode: the screen shows again next time */ }
        if (lenis) { lenis.start(); }
        window.setTimeout(startIntro, 660);
        window.setTimeout(function () { root.classList.add('pre-gone'); }, 1400);
    }

    arrive.load(function (part) { loadedPart = part; }, function () { if (skipPre && !introDone) { /* frames arrive late: used for the scroll only */ } });
    if (skipPre) {
        lifted = true;
        root.classList.add('pre-done', 'pre-gone');
        root.classList.remove('lock');
        startIntro();
    } else if (lenis) {
        lenis.stop();
    }

    /* ---- one loop ------------------------------------------------------- */
    function frame(now) {
        if (lenis) { lenis.raf(now); }
        var sy = window.scrollY || 0;

        /* the loading count */
        if (!lifted) {
            var got = { arrive: loadedPart >= 1, surface: stillReady(still), inside: stillReady(xray) };
            var have = loadedPart * 0.8 + (got.surface ? 0.1 : 0) + (got.inside ? 0.1 : 0);
            have = Math.min(have, Math.max(0, now - t0) / RAMP);
            preList.forEach(function (li) { li.classList.toggle('on', !!got[li.getAttribute('data-k')]); });
            shown += Math.max((have - shown) * 0.07, have > shown ? 0.004 : 0);
            shown = Math.min(shown, have);
            if (have > 0.999 && shown > 0.992) { shown = 1; if (!fullAt) { fullAt = now; } }
            var pct = Math.round(shown * 100);
            if (preNum) { preNum.textContent = ('00' + pct).slice(-3); }
            if (preFill) { preFill.style.transform = 'scaleX(' + shown.toFixed(4) + ')'; }
            if (preArc) {
                preArc.style.strokeDashoffset = (100 * (1 - shown)).toFixed(2);
                if (shown === 1) { preArc.style.strokeDasharray = '200'; }     /* one dash, longer than the ring: no seam */
            }
            /* the sky turns about the pole as the count runs, and comes to rest when it is full */
            if (preTurn) { preTurn.style.transform = 'rotate(' + (48 * (1 - smooth(shown))).toFixed(2) + 'deg)'; }
            var waited = now - t0;
            if ((fullAt && now - fullAt > 320 && waited > MIN_SHOW) || waited > MAX_SHOW) { lift(); }
        }

        /* the card's arrival, played once */
        if (introAt) {
            var k = (now - introAt) / INTRO_MS;
            arrive.draw(k * (ARRIVE - 1));
            if (k > 0.45 && hero) { hero.classList.add('near'); }       /* the reticle is there before the card lands */
            if (k >= 1) { endIntro(); }
        }

        /* the hero as the page scrolls on */
        if (hero && sy < M.heroH * 1.15) {
            var p = clamp(sy / (M.heroH * 0.9), 0, 1);
            if (introDone) {
                var away = p > 0.004;
                /* the frames are of the card's first side; scrolled away from another side, the picture fades instead */
                var frames = away && arrive.ready && !reduce && C.v === 0;
                hero.classList.toggle('seq', frames);
                if (frames) { arrive.draw((1 - p) * (ARRIVE - 1)); }
                if (stage) { stage.style.opacity = away && !frames ? (1 - clamp(p * 1.7, 0, 1)).toFixed(3) : ''; }
                hero.classList.toggle('away', away);
            }
            PAR.x += (PAR.tx - PAR.x) * 0.07;
            PAR.y += ((sy > 0 ? Math.min(PAR.ty, 0) : PAR.ty) - PAR.y) * 0.07;
            if (stage) { stage.style.transform = 'translate3d(' + PAR.x.toFixed(2) + 'px,' + (sy * 0.2 + PAR.y).toFixed(2) + 'px,0)'; }
            if (heroHud) { heroHud.style.transform = 'translate3d(' + (-PAR.x * 0.55).toFixed(2) + 'px,' + (-PAR.y * 0.55).toFixed(2) + 'px,0)'; }
            if (h1) { h1.style.transform = 'translate3d(0,' + (-sy * 0.1).toFixed(1) + 'px,0)'; h1.style.opacity = (1 - p * 1.3).toFixed(3); }

            /* the lens: on the card, full size, from before the card lands */
            if (stage && xray && (introDone || introAt)) {
                var rect = stage.getBoundingClientRect();
                var V = VIEWS[C.v];
                var gone = hero.classList.contains('away');
                /* a mouse resting inside the reticle holds it for a few seconds, then it goes back to its reading */
                if (L.hold && !L.touch && now - L.moved > 5200) { L.hold = false; }
                if (L.hold && (view === 'inside' || gone || !introDone)) { letGo(); }
                var chase = L.hold;
                if (chase) {
                    /* held, it keeps to the card (a little past its edges and no further) and to the window. Under a
                       finger the view sits a little above the fingertip, which would otherwise cover it */
                    var fy = L.touch ? L.py - L.cr * 0.55 : L.py;
                    var lo = Math.max(V.box[0] - 0.02, (L.cr * 0.6 - rect.left) / rect.width);
                    var hi = Math.min(V.box[1] + 0.02, (M.vw - L.cr * 0.6 - rect.left) / rect.width);
                    var tx = clamp((L.px - rect.left) / rect.width, lo, Math.max(lo, hi));
                    var ty = clamp((fy - rect.top) / rect.height, V.box[2] - 0.045, V.box[3] + 0.045);
                    L.x += (tx - L.x) * 0.2;
                    L.y += (ty - L.y) * 0.2;
                    C.held = true;
                } else {
                    var rests = introDone && view !== 'inside' && !gone && !reduce;
                    if (C.held) { C.held = false; glide(now); }          /* let go: back to the place it was reading */
                    if (C.moving) {
                        var gk = clamp((now - C.t0) / GLIDE, 0, 1);
                        var ge = gk < 0.5 ? 4 * gk * gk * gk : 1 - Math.pow(2 - 2 * gk, 3) / 2;
                        var stop = V.stops[C.s];
                        /* on a narrow screen a place near the card's edge is read from where the whole reticle still shows */
                        var sx = Math.min(stop[0], (M.vw - (L.cr || 0) - 2 - rect.left) / rect.width);
                        L.x = lerp(C.fx, sx, ge);
                        L.y = lerp(C.fy, stop[1], ge);
                        if (gk >= 1) { C.moving = false; C.t0 = now; }
                    } else if (!rests) {
                        C.t0 = now;
                    } else if (now - C.t0 > DWELL) {
                        /* one place, then the other, then the card turns to its next side */
                        if (C.s === 0) { C.s = 1; glide(now); } else { showView(C.v + 1, now); }
                    }
                }
                /* the marks beside the count fill as this side's time runs */
                if (hatch.length) {
                    var el = (C.s ? GLIDE + DWELL : 0) + (C.moving ? Math.min(now - C.t0, GLIDE) : GLIDE + Math.min(now - C.t0, DWELL));
                    var hn = Math.min(hatch.length, Math.ceil(el / (2 * (GLIDE + DWELL)) * hatch.length));
                    if (hn !== C.hn) { C.hn = hn; hatch.forEach(function (m, i) { m.classList.toggle('on', i < hn); }); }
                }
                var tr = view === 'inside' ? 1.3 : (gone ? 0 : (M.portrait ? 0.105 : 0.082));
                if (!L.set) { L.set = true; L.r = tr; }                  /* first shown: already its full size */
                L.r += (tr - L.r) * (view === 'inside' || L.r > 0.5 ? 0.05 : 0.09);
                var cx = L.x * rect.width;
                var cy = L.y * rect.height;
                var cr = L.r * rect.width;
                L.cx = rect.left + cx;
                L.cy = rect.top + cy;
                L.cr = cr;
                var clip = 'circle(' + cr.toFixed(1) + 'px at ' + cx.toFixed(1) + 'px ' + cy.toFixed(1) + 'px)';
                xrays.forEach(function (im) { im.style.clipPath = clip; });
                if (lens) {
                    lens.style.transform = 'translate3d(' + cx.toFixed(1) + 'px,' + cy.toFixed(1) + 'px,0)';
                    lens.style.setProperty('--lr', cr.toFixed(1) + 'px');
                }
                if (lensRead) {
                    var q = V.mm;
                    var qw = q[6] * L.x + q[7] * L.y + 1;
                    var mx = (q[0] * L.x + q[1] * L.y + q[2]) / qw;
                    var my = (q[3] * L.x + q[4] * L.y + q[5]) / qw;
                    var read = mx >= 0 && mx <= 85.6 && my >= 0 && my <= 53.98 ? 'X ' + mx.toFixed(1) + '  Y ' + my.toFixed(1) + ' mm' : '';
                    if (read !== L.read) { L.read = read; lensRead.textContent = read; }
                }
                hero.classList.toggle('chase', chase);
                if (wireLine && segTag) {
                    /* the leader: from the reticle's rim to just left of the tag, a circle at each end */
                    var hr = hero.getBoundingClientRect();
                    var tb = segTag.getBoundingClientRect();
                    var ax = rect.left - hr.left + cx;
                    var ay = rect.top - hr.top + cy;
                    var bx = tb.left - hr.left - M.rem * 0.75;
                    var by = tb.top - hr.top + tb.height / 2;
                    var dx = bx - ax;
                    var dy = by - ay;
                    var dl = Math.sqrt(dx * dx + dy * dy) || 1;
                    var rim = dl > cr + 2 ? cr : dl;                     /* with the reticle over the tag there is no line */
                    var sx = (ax + dx / dl * rim).toFixed(1);
                    var sy2 = (ay + dy / dl * rim).toFixed(1);
                    wireLine.setAttribute('x1', sx);
                    wireLine.setAttribute('y1', sy2);
                    wireLine.setAttribute('x2', bx.toFixed(1));
                    wireLine.setAttribute('y2', by.toFixed(1));
                    if (wireNode) { wireNode.setAttribute('cx', sx); wireNode.setAttribute('cy', sy2); }
                    if (wireEnd) { wireEnd.setAttribute('cx', bx.toFixed(1)); wireEnd.setAttribute('cy', by.toFixed(1)); }
                }
            }
        }

        /* the band: a tile opens to the full screen while the card comes apart */
        if (band && tile && sy > M.bandTop - M.vh && sy < M.bandTop + M.bandH) {
            var bp = clamp((sy - M.bandTop) / Math.max(1, M.bandH - M.vh), 0, 1);
            var e = smooth(clamp(bp / 0.36, 0, 1));
            var side = M.portrait ? M.vw * 0.56 : Math.min(M.vw * 0.27, M.vh * 0.46);
            var left0 = M.portrait ? (M.vw - side) / 2 : M.vw - M.side - side;
            var top0 = M.portrait ? M.vh * 0.5 : (M.vh - side) / 2;
            var T = lerp(top0, 0, e);
            var Lf = lerp(left0, 0, e);
            var R = lerp(M.vw - left0 - side, 0, e);
            var B = lerp(M.vh - top0 - side, 0, e);
            tile.style.clipPath = 'inset(' + T.toFixed(1) + 'px ' + R.toFixed(1) + 'px ' + B.toFixed(1) + 'px ' + Lf.toFixed(1) + 'px)';
            if (bandStage) {
                var sh = bandStage.offsetHeight || M.vh;
                var k0 = (side * 1.5) / sh;
                var ddx = (left0 + side / 2 - M.vw / 2) * (1 - e);
                var ddy = (top0 + side / 2 - M.vh / 2) * (1 - e);
                bandStage.style.transform = 'translate3d(' + ddx.toFixed(1) + 'px,' + ddy.toFixed(1) + 'px,0) scale(' + lerp(k0, 1, e).toFixed(4) + ')';
            }
            if (bandLabel) {
                bandLabel.style.opacity = (1 - clamp(bp / 0.2, 0, 1)).toFixed(3);
            }
            explode.draw(clamp((bp - 0.12) / 0.76, 0, 1) * (EXPLODE - 1));
            band.classList.toggle('end', bp > 0.9);
            if (!explode.started) { explode.load(null, function (ok) { if (ok) { band.classList.add('ready'); } }); }
        }

        /* the closing picture drifts behind its line */
        if (closeBg && sy > M.closeTop - M.vh && sy < M.closeTop + M.vh) {
            closeBg.style.transform = 'translate3d(0,' + ((sy - M.closeTop) * 0.16).toFixed(1) + 'px,0)';
        }

        /* the header takes the colour of the section under it, and marks where the page is */
        if (top && M.secs.length) {
            var probe = sy + M.gutter * 1.6;
            var paper = false;
            var here = '';
            for (var i = 0; i < M.secs.length; i += 1) {
                if (probe >= M.secs[i].top && probe < M.secs[i].bottom) { paper = M.secs[i].paper; }
                if (sy + M.vh * 0.5 >= M.secs[i].top && sy + M.vh * 0.5 < M.secs[i].bottom) { here = M.secs[i].id; }
            }
            if (paper !== top.classList.contains('on-paper')) { top.classList.toggle('on-paper', paper); }
            var moved = sy > M.vh * 0.3;
            if (moved !== top.classList.contains('scrolled')) { top.classList.toggle('scrolled', moved); }
            if (here !== top.getAttribute('data-here')) {
                top.setAttribute('data-here', here);
                $$('.nav a').forEach(function (a) { a.classList.toggle('on', a.getAttribute('href') === '#' + here); });
            }
        }

        window.requestAnimationFrame(frame);
    }
    window.requestAnimationFrame(frame);
})();

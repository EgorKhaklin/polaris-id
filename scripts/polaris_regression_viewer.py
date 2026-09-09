"""The regression viewer: one self-contained HTML page with the data embedded (v9.343).

`render_html(dims, fits, full_document=True)` returns the page. With full_document the page is a
complete dark document for the project site (site/regression.html); without it, the page body
alone, for an artifact host that supplies its own skeleton and theme. No library, no network:
the charts are SVG drawn by the page's own script, to one scale, with every label inside the
drawing. The palette is the site's (site/tokens.css); the light theme keeps the same hues.
"""
import html
import json

CSS = r"""
:root{
  --void:#050a12;--bg0:#0a1421;--bg1:#0e1a2b;--line:rgba(141,166,196,.16);--line-strong:rgba(141,166,196,.32);
  --ink:#dce9f6;--ink-dim:#9db1c7;--ink-faint:#6e8299;--gold:#c9a352;--gold-bright:#e8be64;--cyan:#5dd6ff;--cyan-deep:#2a8fb8;
  --red:#ff7478;--amber:#ffc861;--green:#5fd9a2;--grid:rgba(141,166,196,.10);--point:#5dd6ff;--fit:#e8be64;--excluded:#ff7478;
  --font-mono:'JetBrains Mono','SF Mono',ui-monospace,Menlo,Monaco,Consolas,monospace;
  --font-sans:'IBM Plex Sans',-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;
}
@media (prefers-color-scheme: light){
  :root:not([data-theme="dark"]){
    --void:#e9eef5;--bg0:#f3f6fa;--bg1:#ffffff;--line:rgba(20,32,46,.14);--line-strong:rgba(20,32,46,.28);
    --ink:#14202e;--ink-dim:#45586c;--ink-faint:#7b8ea3;--gold:#8a6a1f;--gold-bright:#9a7524;--cyan:#1d7ea6;--cyan-deep:#2a8fb8;
    --red:#c8373c;--amber:#9a6a00;--green:#1f8a5b;--grid:rgba(20,32,46,.08);--point:#1d7ea6;--fit:#9a7524;--excluded:#c8373c;
  }
}
:root[data-theme="light"]{
  --void:#e9eef5;--bg0:#f3f6fa;--bg1:#ffffff;--line:rgba(20,32,46,.14);--line-strong:rgba(20,32,46,.28);
  --ink:#14202e;--ink-dim:#45586c;--ink-faint:#7b8ea3;--gold:#8a6a1f;--gold-bright:#9a7524;--cyan:#1d7ea6;--cyan-deep:#2a8fb8;
  --red:#c8373c;--amber:#9a6a00;--green:#1f8a5b;--grid:rgba(20,32,46,.08);--point:#1d7ea6;--fit:#9a7524;--excluded:#c8373c;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg0);color:var(--ink);font-family:var(--font-sans);font-size:14px;line-height:1.55}
a{color:var(--cyan)}
.wrap{max-width:1180px;margin:0 auto;padding:28px 22px 60px}
header{display:flex;flex-wrap:wrap;gap:18px 32px;align-items:baseline;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:22px}
header h1{font-family:var(--font-mono);font-size:19px;letter-spacing:.14em;text-transform:uppercase;color:var(--gold-bright);margin:0;font-weight:700}
header p{margin:6px 0 0;color:var(--ink-dim);max-width:62ch}
.prov{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px 24px;font-family:var(--font-mono);font-size:11.5px;letter-spacing:.04em;color:var(--ink-faint)}
.prov b{display:block;font-size:18px;letter-spacing:0;color:var(--ink);font-variant-numeric:tabular-nums;font-weight:600}
.work{display:grid;grid-template-columns:250px 1fr;gap:22px;align-items:start}
@media (max-width:820px){.work{grid-template-columns:1fr}}
.rail{display:flex;flex-direction:column;gap:16px;background:var(--bg1);border:1px solid var(--line);border-radius:4px;padding:16px}
.rail label{display:flex;flex-direction:column;gap:5px;font-family:var(--font-mono);font-size:10.5px;letter-spacing:.1em;text-transform:uppercase;color:var(--ink-faint)}
.rail select,.rail button{font:inherit;font-family:var(--font-mono);font-size:12.5px;color:var(--ink);background:var(--bg0);border:1px solid var(--line-strong);border-radius:3px;padding:7px 9px}
.rail select:focus-visible,.rail button:focus-visible,.pairs button:focus-visible,.tabs button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.tabs{display:flex;gap:6px;flex-wrap:wrap}
.tabs button{cursor:pointer;color:var(--ink-dim)}
.tabs button[aria-pressed="true"]{color:var(--gold-bright);border-color:var(--gold)}
.rail .hint{font-size:12px;color:var(--ink-dim);margin:0}
.rail .hint code{font-family:var(--font-mono);color:var(--ink)}
.chips{display:flex;flex-wrap:wrap;gap:6px}
.chips span{font-family:var(--font-mono);font-size:11px;color:var(--excluded);border:1px solid var(--excluded);border-radius:3px;padding:2px 6px}
.stage{display:flex;flex-direction:column;gap:12px;min-width:0}
.eq{display:flex;flex-wrap:wrap;gap:8px 22px;align-items:baseline;font-family:var(--font-mono);font-variant-numeric:tabular-nums;font-size:13.5px;color:var(--ink)}
.eq .f{color:var(--fit);font-weight:700;font-size:15px}
.eq .k{color:var(--ink-faint);font-size:11px;letter-spacing:.08em;text-transform:uppercase;margin-right:4px}
.plain{margin:0;color:var(--ink-dim);font-size:13.5px;max-width:70ch}
.plain em{color:var(--amber);font-style:normal}
.chart{background:var(--bg1);border:1px solid var(--line);border-radius:4px;padding:6px;overflow-x:auto}
svg{display:block;width:100%;height:auto;font-family:var(--font-mono);font-variant-numeric:tabular-nums}
.axis text{fill:var(--ink-faint);font-size:11px}
.axis line{stroke:var(--line-strong)}
.grid line{stroke:var(--grid)}
.axname{fill:var(--ink-dim);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.pt{fill:var(--point);fill-opacity:.85;stroke:var(--bg1);stroke-width:1;cursor:pointer}
.pt.ex{fill:var(--excluded);fill-opacity:.9}
.pt:hover{fill-opacity:1;stroke:var(--ink)}
.fitline{stroke:var(--fit);stroke-width:2;fill:none}
.resid rect{fill:var(--cyan-deep);fill-opacity:.7}
.resid rect.neg{fill:var(--amber);fill-opacity:.6}
.resid .zero{stroke:var(--line-strong)}
.caption{font-family:var(--font-mono);font-size:11px;letter-spacing:.06em;color:var(--ink-faint);margin:0}
.tables{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-top:26px}
@media (max-width:920px){.tables{grid-template-columns:1fr}}
h2{font-family:var(--font-mono);font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--gold-bright);margin:0 0 8px}
.tbl{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-family:var(--font-mono);font-size:12px;font-variant-numeric:tabular-nums}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--ink-faint);font-weight:500;font-size:10.5px;letter-spacing:.08em;text-transform:uppercase}
td.n{text-align:right}
th.n{text-align:right}
.pairs button{font:inherit;font-family:var(--font-mono);color:var(--cyan);background:none;border:0;padding:0;cursor:pointer;text-decoration:underline dotted}
[hidden]{display:none!important}
.since{display:flex;flex-wrap:wrap;align-items:center;gap:8px;text-align:left}.since input{margin:0}.since small{flex-basis:100%;color:var(--ink-faint);letter-spacing:0;text-transform:none;font-size:11px}
.note{margin:10px 0 0;color:var(--ink-faint);font-size:12.5px;max-width:70ch}
footer{margin-top:34px;border-top:1px solid var(--line);padding-top:14px;font-family:var(--font-mono);font-size:11px;letter-spacing:.05em;color:var(--ink-faint);line-height:1.8}
@media (prefers-reduced-motion: no-preference){.pt{transition:fill-opacity .12s}}
"""

JS = r"""
(function(){
  var D = JSON.parse(document.getElementById('polaris-data').textContent);
  var growth = D.dims.rows, perf = D.fits.performance.datasets;
  var DIMS = {day:'day (since the first tag)', minor:'minor version', checks:'invariant checks', routes:'routes', tables:'tables', tests:'tests',
              product_lines:'product lines', docs_lines:'documentation lines', drills:'drills', ci_jobs:'CI jobs', conformance_cases:'conformance cases'};
  var UNIT = {day:'day', minor:'minor version', checks:'check', routes:'route', tables:'table', tests:'test', product_lines:'line', docs_lines:'line', drills:'drill', ci_jobs:'CI job', conformance_cases:'case'};
  var SETS = {
    growth:{label:'Growth by version', rows:growth, dims:Object.keys(DIMS), names:DIMS, id:function(r){return r.tag;}, def:['routes','checks'],
            note:'one row per tagged version; a click on a point excludes that version from the fit'},
    baseline:{label:'Baseline (latency vs load)', rows:(perf.baseline||{}).rows||[], dims:['offered_rps','achieved_rps','p50_ms','p95_ms','p99_ms'],
              names:{offered_rps:'offered req/s',achieved_rps:'achieved req/s',p50_ms:'p50 ms',p95_ms:'p95 ms',p99_ms:'p99 ms'}, id:function(r){return r.stage;}, def:['offered_rps','p95_ms'],
              note:(perf.baseline||{}).note||''},
    atlas:{label:'Atlas render (log-log)', rows:(perf.atlas_render||{}).rows||[], dims:['events','payload_kb','render_ms','log10_events','log10_render_ms'],
           names:{events:'events',payload_kb:'payload KB',render_ms:'render ms',log10_events:'log10 events',log10_render_ms:'log10 render ms'}, id:function(r){return r.events.toLocaleString()+' events';}, def:['log10_events','log10_render_ms'],
           note:(perf.atlas_render||{}).note||''}
  };
  var state = {set:'growth', x:'routes', y:'checks', excluded:{}, since:false};
  function activeRows(S){ return (state.set==='growth' && state.since) ? S.rows.filter(function(r){return +r.minor >= 60;}) : S.rows; }
  var $ = function(id){return document.getElementById(id);};

  function fit(xs, ys){
    var n = xs.length; if (n < 2) return null;
    var mx = 0, my = 0; for (var i=0;i<n;i++){mx+=xs[i]; my+=ys[i];} mx/=n; my/=n;
    var sxx=0, sxy=0, syy=0; for (i=0;i<n;i++){var dx=xs[i]-mx, dy=ys[i]-my; sxx+=dx*dx; sxy+=dx*dy; syy+=dy*dy;}
    if (sxx === 0) return null;
    var a = sxy/sxx, b = my - a*mx, ssres = 0;
    var res = xs.map(function(x,i){var r = ys[i]-(a*x+b); ssres += r*r; return r;});
    var r2 = syy > 0 ? 1 - ssres/syy : (ssres === 0 ? 1 : 0);
    var se = n > 2 ? Math.sqrt((ssres/(n-2))/sxx) : null;
    return {a:a, b:b, r2:r2, n:n, res:res, se:se};
  }
  function niceTicks(lo, hi, count){
    if (!(hi > lo)) { hi = lo + 1; }
    var span = hi - lo, raw = span/Math.max(1,count), mag = Math.pow(10, Math.floor(Math.log10(raw))), norm = raw/mag, step;
    step = norm < 1.5 ? 1 : norm < 3 ? 2 : norm < 7 ? 5 : 10; step *= mag;
    var t0 = Math.floor(lo/step)*step, ticks = []; for (var v=t0; v<=hi+step*0.5; v+=step) ticks.push(+v.toFixed(10));
    return ticks;
  }
  function fmt(v){ if (Math.abs(v) >= 1000) return Math.round(v).toLocaleString(); if (Math.abs(v) >= 10) return (Math.round(v*10)/10).toLocaleString(); return (Math.round(v*1000)/1000).toString(); }
  function fmtEq(v){ return Math.abs(v) >= 100 ? fmt(v) : (Math.round(v*1000)/1000).toString(); }
  function esc(s){ return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/"/g,'&quot;'); }

  function draw(){
    var S = SETS[state.set], rows = activeRows(S).filter(function(r){return r[state.x] != null && r[state.y] != null;});
    var inc = rows.filter(function(r){return !state.excluded[S.id(r)];});
    var xs = inc.map(function(r){return +r[state.x];}), ys = inc.map(function(r){return +r[state.y];});
    var f = fit(xs, ys);
    var allx = rows.map(function(r){return +r[state.x];}), ally = rows.map(function(r){return +r[state.y];});
    var xlo = Math.min.apply(null, allx), xhi = Math.max.apply(null, allx), ylo = Math.min.apply(null, ally), yhi = Math.max.apply(null, ally);
    if (f){ ylo = Math.min(ylo, f.a*xlo+f.b, f.a*xhi+f.b); yhi = Math.max(yhi, f.a*xlo+f.b, f.a*xhi+f.b); }
    var xt = niceTicks(xlo, xhi, 6), yt = niceTicks(ylo, yhi, 5);
    xlo = xt[0]; xhi = xt[xt.length-1]; ylo = yt[0]; yhi = yt[yt.length-1];
    var W = 860, H = 440, L = 74, R = 22, T = 18, B = 54, pw = W-L-R, ph = H-T-B;
    var X = function(v){return L + (v-xlo)/(xhi-xlo||1)*pw;}, Y = function(v){return T + ph - (v-ylo)/(yhi-ylo||1)*ph;};
    var s = '<svg viewBox="0 0 '+W+' '+H+'" role="img" aria-label="scatter of '+esc(S.names[state.y])+' against '+esc(S.names[state.x])+' with the least-squares line">';
    s += '<g class="grid">'; yt.forEach(function(v){ s += '<line x1="'+L+'" x2="'+(W-R)+'" y1="'+Y(v)+'" y2="'+Y(v)+'"/>'; }); s += '</g>';
    s += '<g class="axis"><line x1="'+L+'" x2="'+(W-R)+'" y1="'+(T+ph)+'" y2="'+(T+ph)+'"/><line x1="'+L+'" x2="'+L+'" y1="'+T+'" y2="'+(T+ph)+'"/>';
    xt.forEach(function(v){ s += '<text x="'+X(v)+'" y="'+(T+ph+18)+'" text-anchor="middle">'+fmt(v)+'</text>'; });
    yt.forEach(function(v){ s += '<text x="'+(L-8)+'" y="'+(Y(v)+4)+'" text-anchor="end">'+fmt(v)+'</text>'; });
    s += '</g>';
    s += '<text class="axname" x="'+(L+pw/2)+'" y="'+(H-10)+'" text-anchor="middle">'+esc(S.names[state.x])+'</text>';
    s += '<text class="axname" transform="translate(16 '+(T+ph/2)+') rotate(-90)" text-anchor="middle">'+esc(S.names[state.y])+'</text>';
    if (f){ s += '<path class="fitline" d="M'+X(xlo)+' '+Y(f.a*xlo+f.b)+' L'+X(xhi)+' '+Y(f.a*xhi+f.b)+'"/>'; }
    rows.forEach(function(r){ var id = S.id(r), ex = !!state.excluded[id];
      s += '<circle class="pt'+(ex?' ex':'')+'" data-id="'+esc(id)+'" cx="'+X(+r[state.x])+'" cy="'+Y(+r[state.y])+'" r="4.2"><title>'+esc(id)+(r.date?' ('+r.date+')':'')+': '+esc(S.names[state.x])+' '+fmt(+r[state.x])+', '+esc(S.names[state.y])+' '+fmt(+r[state.y])+(ex?' (excluded)':'')+'</title></circle>'; });
    s += '</svg>';
    $('chart').innerHTML = s;
    var ex = Object.keys(state.excluded).filter(function(k){return state.excluded[k];});
    if (f){
      $('eq').innerHTML = '<span><span class="k">fit</span><span class="f">'+esc(S.names[state.y])+' = '+fmtEq(f.a)+' · '+esc(S.names[state.x])+(f.b>=0?' + ':' − ')+fmtEq(Math.abs(f.b))+'</span></span>'
        + '<span><span class="k">R²</span>'+f.r2.toFixed(3)+'</span><span><span class="k">n</span>'+f.n+(ex.length?' ('+ex.length+' excluded)':'')+(state.set==='growth'&&state.since?' (from v9.60 on)':'')+'</span>'
        + (f.se!=null ? '<span><span class="k">slope ± se</span>'+fmtEq(f.a)+' ± '+fmtEq(f.se)+'</span>' : '');
      var ux = UNIT[state.x]||S.names[state.x], uy = UNIT[state.y]||S.names[state.y];
      var plain = state.set==='growth' ? 'Across these versions, one more '+ux+' comes with '+fmtEq(f.a)+' more '+uy+(Math.abs(f.a)===1?'':'s')+' on average; the line explains '+(f.r2*100).toFixed(0)+'% of the variation in '+S.names[state.y]+'.'
                : state.set==='atlas' && state.x==='log10_events' && state.y==='log10_render_ms' ? 'In log-log space the slope is the exponent: render time grows about as events^'+fmtEq(f.a)+'. The design answer was a server-side rollup, not a faster render.'
                : 'A line through '+f.n+' points of one table on one machine; it describes the table, not a capacity.'+(state.set==='baseline'&&f.a<0?' The slope is negative because the heavier route was offered the lower rate, not because latency falls under load.':'');
      $('plain').innerHTML = esc(plain) + (S.note ? ' <em>'+esc(S.note)+'.</em>' : '');
      var rs = '<svg viewBox="0 0 '+W+' 90" role="img" aria-label="residuals per point"><g class="resid">';
      var rmax = Math.max.apply(null, f.res.map(Math.abs)) || 1, base = 45, sc = 36/rmax;
      var order = inc.map(function(r,i){return {x:+r[state.x], i:i};}).sort(function(a,b){return a.x-b.x;});
      var bw = Math.max(1, pw/Math.max(1,order.length) - 1);
      s = '<line class="zero" x1="'+L+'" x2="'+(W-R)+'" y1="'+base+'" y2="'+base+'"/>';
      order.forEach(function(o,k){ var v = f.res[o.i], h = Math.abs(v)*sc; s += '<rect class="'+(v<0?'neg':'')+'" x="'+(L + k*(pw/Math.max(1,order.length)))+'" y="'+(v>=0?base-h:base)+'" width="'+bw+'" height="'+h+'"><title>'+esc(S.id(inc[o.i]))+' residual '+fmtEq(v)+'</title></rect>'; });
      rs += s + '</g><text class="axname" x="'+L+'" y="12">residuals, ordered by '+esc(S.names[state.x])+' (largest |r| = '+fmtEq(rmax)+')</text></svg>';
      $('resid').innerHTML = rs;
    } else { $('eq').innerHTML = '<span class="k">no fit: fewer than two distinct x values</span>'; $('plain').textContent = ''; $('resid').innerHTML=''; }
    $('chips').innerHTML = ex.map(function(k){return '<span>'+esc(k)+'</span>';}).join('') || '<span style="color:var(--ink-faint);border-color:var(--line)">none</span>';
    $('reset').disabled = ex.length === 0;
  }
  function fillSelects(){
    var S = SETS[state.set];
    ['x','y'].forEach(function(k){ var sel = $(k); sel.innerHTML = S.dims.map(function(d){return '<option value="'+d+'"'+(state[k]===d?' selected':'')+'>'+esc(S.names[d])+'</option>';}).join(''); });
  }
  function setDataset(name){ state.set = name; $('since-label').hidden = (name !== 'growth'); state.x = SETS[name].def[0]; state.y = SETS[name].def[1]; state.excluded = {}; fillSelects();
    document.querySelectorAll('.tabs button').forEach(function(b){ b.setAttribute('aria-pressed', b.dataset.set===name ? 'true':'false'); }); draw(); }
  $('x').addEventListener('change', function(e){ state.x = e.target.value; draw(); });
  $('y').addEventListener('change', function(e){ state.y = e.target.value; draw(); });
  $('reset').addEventListener('click', function(){ state.excluded = {}; draw(); });
  $('since').addEventListener('change', function(){ state.since = this.checked; state.excluded = {}; draw(); });
  document.querySelectorAll('.tabs button').forEach(function(b){ b.addEventListener('click', function(){ setDataset(b.dataset.set); }); });
  $('chart').addEventListener('click', function(e){ var c = e.target.closest('.pt'); if (!c) return; var id = c.getAttribute('data-id'); state.excluded[id] = !state.excluded[id]; draw(); });
  document.querySelectorAll('.pairs button').forEach(function(b){ b.addEventListener('click', function(){ if (state.set!=='growth') setDataset('growth'); state.x = b.dataset.x; state.y = b.dataset.y; fillSelects(); draw(); }); });
  fillSelects(); draw();
})();
"""


def _pairs_table(fits):
    rows = sorted(fits["simple"], key=lambda s: -s["r2"])
    seen, out = set(), []
    for s in rows:
        key = tuple(sorted((s["x"], s["y"])))
        if key in seen or s["x"] in ("day", "minor") and s["y"] in ("day", "minor"):
            continue
        seen.add(key); out.append(s)
        if len(out) >= 14:
            break
    since = {(s["x"], s["y"]): s for s in (fits.get("since") or {}).get("simple", [])}
    since_tag = (fits.get("since") or {}).get("tag", "")
    tr = "".join('<tr><td><button type="button" data-x="%s" data-y="%s">%s ~ %s</button></td><td class="n">%.3f</td><td class="n">%s</td><td class="n">%.3f</td><td class="n">%s</td></tr>'
                 % (s["x"], s["y"], html.escape(s["y"]), html.escape(s["x"]), s["slope"], "%.1f" % s["intercept"], s["r2"],
                    "%.3f" % since[(s["x"], s["y"])]["r2"] if (s["x"], s["y"]) in since else "") for s in out)
    return ('<div class="tbl pairs"><table><thead><tr><th>y ~ x</th><th class="n">slope</th><th class="n">intercept</th><th class="n">R²</th><th class="n">R² from %s</th></tr></thead>'
            '<tbody>%s</tbody></table></div>' % (html.escape(since_tag), tr))


def _multiple_table(fits):
    tr = []
    for m in fits["multiple"]:
        if "error" in m:
            tr.append('<tr><td>%s</td><td colspan="4">not fitted: %s</td></tr>' % (html.escape(m["y"]), html.escape(m["error"])))
            continue
        coefs = ", ".join("b%d = %.4g" % (i, c) for i, c in enumerate(m["coefficients"]))
        ses = ", ".join("%.3g" % v for v in (m["standard_errors"] or [])) or "n/a"
        tr.append('<tr><td>%s ~ %s</td><td>%s</td><td class="n">%.3f</td><td class="n">%s</td><td>%s</td></tr>'
                  % (html.escape(m["y"]), html.escape(" + ".join(m["x"])), html.escape(coefs), m["r2"],
                     "%.3f" % m["adjusted_r2"] if m["adjusted_r2"] is not None else "n/a", html.escape(ses)))
    return ('<div class="tbl"><table><thead><tr><th>model</th><th>coefficients</th><th class="n">R²</th><th class="n">adj. R²</th><th>standard errors</th></tr></thead>'
            '<tbody>%s</tbody></table></div>' % "".join(tr))


def render_html(dims, fits, full_document=True):
    rows = dims["rows"]
    first, last = rows[0], rows[-1]
    data = json.dumps({"dims": dims, "fits": {k: v for k, v in fits.items() if k != "simple"} | {"simple": fits["simple"]}}, separators=(",", ":")).replace("</", "<\\/")
    body = f"""<title>Polaris as Data</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=IBM+Plex+Sans:wght@400;500&display=swap">
<style>{CSS}</style>
<div class="wrap">
<header>
  <div><h1>Polaris as data</h1>
  <p>Every tagged version of the reference implementation measured the same way, and a least-squares line through whichever two dimensions you choose. The points are the versions; click one to leave it out and watch the fit move.</p></div>
  <div class="prov">
    <span>versions measured<b>{len(rows)}</b></span>
    <span>span<b>{html.escape(first["date"])} to {html.escape(last["date"])}</b></span>
    <span>first tag<b>{html.escape(first["tag"])}</b></span>
    <span>generated from<b>{html.escape(dims.get("generated_from", last["tag"]))}</b></span>
  </div>
</header>
<div class="work">
  <aside class="rail">
    <label>dataset<span class="tabs" role="group" aria-label="dataset">
      <button type="button" data-set="growth" aria-pressed="true">Growth by version</button>
      <button type="button" data-set="baseline" aria-pressed="false">Baseline</button>
      <button type="button" data-set="atlas" aria-pressed="false">Atlas render</button></span></label>
    <label for="x">x<select id="x"></select></label>
    <label for="y">y<select id="y"></select></label>
    <label>excluded points<span class="chips" id="chips"></span></label>
    <label class="since" id="since-label"><input type="checkbox" id="since"> from v9.60 on <small>(after the apparatus and archive removal of v9.55 to v9.59)</small></label>
    <button type="button" id="reset" disabled>Restore every point</button>
    <p class="hint">Growth counts what the tree held at each tag: <code>checks</code> are <code>def check_</code> in the invariant layer, <code>routes</code> are <code>@app.route</code>, <code>tables</code> are <code>CREATE TABLE</code>, <code>tests</code> are <code>def test_</code>. The performance sets are the measured tables of the reference documents, read as printed.</p>
  </aside>
  <section class="stage" aria-live="polite">
    <div class="eq" id="eq"></div>
    <p class="plain" id="plain"></p>
    <div class="chart" id="chart"></div>
    <div class="chart" id="resid"></div>
    <p class="caption">least squares, closed form; the same arithmetic as scripts/polaris-regression.py, recomputed live when a point is excluded</p>
  </section>
</div>
<div class="tables">
  <section><h2>Strongest pairs across the growth data</h2>{_pairs_table(fits)}
    <p class="note">Ranked by R² over all {fits.get("n_versions", len(rows))} versions, with the same pair fitted from {html.escape((fits.get("since") or {}).get("tag", "v9.60"))} on beside it. A high value between two counts records that they were built together, the ship discipline, not a cause; a pair that fits only after the break was pulled apart by the v9.55 removal, not by the work since.</p></section>
  <section><h2>Multiple regression</h2>{_multiple_table(fits)}
    <p class="note">b0 is the intercept, then one coefficient per predictor in the order listed. Adjusted R² penalizes the extra predictors; standard errors are per coefficient.</p></section>
</div>
<footer>A record of this repository and its own measurements on one machine, generated by scripts/polaris-regression.py at {html.escape(fits.get("generated_from", last["tag"]))}. A fit describes these points; it is not a law about identity systems.</footer>
</div>
<script type="application/json" id="polaris-data">{data}</script>
<script>{JS}</script>
"""
    if not full_document:
        return body
    return ('<!doctype html>\n<html lang="en" data-theme="dark">\n<head><link rel="icon" type="image/svg+xml" href="favicon.svg">\n<meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
            '<meta name="description" content="Polaris as data: every tagged version measured, with least-squares fits between its dimensions and through its own performance tables.">\n'
            '</head>\n<body>\n' + body + '\n</body>\n</html>\n')

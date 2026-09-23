"""curved_text.py -- set Russian text along a TikZ path, letter by letter.

TikZ's `text along path` decoration reads its text one token at a time, and under
pdflatex a Cyrillic letter is two bytes, so it fails intermittently depending on
which letters a label contains. Placing each letter as its own node through the
`markings` decoration has no such problem: node text is ordinary LaTeX. The cost
is that TikZ no longer measures the text, so this module does: glyph widths for
each style are measured once by a real pdflatex run and kept in glyph-widths.json.

    python3 tools/curved_text.py measure        # re-measure every style (needs docker)
    from curved_text import along               # generate a markings decoration
"""
import json, pathlib, subprocess, sys, tempfile

HERE = pathlib.Path(__file__).resolve().parent
WIDTHS = HERE / "glyph-widths.json"

#: Style name -> the font switches it stands for. A label must use one of these.
STYLES = {
    "si": r"\scriptsize\itshape",
    "ti": r"\tiny\itshape",
    "sc": r"\scriptsize",
    "tt": r"\tiny\ttfamily",
    "st": r"\scriptsize\ttfamily",
    "fb": r"\footnotesize\bfseries",
    "sb": r"\small\bfseries",
    "kk": r"\scriptsize\scshape",
}
ALPHABET = ("абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"
            "0123456789 .,;:-_+()«»")

def _tex(c):
    return {"_": r"\_", " ": r"\ "}.get(c, c)

def measure():
    lines = [r"\documentclass{article}\usepackage[T2A,T1]{fontenc}\usepackage[utf8]{inputenc}"
             r"\usepackage[english,russian]{babel}", r"\newlength{\w}\begin{document}"]
    chars = list(ALPHABET)
    for key, font in STYLES.items():
        for i, c in enumerate(chars):
            lines.append(r"\settowidth{\w}{{%s %s}}\typeout{W|%s|%d|\the\w}" % (font, _tex(c), key, i)
                         if c == " " else
                         r"\settowidth{\w}{{%s%s}}\typeout{W|%s|%d|\the\w}" % (font, _tex(c), key, i))
    lines.append(r"x\end{document}")
    with tempfile.TemporaryDirectory() as d:
        pathlib.Path(d, "w.tex").write_text("\n".join(lines))
        subprocess.run(["docker", "run", "--rm", "-v", d + ":/w", "-w", "/w", "texlive/texlive:latest",
                        "sh", "-c", "pdflatex -interaction=nonstopmode w.tex >/dev/null 2>&1"])
        log = pathlib.Path(d, "w.log").read_text(errors="replace")
    out = {k: {} for k in STYLES}
    for line in log.splitlines():
        if line.startswith("W|"):
            _, key, i, w = line.split("|")
            out[key][chars[int(i)]] = float(w.replace("pt", ""))
    # a space measured as "\ " inside a group includes nothing else; keep it as measured
    WIDTHS.write_text(json.dumps(out, ensure_ascii=False, indent=0))
    return out

def width(text, style):
    table = json.loads(WIDTHS.read_text())[style]
    return sum(table[c] for c in text)

def along(text, style, color="navydark", lift="0pt"):
    """A `decorate, decoration={markings, ...}` option that sets `text` centred on the path.

    Letters are placed at their measured widths from the path's midpoint and turned to
    the tangent there, so the text follows any curve. `lift` moves it off the path
    (positive is to the left of the direction of travel)."""
    table = json.loads(WIDTHS.read_text())[style]
    font = STYLES[style] + (r"\color{%s}" % color if color else "")
    widths = [table[c] for c in text]
    x = -sum(widths) / 2
    marks = []
    for c, w in zip(text, widths):
        mid = x + w / 2
        x += w
        if c == " ":
            continue
        marks.append(r"mark=at position {0.5*\pgfdecoratedpathlength%+.2fpt} with "
                     r"{\node[transform shape, anchor=base, inner sep=0pt, yshift=%s, font=%s] {%s};}"
                     % (mid, lift, font, _tex(c)))
    return "decorate, decoration={markings, " + ", ".join(marks) + "}"

def arc_label(text, style, angle, radius_cm, color="navydark", lift="-1.6pt", pad_pt=0.0):
    """A \\path that sets `text` along a circle of `radius_cm`, centred on `angle` degrees,
    reading upright: clockwise over the top half, counter-clockwise under it.
    Returns (tikz, half_angle_degrees) so callers can leave a gap of the right size."""
    import math
    r_pt = radius_cm * 28.4527
    half = math.degrees((width(text, style) / 2 + pad_pt) / r_pt) + 0.6
    top = 0 <= (angle % 360) <= 180
    a0, a1 = (angle + half, angle - half) if top else (angle - half, angle + half)
    tikz = (r"\path[%s] (%.2f:%s) arc[start angle=%.2f, end angle=%.2f, radius=%s];"
            % (along(text, style, color, lift if top else lift), a0, radius_cm, a0, a1, radius_cm))
    return tikz, half

if __name__ == "__main__":
    if sys.argv[1:] == ["measure"]:
        w = measure()
        print({k: len(v) for k, v in w.items()})

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-vendor-icons.py: build the console's icon sprite from a Lucide release.

    gh release download 1.49.0 -R lucide-icons/lucide -p "lucide-icons-1.49.0.zip"
    python3 scripts/polaris-vendor-icons.py lucide-icons-1.49.0.zip

Writes polaris_web/static/vendor/lucide/sprite.svg: one <symbol id="i-NAME"> per icon in ICONS,
each icon's own elements unchanged, stroked in `currentColor`; the stroke width, caps and joins
come from the console's `.icon` rule, so one stylesheet sets them for every icon. Only the icons the console uses are carried. The release and its SHA-256 are recorded in
polaris_web/static/vendor/VENDOR.md.
"""
import hashlib
import pathlib
import re
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "polaris_web" / "static" / "vendor" / "lucide" / "sprite.svg"

#: The icons the console uses, by their Lucide 1.49.0 names.
ICONS = sorted({
    "activity", "anchor", "arrow-right", "arrow-right-left", "arrow-up-down", "badge-check", "badge-plus",
    "bell", "book-open", "calendar", "check", "chevron-down", "chevron-left", "chevron-right",
    "circle-check", "circle-question-mark", "circle-x", "clock", "copy", "database", "download",
    "ellipsis", "external-link", "eye", "eye-off", "file-search", "fingerprint-pattern", "funnel",
    "gavel", "globe", "hash", "id-card", "inbox", "info", "key", "key-round", "landmark", "layers",
    "layout-dashboard", "life-buoy", "link-2", "list", "lock", "log-out", "menu", "monitor", "moon",
    "network", "octagon-x", "panel-left", "plus", "power", "refresh-cw", "rotate-ccw-clock",
    "rotate-ccw-key", "scale", "scan-search", "search", "server", "settings", "shield",
    "shield-check", "siren", "sliders-horizontal", "smartphone", "sparkles", "sun", "terminal",
    "triangle-alert", "user-round", "users", "wallet", "x",
})


def body(svg_text):
    """The drawing elements of one Lucide SVG, without the outer <svg>."""
    m = re.search(r"<svg[^>]*>(.*)</svg>", svg_text, re.S)
    if not m:
        sys.exit("not an SVG document: %r" % svg_text[:60])
    return " ".join(line.strip() for line in m.group(1).strip().splitlines())


def main(zip_path):
    data = pathlib.Path(zip_path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    symbols = []
    with zipfile.ZipFile(zip_path) as z:
        names = set(z.namelist())
        for icon in ICONS:
            member = "icons/%s.svg" % icon
            if member not in names:
                sys.exit("not in this Lucide release: %s" % icon)
            symbols.append('<symbol id="i-%s" viewBox="0 0 24 24"><g fill="none" stroke="currentColor">%s</g></symbol>'
                           % (icon, body(z.read(member).decode("utf-8"))))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text('<svg xmlns="http://www.w3.org/2000/svg" aria-hidden="true">\n'
                   "<!-- Lucide icons (ISC License, see LICENSE beside this file), from %s, sha256 %s -->\n"
                   "%s\n</svg>\n" % (pathlib.Path(zip_path).name, digest, "\n".join(symbols)))
    print("%d icons -> %s (%d bytes); release sha256 %s"
          % (len(ICONS), OUT.relative_to(ROOT), OUT.stat().st_size, digest))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])

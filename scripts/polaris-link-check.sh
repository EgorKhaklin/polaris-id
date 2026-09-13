#!/bin/bash
# =============================================================================
# scripts/polaris-link-check.sh — verify every cross-reference resolves
#
# After v8.4 reorganized 9 reference docs into docs/, ~30 cross-references
# in code and Markdown had to be updated by a Python pass. The pass caught
# everything, but the next reorg (or rename, or move) won't necessarily.
#
# This script is the proactive safety net: scan every Markdown link
# `[text](relative/path.md)` and every code reference like `'../X.md'`
# or `'docs/X.md'` for files that don't exist on disk. Run it manually,
# in pre-commit, or as part of CI.
#
# What it does NOT check:
#   - External URLs (http://, https://) — that needs network and a curl pass
#   - Anchors within a file (#section) — would need a HTML / Markdown parser
#   - References inside CHANGELOG.md (historical docs may legitimately
#     reference old names)
# What it DOES check:
#   - Every relative-path Markdown link to a .md / .py / .sh / .sql / .html
#   - Every comment-style reference in code: '# ../X.md', '// ../../Y.md', etc.
#   - Every href= and src= in plain HTML (the published site); Flask templates
#     are skipped, since their attributes are url_for() calls
#   - Every github.com/EgorKhaklin/polaris-id/blob/main/... link, from any file,
#     resolved back to the path it names in this tree
#   - Reports file:line for every broken link
#
# Usage:
#     scripts/polaris-link-check.sh        # human-readable report
#     scripts/polaris-link-check.sh --ci   # fail with exit 1 on any broken link
# =============================================================================

set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT"

if [ -t 1 ]; then
    BOLD="\033[1m"; G="\033[0;32m"; R="\033[0;31m"; DIM="\033[2m"; NC="\033[0m"
else
    BOLD=""; G=""; R=""; DIM=""; NC=""
fi

CI_MODE=0
for arg in "$@"; do
    case "$arg" in
        --ci|-c) CI_MODE=1 ;;
        --help|-h) sed -n '2,28p' "$0" | sed 's/^# \?//'; exit 0 ;;
    esac
done

# -----------------------------------------------------------------------------
# Use Python — the regex/path-resolution logic is fiddly enough that bash
# would be a bug magnet. The script is self-contained; no PYTHONPATH games.
# -----------------------------------------------------------------------------
PYTHON="$(command -v python3)"
[ -x "$PYTHON" ] || { printf "${R}python3 required${NC}\n"; exit 2; }

OUTPUT=$("$PYTHON" - "$ROOT" <<'PY'
import os, re, sys
root = os.path.abspath(sys.argv[1])

# File extensions we scan for references.
SCAN_EXTS = ('.md', '.py', '.sh', '.sql', '.html', '.js', '.css', '.json')
# Reference targets we validate.
TARGET_EXTS = ('.md', '.py', '.sh', '.sql', '.html', '.js', '.css', '.json',
               '.png', '.jpg', '.pdf', '.tex')
# Directories we never scan into.
SKIP_DIRS = {'.git', 'node_modules', 'venv', '__pycache__', '.claude',
             'archive'}  # v9.24: archive/ preserves historical AoR with
                          # paths relative to original (root-level) location;
                          # link-checking from archive/ would always fail.

# Match Markdown link [text](path)  — capture path
MD_LINK = re.compile(r'\]\(([^)]+)\)')
# Match relative path mentions in code:
#   '../X.md', '../../Y.md', './X.md', or just 'X.md' inside a comment
# We require the line to look like a comment (#, //, --) OR a string literal.
#: Directories that hold BUILD OUTPUT, never checked into git. A reference into one
#: is correct and unresolvable at the same time, until something builds it.
BUILD_OUTPUT_DIRS = {'dist', 'build', 'target', 'node_modules', '__pycache__'}
CODE_PATH = re.compile(r'''(?:['\"])(\.{1,2}/[\w./-]+\.(?:md|py|sh|sql|html|js|css|json))(?:['\"])''')
# Match Jinja template paths: {% extends "base.html" %} etc.
JINJA_PATH = re.compile(r"['\"]([\w./-]+\.(?:html|md|css|js))['\"]")
# Match href= and src= in HTML. The published page references its own images
# and stylesheet by relative name; nothing checked those until v9.219. The
# quote characters are written as escapes so this block stays inside a bash
# command substitution without unbalancing its quoting.
HTML_ATTR = re.compile(r"(?:href|src)\s*=\s*([\"\x27])([^\"\x27]+)")
# A link into this repository own tree, written as a github.com blob URL
# because a relative link would 404 on the published site. Strip it back to a
# repo-relative path and check that the path exists.
BLOB_URL = re.compile(r"https://github\.com/EgorKhaklin/polaris-id/blob/main/([^\"\x27#\s>]+)")

# -----------------------------------------------------------------------------
# Collect all reference candidates as (file, line, target_path)
# -----------------------------------------------------------------------------
broken = []
checked = 0

# Files whose comments contain illustrative placeholder paths
# (e.g. "../X.md" as an EXAMPLE, not a real reference).
SELF_REFERENTIAL = {'polaris-link-check.sh'}

for dirpath, dirs, files in os.walk(root):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith('.')]
    for fname in files:
        if not fname.endswith(SCAN_EXTS):
            continue
        # Skip CHANGELOG.md — release-history references can legitimately
        # name files that have since moved or been renamed.
        if fname == 'CHANGELOG.md' and os.path.dirname(os.path.join(dirpath, fname)) == root:
            continue
        if fname in SELF_REFERENTIAL:
            continue
        path = os.path.join(dirpath, fname)
        rel = os.path.relpath(path, root)
        try:
            with open(path, encoding='utf-8') as f:
                lines = f.read().splitlines()
        except Exception:
            continue
        for lineno, line in enumerate(lines, 1):
            # Markdown links
            if fname.endswith('.md'):
                for m in MD_LINK.finditer(line):
                    target = m.group(1).split('#', 1)[0].strip()
                    if not target or target.startswith(('http://', 'https://', 'mailto:', '/')):
                        continue
                    if not target.endswith(TARGET_EXTS) and '.' not in os.path.basename(target):
                        # Could be a directory link like (docs/) — still check
                        pass
                    resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
                    checked += 1
                    if not os.path.exists(resolved):
                        broken.append((rel, lineno, target, 'markdown link'))
            # HTML href/src, for the published page and any other plain HTML.
            # Flask templates are skipped: their attributes are url_for() calls.
            if fname.endswith(".html") and "{{" not in line and "{%" not in line:
                for m in HTML_ATTR.finditer(line):
                    target = m.group(2).strip()
                    if not target or target[0] in ("#", "/"):
                        continue
                    if target.startswith(("http://", "https://", "mailto:", "data:")):
                        continue
                    target = target.split("#", 1)[0].split("?", 1)[0]
                    if not target:
                        continue
                    resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
                    checked += 1
                    if not os.path.exists(resolved):
                        broken.append((rel, lineno, target, "html attribute"))
            # Absolute links into this repository own tree, from any file.
            for m in BLOB_URL.finditer(line):
                target = m.group(1).split("#", 1)[0].rstrip(").,")
                checked += 1
                if not os.path.exists(os.path.join(root, target)):
                    broken.append((rel, lineno, target, "repo blob url"))
            # Code-style relative paths (only those starting with ./ or ../)
            for m in CODE_PATH.finditer(line):
                target = m.group(1)
                resolved = os.path.normpath(os.path.join(os.path.dirname(path), target))
                # A path INTO a build output is not a source path. A package manifest
                # points `main`, `types` and `exports` at compiled output that a fresh
                # checkout has never built, so demanding it exist makes this pass or fail
                # on whether someone happened to run a build. Measured: it passed locally
                # with dist/ present and failed CI on the same commit, which is the wrong
                # way round for a check to behave.
                if any(part in BUILD_OUTPUT_DIRS for part in target.split('/')):
                    continue
                checked += 1
                if not os.path.exists(resolved):
                    broken.append((rel, lineno, target, 'code path'))

print(f"checked: {checked}")
print(f"broken:  {len(broken)}")
for rel, lineno, target, kind in broken:
    print(f"BROKEN\t{rel}:{lineno}\t{kind}\t{target}")
PY
)

checked=$(echo "$OUTPUT" | grep '^checked:' | awk '{print $2}')
broken=$(echo "$OUTPUT" | grep '^broken:'  | awk '{print $2}')

if [ "${broken:-0}" -eq 0 ]; then
    printf "${G}OK${NC}  %s references checked, all resolved\n" "${checked:-0}"
    exit 0
fi

printf "${R}BROKEN${NC}  %s of %s references do not resolve:\n\n" "$broken" "$checked"
echo "$OUTPUT" | grep '^BROKEN' | awk -F'\t' '{ printf "  %-40s  %-12s  %s\n", $2, $3, $4 }'
echo
if [ "$CI_MODE" -eq 1 ]; then
    exit 1
fi
exit 0

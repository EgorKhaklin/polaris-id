#!/usr/bin/env bash
# polaris-release-notes.sh: render the GitHub release body for one version from its
# CHANGELOG.md entry, in the fixed shape every release uses:
#   summary, Breaking changes, Upgrade, Verify this release, Details.
#
# Usage:
#   scripts/polaris-release-notes.sh 9.205            # prints the body to stdout
#   scripts/polaris-release-notes.sh 9.205 > notes.md && gh release create v9.205 --notes-file notes.md
#
# The summary and the item list come from the CHANGELOG block verbatim. The
# Breaking changes section is "None" unless the block contains a line that
# starts with "- **Breaking" (case-insensitive). The Upgrade section names
# the roadmap row when the block's title carries one.
set -euo pipefail
VERSION="${1:?usage: $0 MAJOR.MINOR}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CHANGELOG="${ROOT}/CHANGELOG.md"
REPO="EgorKhaklin/polaris-id"

python3 - "$CHANGELOG" "$VERSION" "$REPO" <<'PY'
import re, sys
path, version, repo = sys.argv[1:4]
import os
block = r"^## v" + re.escape(version) + r" — (\d{4}-\d{2}-\d{2}) \((.*?)\)\n(.*?)(?=^## v|\Z)"
source = "CHANGELOG.md"
text = open(path, encoding="utf-8").read()
m = re.search(block, text, re.M | re.S)
if not m:
    # Older entries move to the archive, split by major, unchanged; a release note for
    # one renders from there.
    archive = os.path.join(os.path.dirname(path), "docs", "history", "CHANGELOG-v%s.md" % version.split(".")[0])
    if os.path.isfile(archive):
        source = "docs/history/" + os.path.basename(archive)
        m = re.search(block, open(archive, encoding="utf-8").read(), re.M | re.S)
if not m:
    sys.exit(f"no CHANGELOG entry for v{version} in CHANGELOG.md or docs/history/")
date, title, body = m.group(1), m.group(2).strip(), m.group(3).strip()
paras = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
summary = next((p for p in paras if not p.startswith("- ")), "")
items = [p for p in paras if p.startswith("- ")]
breaking = [ln for ln in body.splitlines() if re.match(r"^- \*\*breaking", ln, re.I)]
row = re.search(r"\b(P\d+\.\d+)\b", title)
print(f"**{title}**\n")
if summary:
    print(summary + "\n")
print("### Breaking changes\n")
print(("\n".join(breaking) if breaking else "None.") + "\n")
print("### Upgrade\n")
print("Pull the tag, rebuild the images, and run `scripts/polaris-deploy.sh prod` "
      "(the expand-contract migration policy keeps the running app safe during the roll); "
      "on a Linux host, `systemctl restart polaris` after `git pull`. "
      + (f"This release closes roadmap row {row.group(1)}." if row else "")
      + "\n")
print("### Verify this release\n")
print("Every release carries SPDX SBOMs with signed SLSA build provenance "
      "(`sbom-python.spdx.json` and `sbom-image-{app,caddy,pgbouncer,postgres}.spdx.json`, "
      "attached by the sbom workflow after publication):\n")
print("```bash\ngh attestation verify sbom-python.spdx.json --repo " + repo + "\n```\n")
print("### Details\n")
if items:
    print("\n\n".join(items) + "\n")
anchor = "v" + version.replace(".", "") + "-" + date + "-" + re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
print(f"The full entry is in [{source}](https://github.com/{repo}/blob/main/{source}) under `v{version}`, dated {date}.")
PY

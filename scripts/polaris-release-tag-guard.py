#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-release-tag-guard.py: a publish never moves a published release tag.

    python3 scripts/polaris-release-tag-guard.py --repo OWNER/polaris-NAME --tag vX.Y.Z \\
        --amd64 sha256:... --arm64 sha256:...
    python3 scripts/polaris-release-tag-guard.py --dry --repo OWNER/polaris-NAME \\
        (--tag vX.Y.Z | --version-file polaris_web/__version__.py)

release-images.yml joins each image's two architectures under the release tag with
`docker buildx imagetools create -t`, and the registry moves a tag that already exists without
a word. So the publish job runs this first, against ghcr.io, and acts on what the tag is now:

  absent (404 MANIFEST_UNKNOWN or NAME_UNKNOWN)    proceed: the tag's first publish
  an index of exactly this run's two digests       proceed: "Re-run failed jobs" in the run
                                                   that published it reuses its build digests
  anything else under the tag                      refuse: a published tag never moves
  any other answer (a refused token, 401, 403,     refuse: a re-run is cheap, and a moved tag
  5xx, a body that is not an index)                cannot be taken back

A change to what was built is a new version, never a second publish of the same tag
(docs/RELEASING.md). Exit 0 to proceed, 1 to refuse, 2 for a usage error. With --dry it reads
the tag the same way, reports what a publish would meet, and exits 0: the dry run of
release-images.yml runs it before the tag exists, on the credentials the publish job uses.

GHCR_USER and GHCR_TOKEN (the workflow's GITHUB_TOKEN) are sent to ghcr.io's token endpoint, as
`docker login` does; without them the read is anonymous.
"""
import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

REGISTRY = "ghcr.io"
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPO = re.compile(r"^[a-z0-9._-]+(?:/[a-z0-9._-]+)+$")
_TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?$")
_INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json")
_ACCEPT = ", ".join(_INDEX_TYPES + ("application/vnd.oci.image.manifest.v1+json",
                                    "application/vnd.docker.distribution.manifest.v2+json"))


def http_get(url, headers):
    """GET url; return (status, body). A transport failure is status 0."""
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, OSError) as e:
        return 0, str(e).encode()


def _error_codes(body):
    try:
        return {e.get("code") for e in json.loads(body).get("errors", []) if isinstance(e, dict)}
    except (ValueError, AttributeError):
        return set()


def read_tag(repo, tag, get=http_get, user="", token=""):
    """What the registry holds under repo:tag: ("absent", None), ("present", index), or
    ("error", reason). Only an index body counts as present; every other answer is an error."""
    scope = urllib.parse.quote(f"repository:{repo}:pull", safe=":/")
    headers = {}
    if user and token:
        headers["Authorization"] = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
    status, body = get(f"https://{REGISTRY}/token?service={REGISTRY}&scope={scope}", headers)
    try:
        bearer = json.loads(body).get("token", "") if status == 200 else ""
    except (ValueError, AttributeError):
        bearer = ""
    if not bearer:
        return "error", f"the token endpoint answered {status} with no token"
    status, body = get(f"https://{REGISTRY}/v2/{repo}/manifests/{tag}",
                       {"Authorization": f"Bearer {bearer}", "Accept": _ACCEPT})
    if status == 404:
        codes = _error_codes(body)
        if codes & {"MANIFEST_UNKNOWN", "NAME_UNKNOWN"}:
            return "absent", None
        return "error", f"404 without a registry error code ({sorted(c for c in codes if c) or 'none'})"
    if status != 200:
        codes = sorted(c for c in _error_codes(body) if c)
        return "error", f"the registry answered {status}" + (f" ({', '.join(codes)})" if codes else "")
    try:
        index = json.loads(body)
    except ValueError:
        return "error", "the registry answered 200 with a body that is not JSON"
    if not isinstance(index, dict) or index.get("mediaType") not in _INDEX_TYPES:
        return "error", "the tag names something other than an image index"
    return "present", index


def children(index):
    """The index's manifests as {"os/arch": digest}, or None when two entries share a platform
    or one has no digest. The arm64 entry may carry the variant v8; it is still linux/arm64."""
    out = {}
    for m in index.get("manifests") or []:
        p = m.get("platform") or {}
        key = f"{p.get('os')}/{p.get('architecture')}"
        if key in out or not _DIGEST.match(m.get("digest") or ""):
            return None
        out[key] = m["digest"]
    return out or None


def decide(state, detail, amd64, arm64):
    """(exit code, message) for a publish of amd64 + arm64 under the tag."""
    if state == "absent":
        return 0, "proceed: the tag is absent, so this is its first publish"
    if state == "present":
        kids = children(detail)
        built = {"linux/amd64": amd64, "linux/arm64": arm64}
        if kids == built:
            return 0, ("proceed: the tag already names this run's two digests, so this is a re-run "
                       "of the run that published it")
        return 1, (f"refuse: the tag is published as {kids or 'an index this guard cannot read'}, "
                   f"and this run built {built}. A published tag never moves: re-run the failed "
                   "jobs of the run that published it, or release the change as a new version")
    return 1, f"refuse: the tag could not be read ({detail}); a re-run is cheap, a moved tag is not"


def describe(state, detail):
    """The dry run's report: what a publish would meet."""
    if state == "absent":
        return "would publish to an absent tag"
    if state == "present":
        return (f"the tag is published as {children(detail) or 'an index this guard cannot read'}; "
                "a publish would proceed only as a re-run of the run that published it")
    return f"cannot read the tag ({detail}); a publish refuses on this answer"


def version_tag(path):
    m = re.search(r'^__version__\s*(?::\s*str\s*)?=\s*"([^"]+)"', open(path).read(), re.M)
    return "v" + m.group(1) if m else ""


def main(argv=None, get=http_get, env=None):
    env = os.environ if env is None else env
    ap = argparse.ArgumentParser(description=(__doc__ or "").split("\n")[0])
    ap.add_argument("--repo", required=True, help="OWNER/polaris-NAME on ghcr.io")
    ap.add_argument("--tag", default="")
    ap.add_argument("--version-file", default="", help="--dry only: the tag is v + __version__")
    ap.add_argument("--amd64", default="")
    ap.add_argument("--arm64", default="")
    ap.add_argument("--dry", action="store_true")
    a = ap.parse_args(argv)
    tag = a.tag
    if a.version_file and not tag:
        if not a.dry:
            print("usage: --version-file is for --dry; a publish names its tag", file=sys.stderr)
            return 2
        tag = version_tag(a.version_file)
    if not _REPO.match(a.repo) or not _TAG.match(tag):
        print(f"usage: a repository OWNER/NAME and a release tag vX.Y.Z, got {a.repo!r} {tag!r}",
              file=sys.stderr)
        return 2
    if not a.dry and not (_DIGEST.match(a.amd64) and _DIGEST.match(a.arm64)):
        print(f"usage: a publish names both digests it built, got {a.amd64!r} {a.arm64!r}",
              file=sys.stderr)
        return 2
    state, detail = read_tag(a.repo, tag, get, env.get("GHCR_USER", ""), env.get("GHCR_TOKEN", ""))
    where = f"{REGISTRY}/{a.repo}:{tag}"
    if a.dry:
        print(f"{where}: {describe(state, detail)}")
        return 0
    code, message = decide(state, detail, a.amd64, a.arm64)
    print(f"{where}: {message}", file=sys.stderr if code else sys.stdout)
    return code


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-pin-chart-images.py: point the Helm chart's self-built images at signed digests.

    python3 scripts/polaris-pin-chart-images.py deploy/helm/polaris/values.yaml INDEX_DIR

INDEX_DIR holds one file per image (app, caddy, pgbouncer, postgres), each containing the
published reference ``ghcr.io/<owner>/polaris-<name>@sha256:<digest>``, as the release-images
workflow writes them (lab record 017, phase 3). Each `images.<name>:` line in values.yaml is
replaced with that reference, so the published chart pulls exactly the images that were signed.
Refuses (exit 2) when a reference is malformed or a chart image has no published reference: a
chart half-pinned to local tags would install images nobody signed.
"""
import pathlib
import re
import sys

CHART_IMAGES = ("app", "caddy", "pgbouncer", "postgres")
_REF = re.compile(r"^ghcr\.io/[a-z0-9._-]+/polaris-([a-z0-9-]+)@sha256:[0-9a-f]{64}$")


def pin(values_text: str, refs: dict) -> str:
    out, seen, in_images = [], set(), False
    for line in values_text.splitlines(keepends=True):
        if re.match(r"^images:\s*$", line):
            in_images = True
        elif in_images and re.match(r"^\S", line):
            in_images = False
        m = re.match(r"^(  )([a-z]+):\s*\S.*$", line) if in_images else None
        if m and m.group(2) in CHART_IMAGES:
            name = m.group(2)
            line = f"{m.group(1)}{name}: {refs[name]}\n"
            seen.add(name)
        out.append(line)
    missing = set(CHART_IMAGES) - seen
    if missing:
        raise ValueError("values.yaml has no images entry for: " + ", ".join(sorted(missing)))
    return "".join(out)


def read_refs(index_dir: pathlib.Path) -> dict:
    refs = {}
    for name in CHART_IMAGES:
        f = index_dir / name
        if not f.is_file():
            raise ValueError(f"no published reference for {name} in {index_dir}")
        ref = f.read_text().strip()
        m = _REF.match(ref)
        if not m or m.group(1) != name:
            raise ValueError(f"{name}: {ref!r} is not a ghcr.io/<owner>/polaris-{name}@sha256 reference")
        refs[name] = ref
    return refs


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 2:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 64
    values, index_dir = pathlib.Path(argv[0]), pathlib.Path(argv[1])
    try:
        pinned = pin(values.read_text(), read_refs(index_dir))
    except ValueError as exc:
        print(f"polaris-pin-chart-images: {exc}", file=sys.stderr)
        return 2
    values.write_text(pinned)
    for name in CHART_IMAGES:
        print(f"pinned {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

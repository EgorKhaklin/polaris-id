#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""The secret files a stack mounts, read from `docker compose config --format json` on stdin.

polaris-deploy.sh's pre-flight reads it, and CI reads it over the HA, DR and blue-green overlays.
SECRETS_DIR (argv[1]) is the secrets directory: every file a service mounts as a secret, and every
file bind-mounted from SECRETS_DIR, is printed as `FILE <path>`. A secret that names no file, or a
service's *_FILE setting naming a /run/secrets file the service does not mount, is printed as
`BAD <why>`; either, or a stack that mounts nothing, exits 3.

    docker compose -f docker-compose.prod.yml config --format json | polaris_stack_secrets.py SECRETS_DIR
"""
import json, os, sys
cfg = json.load(sys.stdin)
sdir = os.path.realpath(sys.argv[1])
top = cfg.get("secrets") or {}
need, bad = set(), []
for svc_name, svc in sorted((cfg.get("services") or {}).items()):
    mounted = set()
    for s in svc.get("secrets") or []:
        src = s.get("source") if isinstance(s, dict) else s
        tgt = (s.get("target") if isinstance(s, dict) else None) or src
        mounted.add(tgt if tgt.startswith("/") else "/run/secrets/" + tgt)
        f = (top.get(src) or {}).get("file")
        if not f:
            bad.append("%s mounts secret %s, which names no file" % (svc_name, src))
        else:
            need.add(f)
    for k, v in sorted((svc.get("environment") or {}).items()):
        if k.endswith("_FILE") and isinstance(v, str) and v.startswith("/run/secrets/") and v not in mounted:
            bad.append("%s sets %s=%s, a secret it does not mount" % (svc_name, k, v))
    for v in svc.get("volumes") or []:
        if isinstance(v, dict) and v.get("type") == "bind":
            src = v.get("source") or ""
            if os.path.realpath(src).startswith(sdir + os.sep):
                need.add(src)
for b in bad:
    print("BAD " + b)
for f in sorted(need):
    print("FILE " + f)
if bad or not need:
    sys.exit(3)

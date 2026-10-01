# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""Time every console page against one database, signed in as a role (lab/strategy/008).

    POLARIS_DB_NAME=polaris_scale python lab/strategy/008/bench.py [--role admin] [--runs 3] [--only SUBSTR]

Prints: path, HTTP status, median server time over the runs, response size. In-process
(Flask test client), so the time is the application and the database, not the network.
"""
import os
import statistics
import sys
import time

sys.path.insert(0, os.environ.get("POLARIS_WEB_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "polaris_web"))
os.environ.setdefault("POLARIS_PQC_PROFILE", "placeholder")
os.environ.setdefault("POLARIS_SECRET_KEY", "bench-secret-key-32-bytes-long-xxxxx")
import app as polaris  # noqa: E402

args = sys.argv[1:]
role = args[args.index("--role") + 1] if "--role" in args else "admin"
runs = int(args[args.index("--runs") + 1]) if "--runs" in args else 3
only = args[args.index("--only") + 1] if "--only" in args else None
PASSWORDS = {"admin": "Admin@123!", "operator": "Operator@123!", "auditor": "Auditor@123!"}

polaris.app.config["TESTING"] = True
client = polaris.app.test_client()
r = client.post("/login", data={"username": role, "password": PASSWORDS[role]})
assert r.status_code == 302, ("login failed", r.status_code, r.get_data(as_text=True)[:300])

q = polaris.query
max_tok = q("SELECT max(token_id) AS m FROM IdentityToken", fetch="one")["m"]
max_ind = q("SELECT max(individual_id) AS m FROM Individual", fetch="one")["m"]
rec = q("SELECT max(recovery_id) AS m FROM RecoveryRequest", fetch="one")["m"]

PAGES = [
    "/dashboard",
    "/tokens", "/tokens?status=ACTIVE", "/tokens?page=2", "/tokens?page=5000",
    "/tokens/1", "/tokens/%d" % max_tok,
    "/investigate/token/%d" % max_tok,
    "/individuals", "/individuals?page=5000", "/individuals?q=Person+1234567",
    "/individuals/%d/edit" % max_ind, "/investigate/individual/%d" % max_ind,
    "/individuals/enrollment",
    "/agencies", "/agencies/1/edit",
    "/verifications", "/verifications?page=5000", "/verifications/new",
    "/anchors", "/epochs", "/epochs?epoch_id=1", "/federation",
    "/duress", "/sql",
    "/uc1/issue", "/uc4/activate-reserve", "/uc5/bind-device", "/uc6/migrate",
    "/uc7/warrant-audit", "/uc8/revoke", "/uc9/queue", "/uc9/initiate-recovery",
    "/atlas", "/athena", "/settings/webauthn",
]
if rec:
    PAGES.append("/uc9/decide/%d" % rec)

print("%-44s %6s %10s %10s" % ("page", "status", "median ms", "KB"))
for path in PAGES:
    if only and only not in path:
        continue
    times, status, size = [], None, 0
    for i in range(runs + 1):
        t0 = time.perf_counter()
        resp = client.get(path)
        dt = (time.perf_counter() - t0) * 1000
        status, size = resp.status_code, len(resp.data)
        if i:  # the first request warms the caches
            times.append(dt)
        if dt > 120000:
            break
    print("%-44s %6s %10.1f %10.1f" % (path, status, statistics.median(times) if times else dt, size / 1024), flush=True)

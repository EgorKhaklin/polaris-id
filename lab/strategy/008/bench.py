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
# Step 2: the forms open on one record. The newest active credential and its holder.
act = q("SELECT t.token_id, t.token_value, t.physical_serial, t.individual_id, i.legal_name, "
        "i.date_of_birth FROM IdentityToken t JOIN Individual i USING (individual_id) "
        "WHERE t.status = 'ACTIVE' ORDER BY t.token_id DESC LIMIT 1", fetch="one")

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
PAGES += ["/uc4/activate-reserve?token_id=%d" % act["token_id"],
          "/uc5/bind-device?token_id=%d" % act["token_id"],
          "/uc6/migrate?token_id=%d" % act["token_id"],
          "/uc8/revoke?token_id=%d" % act["token_id"],
          "/verifications/new?token_id=%d" % act["token_id"],
          "/uc7/warrant-audit?individual_id=%d" % act["individual_id"],
          "/uc9/initiate-recovery?individual_id=%d" % act["individual_id"]]

# Step 3: the lists by key and deep, a rare and a common filter, the log filtered by one
# credential, and the record pages of the newest credential and its holder.
PAGES += ["/tokens?cursor=%d" % (max_tok - 1000), "/individuals?cursor=%d" % (max_ind - 1000),
          "/verifications?outcome=UNAUTHORIZED", "/verifications?outcome=FAILURE",
          "/verifications?token_id=%d" % act["token_id"]]

# The lookups are POSTs: (label, path, form). The search text travels in the body.
csrf_page = client.get("/uc8/revoke").get_data(as_text=True)
csrf = csrf_page.split('name="csrf_token" value="', 1)[1].split('"', 1)[0] if 'name="csrf_token"' in csrf_page else ""
POSTS = [
    ("find credential by number", "/find/credential", {"credential": str(act["token_id"]), "next": "uc8_revoke"}),
    ("find credential by value", "/find/credential", {"credential": act["token_value"], "next": "uc8_revoke"}),
    ("find credential by serial", "/find/credential", {"credential": act["physical_serial"], "next": "uc8_revoke"}),
    ("find person by name and birth date", "/find/person",
     {"person": act["legal_name"][:6], "born": act["date_of_birth"].isoformat(), "next": "uc9_initiate"}),
]

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

for label, path, form in POSTS:
    if only and only not in path and only not in label:
        continue
    times, status, size = [], None, 0
    for i in range(runs + 1):
        t0 = time.perf_counter()
        resp = client.post(path, data=dict(form, csrf_token=csrf))
        dt = (time.perf_counter() - t0) * 1000
        status, size = resp.status_code, len(resp.data)
        if i:
            times.append(dt)
    print("%-44s %6s %10.1f %10.1f" % ("POST " + label, status, statistics.median(times) if times else dt, size / 1024), flush=True)

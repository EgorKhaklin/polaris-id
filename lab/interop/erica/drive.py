# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""drive.py -- ERICA's HTTP API, called the way its web UI calls it.

ERICA has no command line; its UI is a page over two endpoints, and this calls them:
`POST /api/parse-url` (ERICA fetches the request object from the launch URI's request_uri and
checks it) and then `POST /api/debug` (ERICA validates the request against a profile, runs its
wallet simulator in one mode and, with postResponseToUri, posts the encrypted response to the
verifier's response_uri). Standard library only.

  drive.py present ERICA_URL LAUNCH_URI MODE TEMPLATE OUT.json   # parse, simulate, post
  drive.py validate ERICA_URL LAUNCH_URI OUT.json                # parse and validate only
  drive.py findings OUT.json...                                  # every check that failed

`present` prints one line a caller can match: REQUEST REFUSED (ERICA would not take the
request), DISPATCHED (the verifier answered 2xx), DISPATCH FAILED (it did not), or SIMULATION
FAILED (ERICA built no response).
"""
import json
import sys
import urllib.request


def _post(base, path, body):
    req = urllib.request.Request(base.rstrip("/") + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.load(resp)


def _parse(base, uri):
    parsed = _post(base, "/api/parse-url", {"url": uri})
    data = parsed.get("data") or {}
    return parsed, data


def present(base, uri, mode, template, out, post=True):
    parsed, data = _parse(base, uri)
    record = {"launch_uri": uri, "mode": mode, "template": template, "parse": data}
    if not parsed.get("success") or not data.get("request"):
        json.dump(record, open(out, "w"), indent=1, ensure_ascii=False)
        print("REQUEST REFUSED %s" % "; ".join(data.get("errors") or ["no request"]))
        return
    # The body the UI's test mode sends (web/src/hooks/useTestExecution.ts).
    debug = _post(base, "/api/debug", {
        "request": data["request"], "validationProfile": "pid-presentation",
        "simulationMode": mode, "pidTemplate": template, "postResponseToUri": post,
        "preferredFormat": "dc+sd-jwt"})
    record["debug"] = debug
    json.dump(record, open(out, "w"), indent=1, ensure_ascii=False)
    session = debug.get("data") or {}
    simulated = session.get("simulatedResponse") or {}
    if not debug.get("success") or simulated.get("success") is False:
        print("SIMULATION FAILED %s" % (simulated.get("error") or debug.get("error")))
        return
    if not post:
        print("VALIDATED")
        return
    result = simulated.get("postResult") or {}
    if result.get("success"):
        print("DISPATCHED %s HTTP %s" % (mode, result.get("statusCode")))
    else:
        print("DISPATCH FAILED %s %s" % (mode, result.get("error")))


def _failed(checks, stage):
    for check in checks or []:
        if not check.get("passed"):
            yield stage, check


def findings(paths):
    """Every check that failed in the parse and request-validation stages, verbatim, once each,
    then ERICA's own verdict on the request."""
    seen = set()
    for path in paths:
        record = json.load(open(path))
        session = ((record.get("debug") or {}).get("data") or {})
        validation = session.get("requestValidation") or {}
        rows = list(_failed((record.get("parse") or {}).get("checks"), "parse-url"))
        rows += list(_failed(validation.get("checks"), "request"))
        for stage, check in rows:
            key = (stage, check.get("checkId"), check.get("issue"), check.get("details"))
            if key in seen:
                continue
            seen.add(key)
            print("%s %s %s (%s, %s)" % (check.get("severity"), stage, check.get("checkId"),
                                         check.get("checkName"), check.get("category")))
            for label, name in (("issue", "issue"), ("details", "details"),
                                ("field", "field"), ("expected", "expectedValue"),
                                ("actual", "actualValue"), ("fix", "suggestedFix")):
                if check.get(name):
                    print("    %-8s %s" % (label, check[name]))
            ref = check.get("specReference") or {}
            if ref:
                print("    %-8s %s" % ("spec", " ".join(str(ref[k]) for k in ("spec", "section", "url")
                                                     if ref.get(k))))
        if validation:
            summary = validation.get("summary") or {}
            print("verdict  valid=%s, %s of %s request checks passed, %s error(s), %s warning(s)"
                  % (validation.get("valid"), summary.get("passedChecks"), summary.get("totalChecks"),
                     summary.get("errorCount"), summary.get("warningCount")))
            parse = (record.get("parse") or {}).get("checks") or []
            print("         %s of %s parse-url checks passed"
                  % (sum(1 for c in parse if c.get("passed")), len(parse)))


def main(argv):
    if len(argv) >= 6 and argv[0] == "present":
        present(*argv[1:6])
    elif len(argv) == 4 and argv[0] == "validate":
        present(argv[1], argv[2], "VALID", "normal", argv[3], post=False)
    elif len(argv) >= 2 and argv[0] == "findings":
        findings(argv[1:])
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

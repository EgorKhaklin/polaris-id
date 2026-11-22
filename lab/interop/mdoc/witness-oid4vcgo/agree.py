#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""agree.py -- the Annex C agreement table: each row of annexc-rows.json judged by two verifiers at the
rows' instant, this repository's polaris_oid4vp (here) and OID4VCgo's mdocdcapi.VerifyResponse
(annexc/main.go, which run.sh runs into OUT/annexc.jsonl).

    python3 -I lab/interop/mdoc/witness-oid4vcgo/agree.py OUT/annexc.jsonl [ROWS]

Prints one line per row with both verdicts and the SHA-256 of the response as presented (its
base64url text), each refusal's reason under it, then each window row judged again at the run date,
then the counts. Exits 1 unless:

  - every row has one verdict from each verifier, each the row's `expect`, an accepted row's claims
    the row's on both sides;
  - each refusal comes from the stage the row names (STAGES), on both sides;
  - each outside row is a faithful copy of its file, and the file is the one its SHA-256 names;
  - each window row's dates separate the instant from the run date by construction, and both
    verifiers, judging it again at the run date, give the other verdict: the row valid at the
    instant is refused there, at its document signer's validity, the only date of the row the run
    date falls outside; the row not yet valid at the instant is accepted there;
  - each control was made from a row both verifiers accept, so its refusal comes from the one thing
    it changes.

A row where the verifiers disagree is a finding about one of them, reported here and never settled by
editing the row.

Our verdict is annexc.open_response's two steps with `now` given: annexc._open, then
mdoc.verify_device_response(..., now=the instant). open_response itself judges at the verifier's
clock. A row whose `session` is "fields" is opened under a Session set field by field, as
test_annex_c.py's bare_session sets one: annexc.Session refuses a key its EncryptionInfo does not
carry, and the point of such a row is that the open tries one. ours() needs cryptography
(lab/interop/requirements.txt); judge() and read_theirs() need nothing, and test_agree.py holds them.
"""
import base64
import datetime
import hashlib
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
ROWS = HERE / "annexc-rows.json"
UTC = datetime.timezone.utc
OURS, THEIRS = "Polaris", "OID4VCgo"
OUTCOMES = ("accepted", "refused")
INSTANT, RUN_DATE = "instant", "run_date"
#: The rows the table is for (decision record 025, M4); without one of them it says less than it is read to say.
REQUIRED = ("ANNEXC-DETERMINISTIC-001", "ANNEXC-REAL-001", "MINTED-VALID-AT-INSTANT", "MINTED-DS-NOT-YET-VALID",
            "CONTROL-ANOTHER-ORIGIN", "CONTROL-ANOTHER-KEY", "CONTROL-FLIPPED-CIPHERTEXT")
#: The stage a refused row names, as each verifier reports it: our refusal code and a phrase of our reason,
#: then a phrase of OID4VCgo's error (mdocdcapi/response.go at the pinned version).
STAGES = {
    "open": ("hpke", "does not open", "mdocdcapi: decrypt the response: "),
    "document": ("malformed", "no documents", "mdocdcapi: oid4vpmdoc: unmarshal device response: "),
    "document_signer_validity": ("issuer_key", "outside its validity period",
                                 "certificate has expired or is not yet valid"),
}
#: An outside row's fields, each with the path of the vector file's member it copies.
COPIED = (("origin", ("origin",)), ("encryption_info", ("encryptionInfoB64",)),
          ("response", ("encryptedResponseB64",)), ("doctype", ("expected", "docType")))


def instant(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def stamp(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_theirs(path):
    """OID4VCgo's verdicts by row id, at the instant and at the run date, and what is wrong with the file."""
    verdicts, problems = {INSTANT: {}, RUN_DATE: {}}, []
    with open(path) as handle:
        for n, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                verdict = json.loads(line)
                row_id, when = verdict["id"], verdict["when"]
                judged = verdicts[when]
            except (ValueError, KeyError, TypeError):
                problems.append("%s line %d is not a verdict line" % (path, n))
                continue
            if row_id in judged:
                problems.append("%s judged %s twice at the %s" % (path, row_id, when.replace("_", " ")))
            judged[row_id] = verdict
    if not verdicts[INSTANT] and not problems:
        problems.append("%s holds no verdict" % path)
    return verdicts, problems


def ours(fixture, when=None, only=None):
    """This repository's verdicts by row id, at `when` (default the rows' instant), for the rows `only` names."""
    sys.path.insert(0, str(REPO / "packages" / "polaris-oid4vp"))
    from cryptography.hazmat.primitives.asymmetric import ec
    from polaris_oid4vp import annexc, mdoc

    now = (when or instant(fixture["at"])).timestamp()
    roots = [mdoc.IacaRoot(base64.b64decode(fixture["iaca_der_b64"]), fixture["iaca_doctypes"])]
    verdicts = {}
    for row in fixture["rows"]:
        if only is not None and row["id"] not in only:
            continue
        try:
            key = ec.derive_private_key(int(row["recipient_key_hex"], 16), ec.SECP256R1())
            if row["session"] == "Session":
                session = annexc.Session(origin=row["origin"], encryption_info=row["encryption_info"],
                                         recipient_key=key, doctype=row["doctype"], namespaces=row["elements"])
            elif row["session"] == "fields":
                session = object.__new__(annexc.Session)
                session.origin = row["origin"]
                session.encryption_info = row["encryption_info"]
                session.transcript = annexc.session_transcript(row["encryption_info"], row["origin"])
                session.doctype = row["doctype"]
                session.namespaces = row["elements"]
                session._recipient_key = key
            else:
                raise ValueError("session %r is neither Session nor fields" % row["session"])
        except Exception as exc:  # a row this harness cannot set up is never a verdict
            verdicts[row["id"]] = {"outcome": "error", "error": "%s: %s" % (type(exc).__name__, exc)}
            continue
        try:
            device_response = annexc._open(row["response"], session)
        except annexc._Refused as refusal:
            verdicts[row["id"]] = {"outcome": "refused", "code": refusal.code, "error": refusal.reason}
            continue
        verdict = mdoc.verify_device_response(device_response, session_transcript=session.transcript,
                                              iaca_roots=roots, doctype=session.doctype, now=now,
                                              max_skew_seconds=fixture["max_skew_seconds"])
        if verdict.authentic:
            verdicts[row["id"]] = {"outcome": "accepted", "claims": verdict.claims}
        else:
            verdicts[row["id"]] = {"outcome": "refused", "code": verdict.code, "error": verdict.reason}
    return verdicts


def _outside_problems(row, repo):
    source = row.get("source") or {}
    path = (repo / str(source.get("path") or "")).resolve()
    if pathlib.Path(repo).resolve() not in path.parents or not path.is_file():
        return ["%s copies no file this tree holds (%r)" % (row["id"], source.get("path"))]
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != source.get("sha256"):
        return ["%s's file %s is not the one its SHA-256 names" % (row["id"], source["path"])]
    vector, problems = json.loads(raw), []
    for field, member in COPIED:
        value = vector
        for name in member:
            value = value.get(name) if isinstance(value, dict) else None
        if row.get(field) != value or value is None:
            problems.append("%s's %s is not its file's %s" % (row["id"], field, ".".join(member)))
    try:
        same_key = int(row["recipient_key_hex"], 16) == int(vector["recipientPrivateKeyHex"], 16)
    except (KeyError, TypeError, ValueError):
        same_key = False
    if not same_key:
        problems.append("%s's recipient key is not its file's recipientPrivateKeyHex" % row["id"])
    asked = sorted(e for names in (row.get("elements") or {}).values() for e in names)
    if asked != [(vector.get("expected") or {}).get("requestedElement")]:
        problems.append("%s asks for %s, not its file's requestedElement" % (row["id"], asked))
    return problems


def _window_problems(row, at, today):
    """The row's own dates must make it one verdict at the instant and the other on the run date."""
    try:
        ds, mso = row["document_signer"], row["mso"]
        ds_from, ds_until = instant(ds["not_before"]), instant(ds["not_after"])
        signed, mso_from, mso_until = instant(mso["signed"]), instant(mso["valid_from"]), instant(mso["valid_until"])
    except (KeyError, TypeError, ValueError):
        return ["%s states no document signer or MSO window" % row["id"]]
    if not (ds_from <= signed <= ds_until and signed <= mso_from < mso_until):
        return ["%s's dates are out of order: the MSO must be signed inside the document signer's validity, at "
                "or before its own validity starts, and its validity must end after it starts" % row["id"]]
    if row.get("expect") == "accepted" and not (ds_from <= at < ds_until < today and mso_from <= at
                                                and today < mso_until):
        return ["%s no longer separates the instant from the run date: its document signer and MSO must be valid at "
                "%s, and on %s only its document signer expired" % (row["id"], stamp(at), today.strftime("%Y-%m-%d"))]
    if row.get("expect") == "refused" and not (at < ds_from <= mso_from <= today < min(ds_until, mso_until)):
        return ["%s no longer separates the instant from the run date: its document signer must start after %s and "
                "it must be valid on %s" % (row["id"], stamp(at), today.strftime("%Y-%m-%d"))]
    return []


def _stage_problems(row_id, stage, side, verdict):
    expected = STAGES.get(stage)
    if expected is None:
        return ["%s names no stage it is refused at (%r)" % (row_id, stage)]
    code, ours_says, theirs_says = expected
    if side == OURS and (verdict.get("code") != code or ours_says not in verdict.get("error", "")):
        return ["%s: %s refused it at %s, not at %s" % (row_id, side, _reason(verdict), stage)]
    if side == THEIRS and theirs_says not in verdict.get("error", ""):
        return ["%s: %s refused it with %r, not at %s" % (row_id, side, verdict.get("error", ""), stage)]
    return []


def _reason(verdict):
    if verdict.get("code"):
        return "%s: %s" % (verdict["code"], verdict.get("error", ""))
    return verdict.get("error", "")


def judge(fixture, our_verdicts, their_verdicts, today, repo=REPO, our_run_date=None, their_run_date=None):
    """(the table's lines, the problems): see the module docstring."""
    lines, problems = [], []
    our_run_date, their_run_date = our_run_date or {}, their_run_date or {}
    rows = fixture.get("rows") or []
    if not rows:
        problems.append("the rows file holds no row")
    ids = [row.get("id") for row in rows]
    problems += ["no row %s" % row_id for row_id in REQUIRED if row_id not in ids]
    problems += ["two rows are %s" % row_id for row_id in sorted({i for i in ids if ids.count(i) > 1})]
    for side, verdicts in ((OURS, our_verdicts), (THEIRS, their_verdicts)):
        problems += ["%s judged %s, which the rows file does not hold" % (side, row_id)
                     for row_id in sorted(set(verdicts) - set(ids))]
    try:
        at = instant(fixture["at"])
    except (KeyError, TypeError, ValueError):
        return lines, problems + ["the rows file names no instant"]
    by_id = {row.get("id"): row for row in rows}
    agreed = as_expected = 0
    windows = []
    for row in rows:
        row_id, expect = row.get("id"), row.get("expect")
        if expect not in OUTCOMES:
            problems.append("%s expects %r" % (row_id, expect))
        if expect == "accepted" and not row.get("claims"):
            problems.append("%s expects acceptance and states no claims" % row_id)
        mine, theirs = our_verdicts.get(row_id), their_verdicts.get(row_id)
        sha = hashlib.sha256(str(row.get("response", "")).encode("ascii")).hexdigest()
        lines.append("ROW %-27s expect %-8s %s %-8s %s %-8s sha256 %s" % (
            row_id, expect, OURS, (mine or {}).get("outcome", "-"), THEIRS, (theirs or {}).get("outcome", "-"), sha))
        right = 0
        for side, verdict in ((OURS, mine), (THEIRS, theirs)):
            if verdict is None:
                problems.append("%s: no verdict from %s" % (row_id, side))
                continue
            if verdict.get("outcome") not in OUTCOMES:
                problems.append("%s: %s gave no verdict (%s)" % (row_id, side, _reason(verdict)))
                continue
            if verdict["outcome"] == "refused":
                lines.append("    %-8s %s" % (side, _reason(verdict)))
            if verdict["outcome"] != expect:
                problems.append("%s: %s %s it; the row expects %s" % (row_id, side, verdict["outcome"], expect))
            elif expect == "accepted" and verdict.get("claims") != row.get("claims"):
                problems.append("%s: %s accepted it with claims %r, not the row's %r"
                                % (row_id, side, verdict.get("claims"), row.get("claims")))
            elif expect == "refused" and _stage_problems(row_id, row.get("refused_at"), side, verdict):
                problems += _stage_problems(row_id, row.get("refused_at"), side, verdict)
            else:
                right += 1
        if mine and theirs and mine.get("outcome") in OUTCOMES and mine.get("outcome") == theirs.get("outcome"):
            agreed += 1
        as_expected += right == 2
        kind = row.get("kind")
        if kind == "outside":
            problems += _outside_problems(row, repo)
        elif kind == "window":
            problems += _window_problems(row, at, today)
            windows.append(row)
        elif kind == "control":
            source = by_id.get(row.get("of"))
            if source is None or source.get("expect") != "accepted":
                problems.append("%s is a control of %r, which is no row both verifiers are to accept"
                                % (row_id, row.get("of")))
        else:
            problems.append("%s is of kind %r" % (row_id, kind))
    if {row.get("expect") for row in windows} != set(OUTCOMES):
        problems.append("the window rows do not hold one row valid at the instant and one not yet valid there")
    flipped = 0
    for row in windows:
        other = "refused" if row.get("expect") == "accepted" else "accepted"
        mine, theirs = our_run_date.get(row["id"]), their_run_date.get(row["id"])
        lines.append("RUN-DATE %-22s expect %-8s %s %-8s %s %-8s" % (
            row["id"], other, OURS, (mine or {}).get("outcome", "-"), THEIRS, (theirs or {}).get("outcome", "-")))
        both = 0
        for side, verdict in ((OURS, mine), (THEIRS, theirs)):
            if verdict is None or verdict.get("outcome") != other:
                problems.append("%s at the run date: %s gave %s, not %s, so the row does not show the verdict turns "
                                "on the instant" % (row["id"], side, (verdict or {}).get("outcome", "no verdict"), other))
                continue
            if other == "refused":
                lines.append("    %-8s %s" % (side, _reason(verdict)))
                stage = _stage_problems(row["id"] + " at the run date", "document_signer_validity", side, verdict)
                if stage:
                    problems += stage
                    continue
            both += 1
        flipped += both == 2
    lines.append("ROWS %d  BOTH-AGREE %d  BOTH-AS-EXPECTED %d  WINDOW-ROWS-TURNED-AT-THE-RUN-DATE %d"
                 % (len(rows), agreed, as_expected, flipped))
    return lines, problems


def main(argv):
    if len(argv) not in (2, 3):
        print("usage: agree.py OUT/annexc.jsonl [ROWS]", file=sys.stderr)
        return 2
    with open(argv[2] if len(argv) == 3 else ROWS) as handle:
        fixture = json.load(handle)
    theirs, problems = read_theirs(argv[1])
    today = datetime.datetime.now(UTC).replace(microsecond=0)
    windows = {row["id"] for row in fixture.get("rows", []) if row.get("kind") == "window"}
    lines, judged = judge(fixture, ours(fixture), theirs[INSTANT], today,
                          our_run_date=ours(fixture, when=today, only=windows), their_run_date=theirs[RUN_DATE])
    print("\n".join(lines))
    for problem in problems + judged:
        print("FAIL " + problem)
    print("AGREEMENT TABLE: %s" % ("FAIL" if problems + judged else "PASS"))
    return 1 if problems + judged else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

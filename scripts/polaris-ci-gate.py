#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Egor Khaklin and the Polaris contributors
"""polaris-ci-gate.py: does a gate job pass, given the results of the jobs it needs?

A gate is a job that runs `if: always()` and passes only if the jobs it needs did. GitHub
reports a skipped required check as passing, so a gate cannot be skipped and cannot read
"skipped" as "passed". Since 2026-10-15 some of the jobs a gate needs ARE skipped on purpose:
the changes job (scripts/polaris-ci-changes.py) says which parts of CI a change cannot
affect. So a needed job counts as passed when:

  - its result is "success", or
  - its result is "skipped", it is governed by one of the changes job's outputs (--when), and
    that output is exactly "false": the change was measured not to need it.

Everything else fails the gate: a failure, a cancellation, a skip nothing explains (a skipped
job whose output says it was needed, or a job no output governs), a needed job the results do
not mention, a result for a job the gate was not told about, a changes job that did not
succeed or whose output is neither "true" nor "false", and results that are empty or do not
parse. A gate that cannot read its inputs fails.

    RESULTS='${{ toJSON(needs) }}' python3 scripts/polaris-ci-gate.py \
        --changes changes --when full=test-app-role,test-zk --when oid4vp=test-oid4vp-drill \
        --always test-core
"""
from __future__ import annotations

import argparse
import json
import os
import sys

OUTPUT_VALUES = ("true", "false")


def judge(results_text: str, changes: str | None, when: dict, always: list) -> tuple:
    """(passed, [lines explaining each part]) for the needs JSON `results_text`.

    `when` maps an output of the changes job to the jobs it governs; `always` lists the needed
    jobs no output governs (they must succeed). `changes` is the changes job's id, or None for
    a gate that reads no outputs."""
    lines = []
    try:
        results = json.loads(results_text or "")
    except ValueError as exc:
        return False, ["the needs results do not parse as JSON (%s)" % exc]
    if not isinstance(results, dict) or not results:
        return False, ["the needs results are empty or not an object: %r" % (results_text or "")[:200]]

    governed = {}
    for output, jobs in when.items():
        for job in jobs:
            if job in governed:
                return False, ["%s is governed by two outputs (%s and %s)" % (job, governed[job], output)]
            governed[job] = output
    expected = set(governed) | set(always) | ({changes} if changes else set())
    if not expected:
        return False, ["the gate was told about no job, so it would judge nothing"]
    overlap = set(governed) & set(always)
    if overlap:
        return False, ["%s are both governed and always required" % ", ".join(sorted(overlap))]
    missing = sorted(expected - set(results))
    extra = sorted(set(results) - expected)
    if missing:
        lines.append("FAIL the results do not mention %s, which this gate needs" % ", ".join(missing))
    if extra:
        lines.append("FAIL the results carry %s, which this gate was not told how to judge" % ", ".join(extra))

    def result_of(job):
        entry = results.get(job)
        if not isinstance(entry, dict) or not isinstance(entry.get("result"), str):
            return None
        return entry["result"]

    ok = not missing and not extra
    outputs = {}
    if changes:
        r = result_of(changes)
        if r != "success":
            lines.append("FAIL %s: %s; without its outputs no skip can be explained" % (changes, r))
            ok = False
        else:
            raw = results[changes].get("outputs")
            if not isinstance(raw, dict):
                lines.append("FAIL %s carries no outputs" % changes)
                ok = False
                raw = {}
            for output in when:
                v = raw.get(output)
                if v not in OUTPUT_VALUES:
                    lines.append("FAIL %s's output %s is %r, not \"true\" or \"false\"" % (changes, output, v))
                    ok = False
                else:
                    outputs[output] = v
            lines.append("ok   %s: success (%s)" % (
                changes, ", ".join("%s=%s" % (k, outputs.get(k, "?")) for k in sorted(when))))
    elif when:
        return False, ["outputs are named (--when) but no changes job is (--changes)"]

    for job in sorted(set(governed) | set(always)):
        if job not in results:
            continue
        r = result_of(job)
        if r == "success":
            lines.append("ok   %s: success" % job)
        elif r == "skipped" and job in governed and outputs.get(governed[job]) == "false":
            lines.append("ok   %s: skipped, and %s=false says this change does not need it"
                         % (job, governed[job]))
        elif r == "skipped" and job in governed:
            lines.append("FAIL %s: skipped, but %s=%s says this change needs it"
                         % (job, governed[job], outputs.get(governed[job], "unknown")))
            ok = False
        elif r == "skipped":
            lines.append("FAIL %s: skipped, and no output of the changes job governs it" % job)
            ok = False
        else:
            lines.append("FAIL %s: %s" % (job, r if r is not None else "no result"))
            ok = False
    return ok, lines


def _parse_when(items) -> dict:
    when = {}
    for item in items or []:
        output, sep, jobs = item.partition("=")
        names = [j.strip() for j in jobs.split(",") if j.strip()]
        if not sep or not output.strip() or not names:
            raise ValueError("--when takes OUTPUT=job[,job...], not %r" % item)
        when.setdefault(output.strip(), []).extend(names)
    return when


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    ap.add_argument("--changes", default=None, help="the changes job's id")
    ap.add_argument("--when", action="append", default=[], metavar="OUTPUT=JOB[,JOB...]",
                    help="jobs a skip may be explained for, by that output being \"false\"")
    ap.add_argument("--always", action="append", default=[], metavar="JOB[,JOB...]",
                    help="jobs that must succeed")
    ap.add_argument("--results-env", default="RESULTS",
                    help="the environment variable holding toJSON(needs) (default RESULTS)")
    args = ap.parse_args(argv)
    try:
        when = _parse_when(args.when)
    except ValueError as exc:
        print("gate: %s" % exc, file=sys.stderr)
        return 1
    always = [j.strip() for item in args.always for j in item.split(",") if j.strip()]
    passed, lines = judge(os.environ.get(args.results_env, ""), args.changes, when, always)
    for line in lines:
        print(line)
    print("gate: %s" % ("PASSED" if passed else "FAILED"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

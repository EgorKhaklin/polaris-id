# The public transparency program

**Reader:** the authority deciding what to publish about its own operation, and the oversight
body deciding whether the published figures mean anything. **Job:** what goes in the report,
which figures a reader can check for themselves, and why suppressing a small count is not the
same as protecting it.

The mechanism is [`polaris_web/transparency.py`](../../polaris_web/transparency.py), generated
by `polaris-id transparency-report`.

---

## 1. The gap this started from

An identity authority asks to be trusted with the most invasive power in the system: pulling
one named person's entire verification history. Every control around that power is invisible
from outside. The warrant is a piece of paper somewhere else. The role check happens in a
session the public never sees. The disclosure model that blanks zero-knowledge events is a CASE
expression in a stored procedure.

A transparency program is the one surface where the authority says out loud how often it used
that power. Building it began by asking what was recordable, and found that the answer was
nothing.

`AuditAccessLog` has recorded reads of the four tables holding people's histories since v9.20.
Eight routes called the helper that writes it. The warrant-audit route did not, and it is the
single most invasive read the system offers.

**It escaped because the read was behind a function name.** Every other read of
`VerificationEvent` is a `SELECT` in `app.py`, so anybody auditing the file by eye or by grep
finds it. UC-7 selects from `uc7_warrant_audit()`; the table appears only in
`05_procedures.sql`; and the route reads as if it touched nothing. A reviewer looking for
unlogged reads of a table would have had to already know which procedures return that table's
rows.

So the rule is now stated where the evasion lives. `check_audited_reads_are_logged` parses the
procedures file for functions that RETURN ROWS SOURCED FROM a tracked audit table, and requires
every route calling one to write an `AuditAccessLog` row. Procedures that merely count or purge
internally are not caught, because they hand the caller nothing. The check fails if it finds no
such procedure at all: a parse that has broken must not pass by finding nothing to check.

The row records the QUERY and never the RESULTS. An audit-of-audit that copied the subject's
verification history would double the exposure it exists to police, and the warrant already
authorises exactly one copy.

---

## 2. Every figure says where it came from

Two claims in a transparency report look identical on the page and are not the same kind of
claim at all.

| Source | Meaning | In this report |
| --- | --- | --- |
| `PUBLIC` | A reader with the published transparency log or the published source tree can derive it independently. An authority that misstates one can be caught from outside. | Anchor cadence, audit results |
| `OPERATOR_ATTESTED` | Nobody outside can derive it. The figure rests on the authority's word. | Warrant-audit statistics |

Printing both in the same typeface without saying which is which is how a transparency report
becomes a press release. An authority whose interesting numbers are all operator-attested has
written one.

The warrant-audit figures are unavoidably attested: they come from the authority's own log, and
no outside party can detect an authority that simply failed to record an access. That is the
reason the access log is append-only, the reason the report's digest belongs in the
transparency log, and the reason the report states the limit in its own text rather than
leaving a reader to infer it.

**Counts of people are suppressed. Counts of the system's own operations are not.** No person is
disclosed by the number of anchors written or checks passed, and blurring those would hide the
operator's own failures behind a privacy control.

The anchor cadence publishes the longest gap, not only the count. An authority that anchored
nine hundred times in a quarter and then went dark for nine days has a nine-day window in which
the log committed to nothing, and the count alone hides it. The gap is graded against a maximum
the authority DECLARES, since nothing in the database knows what it committed to; a program
that declares none publishes that fact instead of a column of figures nobody can grade.

---

## 3. Suppressing a small count is not protecting it

"Warrant audits this quarter, in this context: 2" identifies people in a small enough
jurisdiction. The standard answer is to suppress cells below a threshold. The standard answer
is also, on its own, wrong.

```
period    context        audits
2026-Q1   LAW_ENF        withheld     <- below the threshold of 5
2026-Q1   BORDER         40
2026-Q1   HEALTHCARE     12
          total          55
```

`55 - 40 - 12 = 3`. The withheld cell is published, and the marker beside it tells the reader it
was protected, which is worse than printing it plainly.

So suppression here is **checked rather than assumed**. For every withheld cell the module
computes the interval of values still consistent with everything published, and the report is
not generated when any small cell has been narrowed to a single value.

### The two kinds of withheld cell

The arithmetic only works if the two are told apart, and this is the part that is easy to get
wrong:

- A cell withheld **because it is small** is known to the reader to lie in `[0, threshold)`.
- A cell withheld **to protect another** is known to lie at or ABOVE the threshold, because a
  reader can see it was not small enough to be withheld on its own account.

Treating the second like the first makes the residual look impossible to satisfy and drives the
algorithm to withhold the entire table. In the worked example above the correct answer is to
publish `BORDER = 40`, withhold `HEALTHCARE` alongside `LAW_ENF`, and keep the total: the
withheld pair then sums to 15 with `LAW_ENF` anywhere in `[0, 4]`.

### The order of last resorts

1. Primary suppression: withhold every people-counting cell below the threshold.
2. Complementary suppression: withhold further cells, SMALLEST FIRST, until no small cell is
   determined.
3. Withhold the total itself, which removes the equation entirely.

Step 3 is last because the total is the figure an oversight reader came for. Both protect
equally; losing one context's count is the cheaper loss. That is a judgment and it is stated as
one.

Where a cell is determined by figures an EARLIER report already made public, none of this
helps: **suppressing more cannot protect against what the reader already holds.** The report is
then not generated at all.

---

## 4. No margins, and no running total

Two rules about equations, because it is the number of equations, not the number of withheld
cells, that makes a table invertible.

**No subtotals.** One total per period and no row or column margins. A period-by-context table
with both margins is a harder problem than this module pretends to solve, so it does not create
one.

**No cumulative total,** which is the same rule applied to time. A running total republished
every quarter looks like one figure and is not: the reader keeps last quarter's and subtracts,
and a program publishing a cumulative total each period would be publishing every per-period
margin without ever deciding to.

Each period therefore carries its own total over its own cells, and the periods share no
equation. That has a second benefit worth naming: a period's cells never change and its
suppression depends on nothing outside it, so recomputing an old quarter years later gives the
identical answer. **Publication is sticky without anybody having to store which decisions were
sticky.**

---

## 5. The cadence, and the gaps in it

A transparency program without a standing cadence is a transparency gesture: the operator
publishes when the numbers are comfortable. The cadence here is 90 days, and the report lists
every period since the program began that has no published report.

A missing period is part of the record. An operator who skipped the quarter the incident
happened in should not be able to publish a tidy series afterwards that hides the hole.

---

## 6. What is checked

| Mechanism | What it holds |
| --- | --- |
| `check_audited_reads_are_logged` | A route reading audited rows through a row-returning procedure writes an `AuditAccessLog` row. Fails if the procedure parse finds nothing. |
| `check_transparency_program` | Every figure carries its source; the invertibility re-check runs BEFORE the digest; complementary suppression is tried before the total is withheld; the two kinds of withheld cell keep different a-priori ranges; periods are suppressed independently; no running total; the report states its own limit. |
| `scripts/polaris-transparency-report-drill.py` | Attacks the report AS PUBLISHED over thousands of random tables and a growing multi-quarter series, with an adversary that enumerates reachable sums rather than recomputing the module's own bounds. Two different algorithms agreeing is evidence; one agreeing with itself is not. |
| `polaris_web/test_transparency.py` | 36 measured tests: the worked example above, two cells pinned at the ceiling (which a "at least two withheld cells" rule passes and discloses), the refusal, per-period independence, the digest's domain separation. |

---

## 7. Running it

```
polaris-id transparency-report --period 2026-Q3 --since 2026-04-01 \
    --published 2026-Q2 --anchor-target-hours 24 \
    --checks-total 222 --checks-passed 222
```

Prints the report as markdown (`--json` for the canonical bytes the digest is taken over) and
the digest on stderr. Anchor that digest in the transparency log: a report the authority can
revise after publication is not evidence of anything.

If suppression cannot protect a withheld cell, the command exits non-zero and prints nothing. A
report that cannot be published safely is not published.

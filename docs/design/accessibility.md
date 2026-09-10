# Accessibility

**Reader:** an engineer changing an operator surface, or an assessor asking what "accessible"
means here. **Job:** what is audited, what the audit can and cannot establish, and what is not
done.

An identity system a person cannot operate is one that excludes them from identity. That is the
same failure as the trusted-referee gap named in
[the 800-63 mapping](../reference/NIST-800-63-MAPPING.md), at a different layer, and it lands on
the same people. So this is not a polish item.

---

## 1. What runs, on every push

[`scripts/polaris-accessibility-drill.sh`](../../scripts/polaris-accessibility-drill.sh) boots
the app, logs in as an operator, and drives **sixteen surfaces** in a real headless Chromium,
running **axe-core** against the rendered DOM of each with the WCAG 2.0, 2.1 and 2.2 A and AA
rule tags.

**Serious and critical violations fail the build.** Moderate and minor ones are counted against
a ceiling that is currently **zero**, so a change that adds twenty small issues fails even
though no single one is serious. That is the category which otherwise accumulates below the
threshold anybody is watching.

**The axe version is pinned at 4.13.0, and that pin is load-bearing.** The convenient Python
wrapper bundles axe 4.4.3, which is from 2022 and predates WCAG 2.2 entirely: it has none of
the 2.2 rules. Auditing with it and reporting "WCAG 2.2 AA" would be a claim about a standard
the tool has never heard of. The drill asserts its own engine is new enough to have the rules it
claims to be testing.

## 2. What this does not establish, said plainly

**Automated testing detects roughly a third of WCAG failures.** It finds a missing label, a
contrast ratio, a broken ARIA reference, a control with no accessible name. It cannot tell you:

- whether alt text or a chart label is *meaningful* rather than merely present;
- whether the focus order through a form makes sense;
- whether an error message explains what to actually do;
- whether a screen-reader user can complete a task end to end;
- whether a workflow is usable with a switch device, voice control, or magnification;
- whether the language of the interface is comprehensible under stress.

**So a green run is a floor, not conformance.** Polaris does not claim WCAG 2.2 AA conformance,
and [ROADMAP.md](../../ROADMAP.md)'s "not claimed" list still carries accessibility conformance
for that reason. What changed is that the mechanical third is now enforced rather than assumed,
and cannot regress unnoticed.

Conformance requires manual testing with assistive technology, by people who use it. That has
not been done and is not something this repository can do to itself.

## 3. What the first audit found

Fifteen of sixteen surfaces were already clean. The Atlas had three real defects, each a
barrier rather than a technicality:

**Contrast, seven nodes.** `--ink-faint` was `#6e8299`, which is **4.43:1** on the panel ground
against the 4.5:1 AA floor for text that size. The Atlas renders its KPI labels at 10px, so
this was the label under every number an operator reads. Failing by 0.07 is still failing; the
token is now `#7b8fa6` at 5.26:1 and is still visibly a faint tone.

**A scrollable region no keyboard could reach.** The Overview panel scrolls, and nothing inside
it takes focus, so there was no way to scroll it without a mouse. Fixed with `tabindex="0"`, and
only that: the element is already a `tabpanel` named by its tab, and adding `role="region"`
would have *replaced* the correct role with a vaguer one.

**Two charts with no accessible name.** Both hero charts carry `role="img"` and no label, so a
screen-reader operator was told "graphic" and nothing else. They are now named from their own
data ("Verification volume over time: 24 intervals, peak 1,203 per interval"), so the label says
what the picture says and cannot go stale the way a static string would.

## 4. Adding a surface

A page missing from the drill's list is a page nobody audits. When you add an operator route,
add it to `SURFACES` in
[`scripts/polaris-accessibility-drill.py`](../../scripts/polaris-accessibility-drill.py).

## 5. What is not covered

- **The public site** (`site/`) is built and deployed separately and is not driven by this
  drill.
- **The CLI** is a different accessibility surface with different rules (screen-reader
  behaviour in a terminal, colour as the only signal). `NO_COLOR` is honoured; nothing else is
  audited.
- **Section 508** is not separately mapped. It incorporates WCAG 2.0 AA by reference, which is
  a subset of what runs here, but the procurement-facing paperwork is an authority's.
- **Manual testing with assistive technology**, per §2. This is the largest gap and no amount
  of automation closes it.

## Proven by

`scripts/polaris-accessibility-drill.sh` in CI on every push, and `check_accessibility`, which
pins the pinned-and-current engine, the rule tags, the zero ceilings, the surface list, and this
document's statement of what automation cannot establish.

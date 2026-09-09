# Timestamp transparency: evidence that survives a stolen authority key (P8.5b, v9.341)

**Status:** shipped in v9.341. **Invariant:** `check_timestamp_transparency` (#190).

## The problem

Long-term validation (v9.334) trusts a timestamp authority the verifier names. If that
authority's key is stolen, the thief can mint a timestamp dated a year ago, and nothing in the
signature distinguishes it from a genuine one; the trust list can mark the key compromised
from an instant, but a forgery simply claims an earlier instant. Every remedy that detects
backdating requires the authority to retain something, and the authority was built to retain
nothing. That made it a decision for the maintainer, who took it: anchoring as the caller's
choice.

## The design

- **Anchoring is the caller's choice.** `POST /api/v1/timestamp/<id>` with `anchor: true`
  (and `anchor_timestamp: true` at signing) appends the timestamp's SHA3-256 to
  `TimestampLog`, an append-only transparency log (migration 007, strict by trigger and
  privilege), and returns the timestamp with an unsigned `anchor`: the inclusion proof and
  the signed head, stapled so verification stays offline. The default request appends nothing,
  as before. What the authority retains for an anchored timestamp is one digest and one instant;
  no document, no requester.
- **The log is published like the others.** `/api/v1/transparency/timestamps/*` serve the head,
  consistency and inclusion proofs and the entries; the registry lists `polaris-timestamp-log`;
  the same monitor and witness daemons watch it.
- **The verifier decides the anchor offline.** `verify_timestamp_anchor` checks the proof is for
  this timestamp, the head is the authority's, the proof reconstructs it, and, when the relying
  party names witnesses, that the head is cosigned by its threshold of them. That last step is
  the substance: a thief with the authority's key can sign a fresh head over a fabricated log,
  but cannot make an independent witness have cosigned that head at the claimed time, and the
  fabricated head against the witnessed one of the same size is a caught split view.
- **Long-term validation gains three inputs.** `require_anchored` (with `trusted_witnesses` and
  `witness_threshold`), `timestamp_quorum` (distinct trusted, independent authorities among
  `ltv.timestamp` and `ltv.timestamps`; the no-retention alternative), and, with a trust list,
  the timestamp authority's key must have been active at the instant, exactly as the signer's.
  `attach_ltv` takes further timestamps.

## What the drill proves under real ML-DSA-65

A genuine anchored timestamp verifies and is witnessed. After the theft, a backdated timestamp
is authentic and trusted, so a verifier with no anchoring policy still accepts it (the residual
risk, stated), and one that requires an anchor refuses it. The thief forges an anchor too: the
inclusion is self-consistent, but no trusted witness cosigned the head, so the witnessed policy
refuses it, and the fake head is a caught split view. The trust list refuses a forgery dated
after the compromise by the authority-key rule alone; one dated before is caught only by the
anchor. Two independent authorities meet a quorum of two, one does not, and two timestamps from
the same authority count once. The two-instance drill anchors over HTTP and shows the unanchored
request leaving no row.

## Limits, stated

- Anchor verification lives in the detached verifier. The Python and TypeScript SDKs verify a
  timestamp's authenticity and its head as artifacts; inclusion and witnessing are not yet in
  them (roadmap P8.5c).
- Witnesses are what make an anchor evidence against a stolen key. An anchor checked without
  witnesses proves inclusion in the authority's own log and no more; the verdict says so.
- Retention, when chosen, is a digest and an instant per anchored timestamp: a record of volume
  and timing, never of content. The readiness ledger states it.

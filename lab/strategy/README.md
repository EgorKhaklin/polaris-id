# lab/strategy/: the bets, and what would prove each one wrong

**Reader:** anyone asking why Polaris built something nobody had asked for. **Job:** hold the
fifth merge reason, [STRATEGIC-BUILD](../../docs/OPERATING-CONTRACT.md), to something a reader
can check later.

The other four merge reasons answer to evidence that already exists: an external suite, an
external user, an external finding, a broken promise. STRATEGIC-BUILD does not, which is
exactly why it is the one that needs a paper trail. A capability admitted here was admitted on
a prediction, and a prediction nobody wrote down is indistinguishable afterwards from a
preference.

## The ten questions

Every record answers all ten. A record that cannot is not an argument for building yet.

1. What capability is being considered?
2. What problem would it solve?
3. Who would plausibly need it?
4. What existing systems already solve it?
5. Can Polaris interoperate instead of rebuild?
6. What unique advantage could Polaris obtain?
7. What happens if Polaris does NOT build it?
8. What other work would be delayed?
9. Can the idea be tested cheaply in LAB first?
10. **What evidence would prove the bet was wrong?**

Ten is the one that matters. It is written before the work starts, not after, because a
falsifier invented later is always satisfied by whatever was built.

## The records

| Record | Capability | State |
|---|---|---|
| [001-token-status-list.md](001-token-status-list.md) | Read a foreign issuer's revocation status (IETF Token Status List) | CLOSED. Both falsifiers checked and neither fired; shipped as v1.0.0-rc.4 and v1.0.0-rc.5. No outside party has used it. |

## Candidates generated, not admitted

Generation is not authorization. These are here so the next strategy pass starts from what was
already measured rather than re-deriving it, and so a candidate that was rejected for a reason
is not re-proposed for the same reason.

**SCITT transparency receipts (RFC 9943).** Researched 2026-09-19, not started. SCITT was
published as RFC 9943 and is explicitly content-agnostic: a Signed Statement is a COSE_Sign1
with CWT claims, a Receipt is a COSE_Sign1 carrying an RFC 9162 Merkle inclusion proof, and a
Transparency Service is an append-only non-equivocating log. Polaris already has every piece
of that shape, built independently: signed tree heads, inclusion proofs, consistency proofs,
equivocation detection and witness cosigning. ML-DSA-65 is COSE algorithm -49, so the
signature suite is expressible without compromise, which is the usual thing that kills a
format bridge here. The open question is demand rather than feasibility: SCITT's adopters
today are supply-chain tooling, and whether anything in identity consumes a SCITT receipt is
exactly what a record would have to answer before this is worth building.

**A signed algorithm-policy artifact.** On `lab/EXTERNAL-NOUNS.md`'s known-limitations list:
algorithm deprecation lives in `CryptographicAlgorithm` rows, not in anything a detached
verifier is handed and can check. Searched 2026-09-19 for a standard to adopt instead of
inventing one, and there is none: RFC 7696 is agility *guidance*, RFC 3125 is a 2001 ASN.1
signature-policy format with no live ecosystem, and NIST publishes deprecation *timelines*
rather than a wire format. So this means inventing a format, which drops ecosystem momentum
and raises maintenance and lock-in. It is not the credential-format mistake the mandate warns
about, since such a policy is private between an issuer and its own verifiers and asks nobody
to migrate, but the payoff estimate has to carry the invention cost honestly. Note that
`lab/strategy/status_list.py` now holds the freshness, staleness and rollback machinery such
an artifact needs, so the cost is lower than it was before record 001.

## What a record does not do

It does not authorize an empire. The build is the smallest version that tests the thesis, it
is attacked before it is believed, and the kill criterion applies to it from the first line. A
record whose project has outgrown its own scope is a record that has stopped being read.

A bet that fails is still worth its record: it removes a direction, and the measurement that
removed it is the useful part. Record what was learned in the file rather than deleting it.

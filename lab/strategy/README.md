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

## How a decision is written

A record starts from a contradiction inside the tree. "The finding that started it" is the
place where something the repository says, or a decision it already recorded, stops holding
against the rest of what it says. A decision does not pick a side of that contradiction. It
says three things:
- what the earlier position got right, which is kept;
- what was false, which is dropped;
- the new position that holds both.

[005](005-oid4vci-issuer.md) is the worked case. It keeps 001's finding that issuer software is
ordinary, and it drops 001's conclusion that issuing could only duplicate that software. The
new position is not "an issuer" but a wallet copy the Polaris record governs, and it inherits
the mdoc bridge's sentence that a classical signature makes a classical credential instead of
arguing with it. A decision that only reverses the one before it has not finished.

## The records

| Record | Capability | State |
|---|---|---|
| [001-token-status-list.md](001-token-status-list.md) | Read a foreign issuer's revocation status (IETF Token Status List) | CLOSED. Both falsifiers checked and neither fired; shipped as v1.0.0-rc.4 and v1.0.0-rc.5. No outside party has used it. |
| [002-relying-party-api-compartment.md](002-relying-party-api-compartment.md) | Run the internet-facing relying-party API as its own service with its own least-privileged database login | MEASURED, NOT BUILT alone: separable (160 of 163 tests pass as the narrowed login, every operator write refused), but the public surface still shares the issuance signing key and reads every credential pack, so the split would overstate its protection. Next: signing custody (003). |
| [003-signing-custody-compartment.md](003-signing-custody-compartment.md) | A signing service outside the web process that signs only the statement formats its caller may request | KILLED on criterion 1: the public surface signs trust decisions (manifest, trust list, registry) on every request, so formats do not partition. Found on the way: any authority-signed artifact re-wrapped as a credential pack verified as authentic. |
| [004-operator-identity-for-four-eyes.md](004-operator-identity-for-four-eyes.md) | The database, not the application, decides which operator acted in separation-of-duties rules, starting with recovery | OPEN, record only. Next: complete a recovery as the application role naming two operators (the ledger's sentence as an executable counterexample). |
| [005-oid4vci-issuer.md](005-oid4vci-issuer.md) | Issue a Polaris credential into a wallet Polaris did not write (OpenID4VCI), still governed by Polaris's issuance rules | OPEN, a demonstration: criterion 4 fired at rc.67 (no outside party has held a wallet copy). Answers 001's rejection of OID4VCI issuance; killed if the wallet copy can outlive or bypass the Polaris record. Step 1 ([005/WALL.md](005/WALL.md)): HAIP certification means a FAPI 2.0 authorization server, so the wallet loop (pre-authorized code) runs first. Step 2 ([005/STEP2.md](005/STEP2.md)): both wallets received with no workaround; the loop issuer, walt.id, `polaris-oid4vp` closed. Step 3 ([005/STEP3.md](005/STEP3.md)): 7 of 7, the wallet copy obeys the Polaris record while the issuing process does. The product loop is built, and S5 ([005/STEP5.md](005/STEP5.md)): walt.id and Credo each received a governed copy from `polaris_web` (VALID, then INVALID after revocation; none for a credential revoked before redemption). S6 ([005/STEP6.md](005/STEP6.md)): both presented it to `polaris-oid4vp`, which read the product's status list (VALID, then INVALID after revocation; only `age_over_18` disclosed). |
| [006-verified-result-from-one-command.md](006-verified-result-from-one-command.md) | One command that runs the production stack on the stranger's own machine under a key minted there, issues one credential and hands over what `polaris-verify` needs to check it | OPEN. One command, `lab/strategy/006/try.sh` (steps 1 to 3, 2026-09-30): from a clean checkout it builds and runs the production stack, issues one credential under a key minted on the machine, and `polaris-verify` from PyPI verifies it, in 7 minutes with a no-cache build. The README names it and a workflow runs it nightly on a clean runner. Still the author's runs. |
| [007-access-gate.md](007-access-gate.md) | A gate the relying organisation runs: a wallet presentation in, a standard OIDC ID token out with a pairwise subject, and a holder's agent grant in, a per-request token out, for the identity-aware proxies that already accept an OIDC provider | OPEN, 2026-10-01: falsifiers written first, then the gate and its tests (`lab/strategy/007/`); killed if no outsider runs the Pomerium demonstration by 2026-11-12 |

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
`packages/polaris-oid4vp/polaris_oid4vp/status.py` now holds the freshness, staleness and
rollback machinery such an artifact needs, so the cost is lower than it was before record 001.

## What a record does not do

It does not authorize an empire. The build is the smallest version that tests the thesis, it
is attacked before it is believed, and the kill criterion applies to it from the first line. A
record whose project has outgrown its own scope is a record that has stopped being read.

A bet that fails is still worth its record: it removes a direction, and the measurement that
removed it is the useful part. Record what was learned in the file rather than deleting it.

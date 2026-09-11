# The trust ladder: what each rung refuses, and what holds it up

**Reader:** someone asking not what Polaris enforces but why the enforcement
sits where it does, and where the reasoning runs out. **Job:** name every rung
of the anti-trust ladder, bind each one to the mechanism in this tree that
discharges it, and state plainly where the ladder stops.

[MISSION.md](../MISSION.md) states the constraints. This file states the
argument that produces them, which is a single move applied repeatedly: find
the thing the system is currently trusting, refuse to trust it, and replace the
trust with a mechanism. The interesting part is not the move. It is that the
move can be applied to its own output, over and over, until it reaches
something that cannot be discharged by a mechanism at all.

---

## The ladder

Each rung names what a conventional system trusts, what Polaris does instead,
and the object in this tree that carries it. A rung with no mechanism is not a
position, it is an opinion; the check layer holds these names to the code.

| # | Normally trusted | Refused by | Mechanism |
|---|---|---|---|
| 1 | The user's input | Server-side enforcement | C6 disclosure enforcement in `polaris_web/app.py`; `check_operator_scripts_validate_argv` for operator argv |
| 2 | The operator and the issuing authority | An audit of record they cannot edit | C1 append-only triggers in `polaris_sql/06_triggers.sql`; `check_audited_reads_are_logged` for the warrant path |
| 3 | The application code | Guarantees that live below it | C1 to C10 as triggers, CHECK constraints and partial unique indexes, not as policy; `polaris_checks/checks.py` |
| 4 | The test suite that proves the code | Mutation, not assertion | `scripts/polaris-check-mutation-drill.py` for the checks, `scripts/polaris-constraint-mutation-drill.py` for the database constraints |
| 5 | Today's cryptography, forever | An algorithm registry and a migration path | C7: the algorithm is a row in `CryptographicAlgorithm`, never a literal; [PQC-POSTURE.md](../docs/reference/PQC-POSTURE.md) carries a per-surface deadline |
| 6 | Today's model of computation, forever | Nothing. This rung is open | See below |

Rungs 1 to 5 each ended with a mechanism. That is what makes them settled:
the refusal is discharged by an object, and the object is checked.

Rung 6 has no mechanism and will not get one. "Post-quantum" means secure
against the standard quantum model. It does not mean secure against a model
nobody has written yet, and no amount of engineering inside this repository can
make it mean that. PQC-POSTURE says so per surface rather than in general,
which is the honest version of admitting it.

---

## What survives a rung that cannot be discharged

If the adversary's computational power cannot be bounded, then every protection
that rests on computational difficulty is a protection with an expiry date that
nobody can name. One thing is not in that category: information that was never
recorded. An absent fact is not hard to recover. It is not there to recover, and
that is true against any adversary, with any computer, under any physics.

This is not a new idea in Polaris and it is not speculative. It is already the
design rule on the surfaces where it matters most, stated as
**prefer non-creation over protection**:

| Surface | What is not created | Enforced by |
|---|---|---|
| Zero-knowledge verification | The link from the event to the token. There is no verification graph to reconstruct from a full database capture | `chk_disclosure_token_consistency`, proved in [redaction-proof.md](redaction-proof.md) |
| Presentation to a relying party | Any identifier stable across verifiers | Scoped nullifiers, `scripts/polaris-pairwise-drill.py` |
| Enrollment codes | The code itself. Only its hash is stored, and the plaintext is returned once | `polaris_web/enrollment_code.py`, trigger `enrollment_code_one_way_door` |
| Duress codes | The code itself | `chk_duress_hash_well_formed` |
| Published transparency figures | Any per-period margin recoverable by subtraction | `polaris_web/transparency.py` |

And the honest other half, because a ledger that lists only the wins is an
advertisement. Polaris records these, and an adversary with unbounded future
computation and a copy of the database gets them:

- `Individual.legal_name` and `date_of_birth`. An identity system that cannot
  name the person is not an identity system; this is the thing being protected,
  not an accident.
- `token_id` on SELECTIVE and FULL verification events. That link is the audit
  of record. C1 requires it to exist and C2 requires it to be absent only where
  the holder chose zero-knowledge. Both at once is the design.
- Event location, where an agency recorded one.
- The epoch Merkle tree and its leaves.

Nothing on that list is a defect. The point of the ledger is that the list is
written down, so the question "what would a future adversary get" has an answer
that is read rather than guessed.

---

## The rung below the speculation

The interesting thing about rung 6 is that its practical form is already an
engineering line item, and it has a name: harvest now, decrypt later. An
adversary who records a TLS session today and breaks its key exchange in twenty
years reads that session, and no future patch reaches backwards to stop it.
That is "future computation recovers present information" stated without any
appeal to physics, and Polaris measures it per hop rather than assuming it:
`scripts/polaris-internal-kex-drill.sh` reads the negotiated group off a real
handshake, and PQC-POSTURE records what each hop actually negotiated rather than
what its Dockerfile implies.

So the ladder does not need a speculative rung to produce work. It produced the
KEX measurement, the suppression rules in the transparency report, the scoped
nullifiers, and the NULL that C2 enforces. Each of those is the same instruction:
where the adversary cannot be bounded, do not create the thing.

---

## What Polaris does not claim

This section is the boundary, and it is load-bearing.

- Polaris implements **no** temporal cryptography, no physics-based security,
  and nothing whose security argument depends on information becoming
  physically unavailable. There is no such mechanism in this tree and none is
  planned.
- The cryptography here is standard and named: FIPS 204 ML-DSA-65 for credential
  signatures, standard TLS 1.3 for transport, scrypt for operator passwords. The
  ZK proof system's post-quantum standing is a hash-reduction argument, stated as
  such in PQC-POSTURE, not a certification.
- Rung 6 is a question this document declines to answer, not a feature. Nothing
  in the running system depends on it having an answer. If the ladder's top rung
  were deleted tomorrow, no guarantee in [MISSION.md](../MISSION.md) would weaken.
- "Prefer non-creation over protection" is a design rule with a ledger, not a
  claim that Polaris stores nothing. The ledger above says exactly what it stores.

The reason to write the ladder down at all is that it tells you where effort is
worth spending: rungs 1 to 5 are discharged and stay discharged because the
check layer holds them; rung 6 cannot be discharged, so the work it justifies is
not a stronger algorithm but a shorter list of things recorded.

---

## Related

- [MISSION.md](../MISSION.md): the constraints themselves, and the vocation above them
- [constraint-lattice.md](constraint-lattice.md): how C1 to C10 hold each other up
- [structural-architecture.md](structural-architecture.md): the Removable Test, which decides which rung a mechanism belongs on
- [redaction-proof.md](redaction-proof.md): the proof behind the first row of the non-creation ledger
- [PQC-POSTURE.md](../docs/reference/PQC-POSTURE.md): the per-surface migration clock, and the measured key exchange on every hop

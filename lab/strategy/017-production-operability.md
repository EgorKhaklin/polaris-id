# 017: an operator who is not the author runs Polaris

**Opened 2026-10-07.** STRATEGIC-BUILD under the [operating contract](../../docs/OPERATING-CONTRACT.md),
on the owner's direction of 2026-10-07: a deployment an experienced operator can trust and an
inexperienced one can complete. State: OPEN. The falsifiers in section 10 were written before the
build. Step 0: this record, the operability gate in
[PRODUCTION-READINESS.md](../../docs/PRODUCTION-READINESS.md#operability-gate), and two operator
documents corrected.

---

## The finding that started it

PRODUCTION-READINESS.md says every engineering gap it enumerated is closed. Read against the code,
an operator who is not the author meets these before any limitation that ledger lists:

- the server is published nowhere, so the operator builds every image from source, the Rust prover
  and liboqs included;
- every health check (compose, the TLS edge, the Helm probes) routes on whether the process is
  alive, not on whether this instance can serve;
- a Helm upgrade never migrates the schema: nothing runs the migrations after the first install;
- an unreadable secret file falls back to an environment variable or a development default, so a
  misconfigured production instance fails late rather than at boot;
- two operator documents describe an older chart and an older edge.

[006](006-verified-result-from-one-command.md) got a stranger to a verified result from one
command on their own machine. It did not cover running that stack for anyone else.

- **Kept:** 006's finding that packaging, not mechanism, is the gap; the production stack, the
  drills and the custody drivers as they are.
- **Kept:** "not production-ready for real identity data" until an external review, the
  operator's DPIA and a pilot exist. Nothing here changes that sentence.
- **Dropped:** the reading that a closed engineering ledger means an operator can deploy and run
  Polaris without the author.
- **New position:** one canonical node (stateless application, PostgreSQL as the only record, an
  edge) delivered as signed images under one configuration contract, and a gate whose every PASS
  cites evidence a check resolves.

## 1. What capability is being considered?

A Polaris node an outside operator installs from signed release artifacts, configures with a
handful of values, upgrades, backs up, restores to a point in time and diagnoses, on one host or
on Kubernetes; and a gate that says, criterion by criterion and with evidence, how far that holds.

## 2. What problem would it solve?

The 1.0.0 condition and a pilot both need an operator who is not the author. Today that operator
builds from source and reads code to learn what an unhealthy instance looks like.

## 3. Who would plausibly need it?

A pilot operator; a relying party standing up the verifier; an evaluator or auditor; the stranger
the contract's 1.0.0 condition names.

## 4. What existing systems already solve it?

Inside the tree: the production compose, Patroni, pgBackRest, the custody drivers, the Helm chart
and the drills. Outside it, Kubernetes, managed PostgreSQL, cloud KMS and secret managers solve
the surrounding infrastructure; none of them supplies Polaris's configuration contract, health
semantics, migrations or custody.

## 5. Can Polaris interoperate instead of rebuild?

Mostly. Ingress or Gateway, cert-manager, External Secrets, managed PostgreSQL and cloud KMS are
consumed through files, PKCS#11 and KMS APIs rather than rebuilt. No Operator, no service mesh, no
database abstraction: the schema is the security boundary and stays PostgreSQL.

## 6. What unique advantage could Polaris obtain?

Readiness claims that are machine-checked like its constraints: an outsider sees what passes,
what does not, and the evidence for each row.

## 7. What happens if Polaris does NOT build it?

The candidate stays a candidate: no outside operator reaches a running instance without the author.

## 8. What other work would be delayed?

The open lab records continue at a lower rate; this work runs in the time CI takes.

## 9. Can the idea be tested cheaply in LAB first?

Step 0 is documents and one check. The first engineering step, a configuration contract, changes
behaviour only under `POLARIS_ENV=production`.

## 10. What evidence would prove the bet wrong?

- **Nobody uses it.** If no named operator outside the project attempts an install from release
  artifacts by 2027-01-15, stop after the single-host node and record why.
- **It is not plug-and-play.** If an install on a fresh host from release artifacts needs more than
  five operator inputs or fifteen minutes, packaging is not the gap; record what is.
- **The gate says more than its evidence.** If a PASS row's citation stops resolving, the check
  fails and the row is restated, not the check loosened.
- **It is read as readiness for real data.** If any surface reads this work that way, the wording
  is retracted; that label needs the external review, the DPIA and a pilot.

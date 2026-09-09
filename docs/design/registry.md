# The signed registry (P8.3)

**Reader:** an engineer integrating with a Polaris instance, or an assessor who wants to know
how a consumer learns what an instance offers and trusts without being told out of band.

**Status:** shipped v9.323. `polaris-registry/1`, published at `GET /api/v1/registry/<id>`,
verified offline by `scripts/polaris-verify.py` (`verify_registry`) and read for discovery
(`registry_service`, `registry_authority`, `registry_trusts`).

## What it is

One signed, machine-readable artifact in which a publishing authority states what its
instance offers and trusts:

- `instance.protocol`: the format names it speaks with their major versions, its algorithms,
  and where the wire spec and conformance suite live;
- `instance.services`: each service's kind, path template, method, and how it authenticates
  (`none`, `possession`, `client-credentials`, `bearer:verify`, `responder-signature`);
- `instance.transparency_logs` and the disclosure vocabulary;
- `authorities`: every federated authority the instance knows, with its registered key;
- `contexts`: the verification contexts and the proof each requires;
- `trust`: the in-context trust graph -- who attests whom, for which context, until when;
- `relying_parties`: the organizations it serves, by name and scope only.

Every fact is a view over Athena (`v_athena_agency`, `v_athena_proof_policy`,
`v_athena_disclosure_policy`, `v_athena_trust_agreement`) and the authority tables. The
registry adds no truth of its own; it is the authority layer, signed and published.

## Why it is signed, and why it must list itself

A registry answers "where do I send this, and whom do I trust?" -- exactly the questions an
attacker would like to answer for you. So it is signed by the publishing authority, and a
verifier requires self-consistency: the signing key must be the active key the registry lists
for its own publisher. A stranger cannot publish a registry in an authority's name, because the
authority's registered key is already known to anyone who trusts it. Whether the publisher is
trusted at all remains the consumer's anchor decision, as everywhere in Polaris. The registry is
short-lived so services and trust do not go stale, and it is non-transitive: it describes its
publisher's instance and attestations, never another authority's.

## Discovery, not configuration

A consumer fetches the registry, verifies it, and then drives its calls from it: the path
template for a service (`registry_service(reg, "timestamp")`), the authority behind a key
(`registry_authority`), and the in-context trust graph (`registry_trusts(reg, key, context)`).
The two-instance drill does exactly this over HTTP: it reads the timestamp service's path out
of B's registry and calls it, reads B's attestation of A from the trust graph, and after B
revokes that attestation sees the re-fetched registry drop it. Version negotiation over
`instance.protocol.formats` is P8.8.

## What it deliberately does not contain

No token, no holder, no verification record, no relying-party credential (organization name
and scope only). Institutional data, published trust, nothing personal: the registry is a map
of the institutions, never of the people.

## What runs

`scripts/polaris-registry-drill.py` (the `pqc-real` CI job) builds a registry under a real
ML-DSA-65 root and drives the matrix: authentic, fresh, self-consistent, trusted; a service, an
authority and the trust graph discovered from it; an impostor in the publisher's name, a
tampered copy, and an expired copy caught; hostile input does not crash the verifier. The
statement is in the canonical-equivalence oracle, the wire spec (section 3.10), the
conformance suite (three published vectors, both SDKs, including the impostor case), and the
metamorphic fuzzer. `check_registry` pins all of it and, in addition, pins the advertised
format list to the wire spec's, with a detection test.

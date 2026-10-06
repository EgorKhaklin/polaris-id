# Record 015, step 3: the FN-DSA family end to end, through the product

**Run 2026-10-06** with [`fndsa_e2e.py`](fndsa_e2e.py) on an Apple M3, liboqs 0.15.0,
@noble/post-quantum 0.7.1, PostgreSQL 16; real signing (`POLARIS_USE_REAL_PQC=1`) under the
experimental opt-in (`POLARIS_EXPERIMENTAL_SIGNERS=Falcon-padded-1024`), outside production.

**The question:** with the experimental signer wired, does a population move onto
Falcon-padded-1024 through the product's own migration runner, and does every credential then
verify everywhere a relying party can check it?

**The answer: yes, 16 of 16 rows.** 224 live credentials (220 seeded plus four fixtures), each
standing on an ML-DSA-65 signature:

| Hop | Result |
|---|---|
| ML-DSA-65 to Falcon-padded-1024 | 224 re-signed at 501/s; the window closed; nobody dark |
| Verification after it | the detached verifier and the Python SDK accept all 224; the TypeScript SDK (an independent implementation) accepts a 20-credential sample; a tampered pack is refused by all three; every signature is 1,280 bytes |
| Falcon to ML-DSA-87 | the 222 that never held ML-DSA-87 re-signed at 321/s and verify; the 2 fixtures that already held one (retired when the Falcon window closed) are blocked, never dark, and closing the window is refused with the re-issue instruction |
| Long-term validation | the 224 Falcon signatures still verify after their window closed |
| Back to ML-DSA-65 | only the 2 that never held it are re-signed; closing is refused |

**What it shows beyond FN-DSA:** a credential holds one signature per algorithm, ever, so a
population cannot return to a family it left, and a credential that already passed through a
family cannot come back to it. The runner refuses those by name and strands nobody. That is the
limit record 014 (Precession) proposes to lift with generations.

**Measured alongside (quantum-event drill, 2,000 credentials, `POLARIS_QE_TARGET`):** onto
Falcon-padded-1024 at 604 re-signed/s, onto ML-DSA-87 at 319/s, every one of the drill's 20
safety cases holding for both. The first Falcon measurement was 14/s: the second witness started
Node per signature. It now runs one resident process.

**Not shown here:** anything about side channels. Signing stays experimental until step 4's
timing test clears falsifier 2.

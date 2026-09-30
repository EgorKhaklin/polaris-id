// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { sha3_256 } from "@noble/hashes/sha3.js";
import { verifyAuthenticity, PolarisVerifier, pairwiseHandle, handlesLink,
         nullifiersLink, grantCovers, grantWithinLimits, revocationEndsGrant, agentProofProves, grantPrincipalBound,
         verifyExchangeRequest, verifyExchangeReceipt, verifyExchangeMint,
         verifyInclusion, verifyStatusAssertion, verifyIdToken, verifyHolder, verifyTimestampAnchor,
         verifySignedArtifact, verifyCosignature,
         verifyAttestation, verifyCrossAuthority,
         __canonicalJsonForTest, __isoToEpochForTest, expiresIn, tokenValueSerialProblem } from "../src/index.ts";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const vec = (n: string) => JSON.parse(readFileSync(join(ROOT, "vectors", n), "utf8"));

test("genuine signature is authentic", () => {
  assert.equal(verifyAuthenticity(vec("ml-dsa-65-valid.json")).authentic, true);
});

test("tampered and wrong-key are not authentic", () => {
  for (const n of ["ml-dsa-65-tampered-signature.json", "ml-dsa-65-tampered-token.json", "ml-dsa-65-wrong-key.json"]) {
    assert.equal(verifyAuthenticity(vec(n)).authentic, false, n);
  }
});

test("placeholder is not authenticatable offline", () => {
  assert.equal(verifyAuthenticity(vec("placeholder.json")).authentic, false);
});

test("anchor trust", () => {
  const valid = vec("ml-dsa-65-valid.json");
  assert.equal(verifyAuthenticity(valid).issuerTrusted, null);
  assert.equal(verifyAuthenticity(valid, [valid.public_key_hex]).issuerTrusted, true);
  assert.equal(verifyAuthenticity(valid, ["00"]).issuerTrusted, false);
});

test("offline presentation is provisional", async () => {
  const v = new PolarisVerifier();
  const out = await v.verifyPresentation({ credential: vec("ml-dsa-65-valid.json") });
  assert.equal(out.decision, "provisional");
});

test("active presentation is accepted; revoked is rejected but authentic", async () => {
  const mk = (authoritative: boolean) => {
    const v = new PolarisVerifier({ issuerUrl: "http://x" });
    (v as any).onlineStatus = async () => ({ currently_authoritative: authoritative, status: authoritative ? "ACTIVE" : "REVOKED" });
    return v;
  };
  const pres = { credential: vec("ml-dsa-65-valid.json") };
  assert.equal((await mk(true).verifyPresentation(pres)).decision, "accept");
  const rej = await mk(false).verifyPresentation(pres);
  assert.equal(rej.decision, "reject");
  assert.equal(rej.authentic, true);
});

test("untrusted issuer is rejected without a status call", async () => {
  const v = new PolarisVerifier({ issuerUrl: "http://x", anchors: ["00"] });
  (v as any).onlineStatus = async () => { throw new Error("must not be called"); };
  assert.equal((await v.verifyPresentation({ credential: vec("ml-dsa-65-valid.json") })).decision, "reject");
});

// --- P9.3 / P9.4: the two per-verifier handles -------------------------------

test("a pairwise handle differs at every verifier", () => {
  const key = "ab".repeat(32);
  const clinic = pairwiseHandle(key, "rp_clinic_0000000000000001");
  const library = pairwiseHandle(key, "rp_library_000000000000001");
  assert.notEqual(clinic, library, "two verifiers must not receive the same handle");
  assert.equal(handlesLink(clinic, library), false,
    "comparing handles across scopes must not report a match");
});

test("a pairwise handle is stable at one verifier, so the account works", () => {
  const key = "ab".repeat(32);
  assert.equal(pairwiseHandle(key, "rp_clinic"), pairwiseHandle(key, "rp_clinic"));
  assert.equal(handlesLink(pairwiseHandle(key.toUpperCase(), "rp_clinic"),
                           pairwiseHandle(key, "rp_clinic")), true,
    "hex case must not split one holder into two accounts");
});

test("a pairwise handle refuses unusable input rather than hashing nothing", () => {
  // The hash of an empty string is a perfectly good hex value, and keying records on
  // it would collide every holder into one record.
  assert.equal(pairwiseHandle("", "rp_x"), null);
  assert.equal(pairwiseHandle("ab".repeat(32), "  "), null);
  assert.equal(pairwiseHandle(null, "rp_x"), null);
  assert.equal(pairwiseHandle("ab".repeat(32), undefined), null);
});

test("the Python SDK and this one derive the same handle", () => {
  // Pinned to the value the Python SDK and the detached verifier produce, so a drift in
  // any of the three is a failing test here rather than an integrator's mystery later.
  assert.equal(pairwiseHandle("ab".repeat(32), "rp_clinic_0000000000000001"),
    "2115deb30abcf45aa7e05244051abb1cc81d21ad8197d70b34327d4c56572de7");
});

test("nullifiers link only on exact hex", () => {
  assert.equal(nullifiersLink("AB".repeat(32), "ab".repeat(32)), true);
  assert.equal(nullifiersLink("ab".repeat(32), "ab".repeat(31) + "ff"), false);
  assert.equal(nullifiersLink(null, 1), false);
});

// --- P9.8: the delegated agent grant ------------------------------------------

const GRANT = {
  format: "polaris-agent-grant/1", grant_id: "g1",
  actions: ["read:status"], limits: { max_uses: 2 }, public_key_hex: "ab".repeat(32),
};

test("a grant covers only the actions it names", () => {
  assert.equal(grantCovers(GRANT, "read:status"), true);
  assert.equal(grantCovers(GRANT, "transfer:funds"), false);
});

test("a grant naming no actions grants nothing, not everything", () => {
  // The dangerous reading: an empty list as "unrestricted". Everything would work, and the
  // grant would silently be the credential hand-over it exists to replace.
  assert.equal(grantCovers({ ...GRANT, actions: [] }, "read:status"), false);
  assert.equal(grantCovers({ ...GRANT, actions: undefined }, "read:status"), false);
  assert.equal(grantCovers(null, "read:status"), false);
});

test("limits are enforced, and unknown limits are refused rather than ignored", () => {
  assert.equal(grantWithinLimits(GRANT, 0)[0], true);
  assert.equal(grantWithinLimits(GRANT, 2)[0], false);
  const [ok, note] = grantWithinLimits({ limits: { max_transfers: 3 } });
  assert.equal(ok, false);
  assert.match(String(note), /does not understand/);
});

// 2026-09-30: `limits` as a string or a number read as no limits here, and the Python verifiers
// read a list that way too, so one signed grant got two answers. Present and not a plain object
// is refused; absent still means unlimited.
test("limits that are not an object are refused, and absent limits still mean unlimited", () => {
  for (const limits of [[{ max_uses: 1 }], [], "max_uses=1", 1, 0, true]) {
    const [ok, note] = grantWithinLimits({ limits }, 5, 1e9);
    assert.equal(ok, false, JSON.stringify(limits));
    assert.match(String(note), /not an object/);
  }
  for (const grant of [null, [], "grant", 3]) assert.equal(grantWithinLimits(grant, 0)[0], false);
  for (const grant of [{}, { limits: null }, { limits: {} }]) {
    assert.deepEqual(grantWithinLimits(grant, 1e6, 1e9), [true, null], JSON.stringify(grant));
  }
});

test("only the holder who signed a grant can revoke it", () => {
  const rev = { format: "polaris-grant-revocation/1", grant_id: "g1", public_key_hex: "AB".repeat(32) };
  assert.equal(revocationEndsGrant(rev, GRANT), true, "hex case must not defeat a revocation");
  assert.equal(revocationEndsGrant({ ...rev, public_key_hex: "cd".repeat(32) }, GRANT), false,
    "a stranger's key must not end someone else's grant");
  assert.equal(revocationEndsGrant({ ...rev, grant_id: "other" }, GRANT), false,
    "a revocation naming another grant must not end this one");
  assert.equal(revocationEndsGrant({ ...rev, format: "polaris-status-assertion/1" }, GRANT), false);
});

test("a grant speaks for a principal only under an active binding", () => {
  const conf = (n: string) => JSON.parse(readFileSync(join(ROOT, "conformance", "vectors", n), "utf8"));
  const cred = conf("grant-principal-credential.json");
  const grant = conf("grant-principal-grant.json");
  const active = conf("grant-principal-binding-active.json");
  const now = "2026-05-01T00:00:30Z";
  assert.equal(grantPrincipalBound(grant, active, cred, now), true);
  assert.equal(grantPrincipalBound(grant, conf("grant-principal-binding-revoked.json"), cred, now), false,
    "a binding the issuer revoked (the lost-device case) speaks for nobody");
  assert.equal(grantPrincipalBound(conf("grant-principal-grant-stranger.json"), active, cred, now), false,
    "a grant signed by a key no issuer bound");
  assert.equal(grantPrincipalBound(grant, active, { ...cred, token_value: "OTHER" }, now), false,
    "a binding for another credential");
  assert.equal(grantPrincipalBound(grant, { ...active, holder_public_key_hex: "aa".repeat(32) }, cred, now), false,
    "a binding edited after signing");
  assert.equal(grantPrincipalBound(grant, conf("grant-principal-binding-wrong-type.json"), cred, now), false,
    "a genuine issuer-signed object of another type, carrying a binding's fields, is not a binding");
  assert.equal(grantPrincipalBound(grant, "binding", cred, now), false);
});

// The exchange in use (1.0.0-rc.64): the same questions the detached verifier answers.
const xch = (n: string) => JSON.parse(readFileSync(join(ROOT, "conformance", "vectors", `exchange-use-${n}.json`), "utf8"));
const XNOW = "2026-05-01T00:00:30Z";

test("an exchange request answers who, whether authorized and what body", () => {
  const env = xch("request"); const man = xch("manifest");
  const me = env.requester.public_key_hex;
  const body = { ask: "balance", account: "notional-7" };
  const v = verifyExchangeRequest(env, me.toUpperCase(), [man], body, XNOW);
  assert.deepEqual([v.authentic, v.requesterMatches, v.requesterAuthorized, v.bodyBound], [true, true, true, true]);
  assert.equal(verifyExchangeRequest(env).requesterAuthorized, null, "no manifests is no answer");
  assert.equal(verifyExchangeRequest(env, "aa".repeat(32), null, null, XNOW).requesterMatches, false);
  assert.equal(verifyExchangeRequest(env, 7 as any, null, null, XNOW).requesterMatches, false);
  const closed = { ...man, attestations: man.attestations.map((a: any) => ({ ...a, valid_until: "whenever" })) };
  const refusals: [string, any, any, string][] = [
    ["a context the requester is not attested in", xch("request-context-3"), [man], XNOW],
    ["an attestation added after the authority signed", xch("request-context-3"), [xch("manifest-forged")], XNOW],
    ["an attestation whose own window closed", xch("request-context-2"), [man], XNOW],
    ["a manifest that expired before the instant decided", env, [man], "2026-05-03T00:00:00Z"],
    ["a manifest decided before it was issued", env, [man], "2026-04-01T00:00:00Z"],
    ["an attestation window nobody can read", env, [closed], XNOW],
    ["manifests that are not a list", env, man, XNOW],
    ["a manifest that is not an object", env, ["manifest"], XNOW]];
  for (const [label, e, mans, at] of refusals) {
    assert.equal(verifyExchangeRequest(e, null, mans, null, at).requesterAuthorized, false, label);
  }
  assert.equal(verifyExchangeRequest(env, null, null, { ...body, account: "x" }).bodyBound, false);
  for (const [label, bad] of [["a stranger's signature in the requester's name", xch("request-stranger")],
                              ["edited after signing", xch("request-tampered")],
                              ["another format", { ...env, format: "polaris-exchange-receipt/1" }],
                              ["not an object", "envelope"]] as [string, any][]) {
    const b = verifyExchangeRequest(bad, me, [man], body, XNOW);
    assert.deepEqual([b.authentic, b.requesterMatches, b.requesterAuthorized, b.bodyBound],
      [false, null, null, null], label + " answers nothing");
  }
});

test("an exchange receipt answers who, whether authorized, by whom and what bodies", () => {
  const rc = xch("receipt"); const man = xch("manifest");
  const req = '{"account":"notional-7","ask":"balance"}';
  const resp = '{"balance":"notional"}';
  const v = verifyExchangeReceipt(rc, XNOW, [man], rc.public_key_hex, req, new TextEncoder().encode(resp));
  assert.deepEqual([v.authentic, v.responderMatches, v.requesterAuthorized, v.via, v.requestBound, v.responseBound, v.responder],
    [true, true, true, man.authority, true, true, rc.responder]);
  assert.equal(verifyExchangeReceipt(rc, null, null, "aa".repeat(32)).responderMatches, false);
  assert.equal(verifyExchangeReceipt(rc, null, null, null, " " + req).requestBound, false,
    "the body is hashed as given, never re-serialized");
  assert.equal(verifyExchangeReceipt(rc, null, null, null, null, "{}").responseBound, false);
  const refusals: [string, any, any][] = [
    ["a receipt that states no context, beside an attestation in context 1", xch("receipt-no-context"), [man]],
    ["a context the requester is not attested in", xch("receipt-context-3"), [man]],
    ["a manifest that is not genuine", rc, [xch("manifest-forged")]],
    ["a genuine manifest that names no authority, so `via` could name nobody", rc, [xch("manifest-nameless")]]];
  for (const [label, r, mans] of refusals) {
    const b = verifyExchangeReceipt(r, XNOW, mans);
    assert.deepEqual([b.requesterAuthorized, b.via], [false, null], label);
  }
  for (const [label, bad] of [["edited after signing", xch("receipt-tampered")],
                              ["another format", { ...rc, format: "polaris-exchange-request/1" }],
                              ["not an object", ["receipt"]]] as [string, any][]) {
    const b = verifyExchangeReceipt(bad, XNOW, [man], rc.public_key_hex, req, resp);
    assert.deepEqual([b.authentic, b.responderMatches, b.requesterAuthorized, b.via, b.requestBound, b.responseBound, b.responder],
      [false, null, null, null, null, null, null], label + " answers nothing and names no responder");
  }
});

test("an exchange mint answers whose it is", () => {
  const m = xch("mint");
  assert.equal(verifyExchangeMint(m, m.public_key_hex.toUpperCase()).responderMatches, true);
  assert.equal(verifyExchangeMint(m).responderMatches, null);
  assert.equal(verifyExchangeMint(m, "aa".repeat(32)).responderMatches, false);
  for (const bad of [xch("mint-tampered"), { ...m, format: "polaris-exchange-receipt/1" }, "mint"]) {
    const b = verifyExchangeMint(bad, m.public_key_hex);
    assert.deepEqual([b.authentic, b.responderMatches], [false, null]);
  }
});

test("an agent proof must bind this grant, this action and this nonce", () => {
  const grant = { grant_id: "g1", agent_public_key_hex: "AA".repeat(32), agent_algorithm: "ML-DSA-65" };
  const good = { format: "polaris-agent-proof/1", grant_id: "g1", public_key_hex: "aa".repeat(32),
                 algorithm: "ML-DSA-65", action: "read:status", service_nonce: "n-1" };
  assert.equal(agentProofProves(good, grant, "read:status", "n-1"), true, "the matching proof proves the agent");
  assert.equal(agentProofProves(good, grant), true);
  assert.equal(agentProofProves({ ...good, format: "polaris-grant-revocation/1" }, grant), false);
  assert.equal(agentProofProves({ ...good, grant_id: "g2" }, grant), false, "another grant's proof");
  assert.equal(agentProofProves({ ...good, public_key_hex: "bb".repeat(32) }, grant), false,
    "a key the grant does not name: a copied grant is not a bearer token");
  assert.equal(agentProofProves({ ...good, algorithm: "ML-DSA-87" }, grant), false,
    "an algorithm the holder did not authorize");
  assert.equal(agentProofProves(good, grant, "read:status", "n-2"), false, "a replay to another service");
  assert.equal(agentProofProves(good, grant, "transfer:funds", "n-1"), false, "another action");
  assert.equal(agentProofProves("proof", grant), false);
});

// ---------------------------------------------------------------------------
// Every refusal in this file, exercised so that inverting it goes red.
//
// scripts/polaris-sdk-mutation-drill.py turns each `return false` into `return true`
// and each `throw` into nothing, then asks whether these tests and the conformance
// suite notice. The first run over this file answered 9 of 14 unprotected, among them
// sameBytes's length guard -- inverted, two byte arrays of DIFFERENT lengths compare
// as equal, so a 32-byte Merkle root matches a five-byte value.
//
// sameBytes and hexToBytes are internal, so they are reached through the public API
// rather than exported for a test: exporting them would widen a published SDK's
// surface to suit its own suite.
// ---------------------------------------------------------------------------

test("a leaf index outside the tree does not verify", () => {
  const leaf = new Uint8Array(32).fill(0x11), root = new Uint8Array(32).fill(0x22);
  for (const [idx, size] of [[-1, 4], [4, 4], [99, 4], [1.5, 4]] as [number, number][]) {
    assert.equal(verifyInclusion(idx, size, leaf, root, []), false, `idx=${idx} size=${size}`);
  }
});

test("a malformed proof node does not verify", () => {
  const leaf = new Uint8Array(32).fill(0x11), root = new Uint8Array(32).fill(0x22);
  assert.equal(verifyInclusion(0, 4, leaf, root, ["nope" as any]), false,
               "a path element that is not bytes must not verify");
  assert.equal(verifyInclusion(0, 1, leaf, root, [new Uint8Array(32)]), false,
               "a one-leaf tree admits no path; a supplied one must not verify");
});

test("a root of the wrong length does not match (sameBytes length guard)", () => {
  // A single-leaf tree: the computed root IS the leaf, so this isolates the comparison.
  const leaf = new Uint8Array(32).fill(0x11);
  assert.equal(verifyInclusion(0, 1, leaf, leaf, []), true, "the leaf is the root of a 1-leaf tree");
  assert.equal(verifyInclusion(0, 1, leaf, new Uint8Array(5).fill(0x11), []), false,
               "a root of a different LENGTH must not compare equal");
  assert.equal(verifyInclusion(0, 1, leaf, new Uint8Array(0), []), false,
               "an empty root must not compare equal");
});

test("malformed hex is refused rather than parsed", () => {
  // hexToBytes throws on odd-length or non-string input; verifyAuthenticity must turn
  // that into a verdict of not-authentic, never a pass and never an escaping throw.
  const pack = vec("ml-dsa-65-valid.json");
  for (const bad of ["abc", "zz", "", null, 1234]) {
    const broken = { ...pack, public_key_hex: bad as any };
    let verdict: any;
    assert.doesNotThrow(() => { verdict = verifyAuthenticity(broken); },
                        `public_key_hex=${String(bad)} must not throw out of the SDK`);
    assert.notEqual(verdict.authentic, true, `public_key_hex=${String(bad)} must not verify`);
  }
  for (const bad of ["abc", "zz", ""]) {
    const broken = { ...pack, signature_hex: bad };
    let verdict: any;
    assert.doesNotThrow(() => { verdict = verifyAuthenticity(broken); });
    assert.notEqual(verdict.authentic, true, `signature_hex=${bad} must not verify`);
  }
});

test("linking refuses anything that is not a pair of strings", () => {
  for (const fn of [nullifiersLink, handlesLink]) {
    for (const [a, b] of [[null, "ab"], ["ab", null], [1, 2], [{}, []], [undefined, "ab"]]) {
      assert.equal((fn as any)(a, b), false,
                   `${fn.name} must not answer for non-strings`);
    }
  }
});

test("a revocation must be an object, and name this grant", () => {
  const grant = { grant_id: "g-1", public_key_hex: "AA".repeat(32) };
  const good = { format: "polaris-grant-revocation/1", grant_id: "g-1",
                 public_key_hex: "aa".repeat(32) };
  assert.equal(revocationEndsGrant(good, grant), true, "the matching revocation ends it");
  for (const [label, bad] of [["not an object", "revoked"],
                              ["null", null],
                              ["wrong format", { ...good, format: "polaris-grant/1" }],
                              ["another grant's id", { ...good, grant_id: "g-2" }],
                              ["a different key", { ...good, public_key_hex: "bb".repeat(32) }]] as [string, any][]) {
    assert.equal(revocationEndsGrant(bad, grant), false, `${label} must not end this grant`);
  }
  assert.equal(revocationEndsGrant(good, "grant" as any), false, "a non-object grant ends nothing");
});

// Every structural refusal, driven from a table. The mutation drill reached only
// `return false` and `throw` until 2026-09-13; the refusals expressed as a returned
// VERDICT OBJECT -- `return { authentic: false, note: "not a polaris-status-assertion/1" }`
// -- were never inverted, and there are 29 of them. Flipped, each reports material the
// verifier exists to reject as AUTHENTIC.
const PLACEHOLDER = "DETERMINISTIC-PLACEHOLDER-SHA3-256";
const KEY = "ab".repeat(1952);
const SIG = "cd".repeat(3309);

const STRUCTURAL_REFUSALS: Array<[string, (o: any) => any]> = [
  ["status assertion in the wrong format", verifyStatusAssertion],
  ["status assertion with the dev placeholder", verifyStatusAssertion],
  ["id token in the wrong format", verifyIdToken],
  ["artifact of an unknown type", verifySignedArtifact],
  ["artifact with the dev placeholder", verifySignedArtifact],
  ["artifact with an unaccepted algorithm", verifySignedArtifact],
  ["cosignature in the wrong format", verifyCosignature],
  ["cosignature with the dev placeholder", verifyCosignature],
  ["cosignature with an unaccepted algorithm", verifyCosignature],
  ["attestation with no signature at all", verifyAttestation],
  ["attestation in the wrong format", verifyAttestation],
  ["attestation with the dev placeholder", verifyAttestation],
  ["attestation with an unaccepted algorithm", verifyAttestation],
  ["status assertion with an unaccepted algorithm", verifyStatusAssertion],
];

const STRUCTURAL_INPUTS: Record<string, any> = {
  "status assertion in the wrong format":
    { format: "not-a-status-assertion", algorithm: "ML-DSA-65", public_key_hex: KEY, signature_hex: SIG },
  "status assertion with the dev placeholder":
    { format: "polaris-status-assertion/1", algorithm: PLACEHOLDER, public_key_hex: KEY, signature_hex: SIG },
  "id token in the wrong format":
    { format: "not-an-id-token", algorithm: "ML-DSA-65", public_key_hex: KEY, signature_hex: SIG },
  "artifact of an unknown type":
    { format: "polaris-nonesuch/1", algorithm: "ML-DSA-65", public_key_hex: KEY, signature_hex: SIG },
  "artifact with the dev placeholder":
    { format: "polaris-revocation-feed/1", algorithm: PLACEHOLDER, public_key_hex: KEY, signature_hex: SIG },
  "artifact with an unaccepted algorithm":
    { format: "polaris-revocation-feed/1", algorithm: "ML-DSA-44", public_key_hex: KEY, signature_hex: SIG },
  "cosignature in the wrong format":
    { format: "not-a-cosignature", algorithm: "ML-DSA-65", public_key_hex: KEY, signature_hex: SIG },
  "cosignature with the dev placeholder":
    { format: "polaris-transparency-cosignature/1", algorithm: PLACEHOLDER, public_key_hex: KEY, signature_hex: SIG },
  "cosignature with an unaccepted algorithm":
    { format: "polaris-transparency-cosignature/1", algorithm: "ML-DSA-44", public_key_hex: KEY, signature_hex: SIG },
  "attestation with no signature at all":
    { format: "polaris-trust-attestation/1", algorithm: "ML-DSA-65" },
  "attestation in the wrong format":
    { format: "not-an-attestation", algorithm: "ML-DSA-65", public_key_hex: KEY, signature_hex: SIG },
  "attestation with the dev placeholder":
    { format: "polaris-trust-attestation/1", algorithm: PLACEHOLDER, public_key_hex: KEY, signature_hex: SIG },
  "attestation with an unaccepted algorithm":
    { format: "polaris-trust-attestation/1", algorithm: "ML-DSA-44", public_key_hex: KEY, signature_hex: SIG },
  "status assertion with an unaccepted algorithm":
    { format: "polaris-status-assertion/1", algorithm: "ML-DSA-44", public_key_hex: KEY, signature_hex: SIG },
};

// The two DECISION paths that reject because the credential underneath is not authentic.
// Inverted, a presentation or a cross-authority check ACCEPTS a credential whose own
// signature never verified, which is the decision both functions exist to make.
const NOT_AUTHENTIC_PACK = {
  format: "polaris-authenticity-pack/1", token_value: "T", algorithm: "ML-DSA-65",
  public_key_hex: KEY, signature_hex: SIG,
};

test("a cross-authority decision rejects a credential that is not authentic", () => {
  const v = verifyCrossAuthority(NOT_AUTHENTIC_PACK, 1, []);
  assert.strictEqual(v.decision, "reject",
    "a pack whose signature does not verify must not cross an authority boundary");
  assert.strictEqual(v.authentic, false);
});

test("a presentation is rejected when its credential is not authentic", async () => {
  const verdict = await new PolarisVerifier().verifyPresentation({ credential: NOT_AUTHENTIC_PACK });
  assert.strictEqual(verdict.decision, "reject",
    "a presentation carrying an unverifiable credential must be rejected");
  assert.strictEqual(verdict.authentic, false);
});

test("every structural refusal refuses (table-driven)", async () => {
  for (const [label, fn] of STRUCTURAL_REFUSALS) {
    const v = await fn(STRUCTURAL_INPUTS[label]);
    assert.strictEqual(
      v.authentic, false,
      `${label} must not be reported authentic; the verifier returned ${v.authentic}`);
  }
});

test("a broken commitment reports freshness the same way in every artifact", () => {
  // Five formats in verifySignedArtifact check a commitment that rides outside the signed
  // statement. Four fell through to the tail and reported the window's answer for `fresh`;
  // epoch-leaves returned early with `fresh: null`. Same class of failure, two different
  // verdicts, inside one implementation, and the Python SDK fell through for all five, so
  // the two published reference SDKs disagreed. No conformance case constrains `fresh` on
  // that artifact, so the suite could not see it: scripts/polaris-sdk-agreement-drill.py
  // found it by comparing the SDKs to each other instead of to the contract.
  const swapped = JSON.parse(readFileSync(
    join(ROOT, "conformance", "vectors", "epoch-leaves-swapped.json"), "utf8"));
  const feed = JSON.parse(readFileSync(
    join(ROOT, "conformance", "vectors", "revocation-feed-commitment-mismatch.json"), "utf8"));
  const now = "2026-05-01T00:00:30Z";

  const leaves = verifySignedArtifact(swapped, now);
  const revocation = verifySignedArtifact(feed, now);
  assert.equal(leaves.authentic, false, "a swapped leaf set is not authentic");
  assert.equal(revocation.authentic, false, "a mismatched feed commitment is not authentic");
  assert.equal(typeof leaves.fresh, typeof revocation.fresh,
    `epoch-leaves reported fresh=${JSON.stringify(leaves.fresh)} while revocation-feed ` +
    `reported ${JSON.stringify(revocation.fresh)}: the same failure answering differently`);
  assert.equal(leaves.note, "the published leaves do not match the committed set",
    "falling through must not lose the reason");
});


// 2026-09-17: an adversarial review compared this SDK against the Python reference and found
// them disagreeing on inputs a federation of national agencies produces every day. Two
// divergences made this SDK REJECT genuinely-signed artifacts; two made it accept what the
// reference refuses. Every case below was executed against both sides first.

test("canonical JSON escapes non-ASCII the way the wire format does", () => {
  // The comment on canonicalJson claimed it matched Python byte for byte. It did not, for
  // any non-ASCII byte: JSON.stringify emits raw UTF-8 and json.dumps escapes to uXXXX.
  // Measured with real ML-DSA-65 signatures: an artifact whose signer carries an accent
  // verified in Python and was REJECTED here. No JSON fixture in the tree has a non-ASCII
  // byte, which is why nothing caught it, and an accent in an agency name is ordinary.
  const cases: [unknown, string][] = [
    [{ signer: "Ministere des Affaires \u00c9trang\u00e8res" },
     '{"signer":"Ministere des Affaires \\u00c9trang\\u00e8res"}'],
    [{ purpose: "\u6771\u4eac" },
     '{"purpose":"\\u6771\\u4eac"}'],
    [{ emoji: "\u{1F600}" },
     '{"emoji":"\\ud83d\\ude00"}'],
    [{ del: "\u007f", ctl: "\u001f" },
     '{"ctl":"\\u001f","del":"\\u007f"}'],
    [{ "\u00e9": "an accented KEY" },
     '{"\\u00e9":"an accented KEY"}'],
    [{ z: 1, a: [1, { y: "\u00ff", x: null }] },
     '{"a":[1,{"x":null,"y":"\\u00ff"}],"z":1}'],
  ];
  for (const [value, expected] of cases) {
    assert.equal(__canonicalJsonForTest(value), expected,
      "canonical form must equal Python json.dumps(sort_keys=True, separators=(',',':'))");
  }
});

test("an instant with no offset is read as UTC, not as local time", () => {
  // Date.parse reads an offset-less date-time as LOCAL. The Python reference stamps it UTC.
  // Measured: an epoch checkpoint whose window closed three hours earlier verified as FRESH
  // for any verifier west of UTC. The wire spec requires issued_at <= now < expires_at, and
  // a window that means something different depending on where the verifier stands is not
  // that window.
  assert.equal(__isoToEpochForTest("2026-09-17T09:00:00"), Date.UTC(2026, 8, 17, 9) / 1000,
    "no offset must mean UTC, whatever the machine timezone is");
  assert.equal(__isoToEpochForTest("2026-09-17T09:00:00Z"), Date.UTC(2026, 8, 17, 9) / 1000);
  assert.equal(__isoToEpochForTest("2026-09-17T09:00:00+02:00"), Date.UTC(2026, 8, 17, 7) / 1000);
  assert.equal(__isoToEpochForTest("2026-09-17T09:00:00-05:00"), Date.UTC(2026, 8, 17, 14) / 1000);
  assert.equal(__isoToEpochForTest("2026-09-17"), Date.UTC(2026, 8, 17) / 1000);
});

test("date shapes the Python reference refuses are refused here too", () => {
  // Date.parse accepted forms fromisoformat does not, so the two sides disagreed on 12 of
  // 33 freshness cases. A verifier that reads more date formats than the signer wrote is
  // not being generous; it is disagreeing about when things expire.
  for (const bad of ["Thu, 17 Sep 2026 13:00:00 GMT", "09/17/2026", "2026-09-17T09",
                     "not a date", "", "2026-9-7T09:00:00Z"]) {
    assert.equal(__isoToEpochForTest(bad), null, bad + " must not parse");
  }
});

test("verifyInclusion refuses arguments that are not bytes", () => {
  // sameBytes had no type check, so two equal-length hex STRINGS compared EQUAL at every
  // position and reported the leaf INCLUDED. Hex is the form these values arrive in inside
  // the proof JSON, so passing it is the natural mistake rather than an exotic one. The
  // Python reference returns false for all of them.
  const bytes = new Uint8Array([1, 2, 3]);
  assert.equal(verifyInclusion(0, 1, "deadbeef" as any, "cafebabe" as any, []), false);
  assert.equal(verifyInclusion(0, 1, "x" as any, new Uint8Array([0]) as any, []), false);
  assert.equal(verifyInclusion(0, 1, ["a"] as any, ["b"] as any, []), false);
  // And the documented totality: false, never a throw.
  assert.equal(verifyInclusion(0, 1, null as any, null as any, []), false);
  assert.equal(verifyInclusion(0, 1, bytes, bytes, {} as any), false);
  // The positive control: a one-leaf tree whose root IS the leaf still verifies, so the
  // guards refuse the wrong TYPE rather than refusing everything.
  assert.equal(verifyInclusion(0, 1, bytes, bytes, []), true);
});

test("a grant limit is refused when either side is not a whole finite number", () => {
  // Number.isFinite guarded maxUses and not usesSoFar, so a NaN use count cleared the limit
  // here exactly as a NaN limit cleared it in the Python reference: each SDK had a hole the
  // other did not, and limits is inside the SIGNED statement.
  assert.equal(grantWithinLimits({ limits: { max_uses: 3 } }, NaN)[0], false);
  assert.equal(grantWithinLimits({ limits: { max_uses: Infinity } }, 0)[0], false);
  assert.equal(grantWithinLimits({ limits: { max_uses: [2] as any } }, 0)[0], false);
  assert.equal(grantWithinLimits({ limits: { max_uses: 1.9 } }, 1)[0], false);
  assert.equal(grantWithinLimits({ limits: { max_amount: NaN } }, 0, 1e9)[0], false);
  assert.equal(grantWithinLimits({ limits: { max_amount: 100 } }, 0, NaN)[0], false);
  // Positive controls, or a function that refused everything would pass all of the above.
  assert.equal(grantWithinLimits({ limits: { max_uses: 3 } }, 1)[0], true);
  assert.equal(grantWithinLimits({ limits: { max_uses: 3 } }, 3)[0], false);
  assert.equal(grantWithinLimits({ limits: { max_amount: 100 } }, 0, 50)[0], true);
  assert.equal(grantWithinLimits({ limits: { max_amount: 100 } }, 0, 1000)[0], false);
});

test("the cached token lifetime is bounded, and matches the Python kit", () => {
  // `JSON.parse` here refuses the bare literals NaN and Infinity, which is stricter than
  // Python. It does NOT refuse `1e400`: that is ordinary JSON grammar and arrives as
  // Infinity in both languages, which is the half of this defect a reader assumes cannot
  // reach JavaScript.
  assert.equal(JSON.parse('{"a": 1e400}').a, Infinity,
    "if this ever throws, the exponent leg of this defect is gone and this test is stale");

  for (const bad of [Infinity, -Infinity, NaN, 0, -1, "300", null, undefined, {}, [], true]) {
    assert.equal(expiresIn(bad as unknown), 300,
      `an unusable expires_in (${String(bad)}) must fall back, not be believed`);
  }
  assert.equal(expiresIn(1e308), 24 * 3600, "an enormous lifetime is capped, not believed");
  assert.equal(expiresIn(99999999), 24 * 3600);
  assert.equal(expiresIn(300), 300, "an ordinary lifetime is used as given");
  assert.equal(expiresIn(3599.9), 3599, "a fractional lifetime truncates, never rounds up");
  assert.equal(expiresIn(24 * 3600), 24 * 3600, "the cap itself is admissible");
});


// 2026-09-23: ten semantic mutations written AFTER the refusal drill was green. Eight
// survived this suite and the conformance runner (a not-yet-valid window, a doubled replay
// window, a future-dated proof, an inclusion bound off by one, the exhausted-tree test
// skipped, a case-sensitive revocation lookup, a doubled amount limit, a cosignature from
// the wrong witness). The drill inverts refusals; none of these is an inverted refusal, it
// is a boundary moved. Each test pins one boundary where the mutation changes the answer.
// The Python SDK carries the same tests, against the same fixtures.
const conf = (n: string) => JSON.parse(readFileSync(join(ROOT, "conformance", "vectors", n), "utf8"));

test("held-out: a status assertion is not fresh before its window opens", () => {
  const a = conf("status-assertion-valid.json");   // [2026-01-01, 2027-01-01)
  assert.equal(verifyStatusAssertion(a, "2026-01-01T00:00:00Z").fresh, true);
  assert.equal(verifyStatusAssertion(a, "2025-12-31T23:59:59Z").fresh, false,
    "an assertion is not fresh one second before it was issued");
  assert.equal(verifyStatusAssertion(a, "2027-01-01T00:00:00Z").fresh, false,
    "the window is half-open: expires_at itself is outside it");
});

test("held-out: a holder proof is fresh for exactly its replay window", () => {
  const p = conf("holder-proof-valid.json");       // issued 2026-05-01T00:00:00Z
  assert.equal(verifySignedArtifact(p, "2026-05-01T00:05:00Z").fresh, true);
  assert.equal(verifySignedArtifact(p, "2026-05-01T00:05:01Z").fresh, false,
    "a holder proof 301 seconds old is a replay");
});

test("held-out: a holder proof from the future is fresh only within the skew", () => {
  const p = conf("holder-proof-valid.json");
  assert.equal(verifySignedArtifact(p, "2026-04-30T23:59:00Z").fresh, true);
  assert.equal(verifySignedArtifact(p, "2026-04-30T23:58:59Z").fresh, false,
    "a proof 61 seconds ahead of the verifier's clock is not fresh");
});

test("held-out: an index equal to the tree size does not verify", () => {
  // A one-leaf tree whose root is the leaf: at idx == treeSize an empty path walks nothing
  // and the comparison alone would say yes.
  const leaf = new Uint8Array(32).fill(0x11);
  assert.equal(verifyInclusion(0, 1, leaf, leaf, []), true);
  assert.equal(verifyInclusion(1, 1, leaf, leaf, []), false);
});

test("held-out: a path too short for the tree does not verify", () => {
  const leaf = new Uint8Array(32).fill(0x11);
  assert.equal(verifyInclusion(0, 2, leaf, leaf, []), false,
    "a two-leaf tree needs one sibling; an empty path proves nothing");
});

test("held-out: an upper-case leaf in a genuine feed still revokes", () => {
  const fx = JSON.parse(readFileSync(join(ROOT, "sdk", "testdata", "revocation-uppercase-leaf.json"), "utf8"));
  const { now, context_id } = fx._fixture;
  assert.equal(verifySignedArtifact(fx.feed, now).authentic, true);
  const v = verifyCrossAuthority(fx.pack, context_id, [fx.manifest], null, fx.feed, now);
  assert.equal(v.decision, "reject", String(v.reason));
  assert.match(String(v.reason), /revoked/);
  assert.equal(verifyCrossAuthority(fx.pack, context_id, [fx.manifest], null, null, now).decision,
    "accept", "without the feed the same inputs are accepted");
});

test("held-out: a cosignature from another witness is refused", () => {
  const cos = conf("timestamp-anchor-witnessed.json").anchor.cosignatures;
  assert.equal(verifyCosignature(cos[0], cos[0].public_key_hex).authentic, true);
  assert.equal(verifyCosignature(cos[0], cos[1].public_key_hex).authentic, false);
});

test("held-out: a grant amount is bounded at its limit", () => {
  const g = { limits: { max_amount: 100 } };
  assert.equal(grantWithinLimits(g, 0, 100)[0], true);
  assert.equal(grantWithinLimits(g, 0, 100.01)[0], false);
  assert.equal(grantWithinLimits(g, 0, 150)[0], false);
});


// 2026-09-23: a held-out round on the online half of verifyPresentation. Five of six
// mutations survived: a status check that FAILED returned accept; the untrusted-issuer
// refusal deleted (the test above made the status call throw, so the failed call rejected
// instead); `current` read from the status string; an expired bearer reused; a non-OK
// answer from the verify endpoint parsed as a status. Each test below gives every other
// check a passing answer, so only the mechanism named can refuse.
const PRES = () => ({ credential: vec("ml-dsa-65-valid.json") });

test("held-out: a status check that fails rejects", async () => {
  const v = new PolarisVerifier({ issuerUrl: "http://x" });
  (v as any).onlineStatus = async () => { throw new Error("connection refused"); };
  const out = await v.verifyPresentation(PRES());
  assert.equal(out.decision, "reject");
  assert.equal(out.authentic, true);
});

test("held-out: an untrusted issuer is rejected even when the status says current", async () => {
  const v = new PolarisVerifier({ issuerUrl: "http://x", anchors: ["00"] });
  (v as any).onlineStatus = async () => ({ currently_authoritative: true, status: "ACTIVE" });
  assert.equal((await v.verifyPresentation(PRES())).decision, "reject");
});

test("held-out: only the authoritative flag makes a credential current", async () => {
  for (const status of [{ currently_authoritative: false, status: "SUSPENDED" },
                        { currently_authoritative: false, status: "ACTIVE" },
                        { status: "ACTIVE" }, {}]) {
    const v = new PolarisVerifier({ issuerUrl: "http://x" });
    (v as any).onlineStatus = async () => status;
    assert.equal((await v.verifyPresentation(PRES())).decision, "reject", JSON.stringify(status));
  }
});

test("held-out: a bearer is reused until five seconds before expiry and no later", async () => {
  const saved = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async () => {
    calls++;
    return { ok: true, status: 200, json: async () => ({ access_token: "new", expires_in: 300 }) };
  }) as any;
  try {
    const v = new PolarisVerifier({ issuerUrl: "http://x", clientId: "c", clientSecret: "s" });
    (v as any).bearer = "old";
    (v as any).bearerExp = Date.now() + 60_000;
    assert.equal(await (v as any).accessToken(), "old");
    assert.equal(calls, 0);
    (v as any).bearerExp = Date.now() + 4_000;
    assert.equal(await (v as any).accessToken(), "new", "a token about to expire is replaced");
    (v as any).bearer = "old";
    (v as any).bearerExp = Date.now() - 1;
    assert.equal(await (v as any).accessToken(), "new", "an expired token is never reused");
  } finally {
    globalThis.fetch = saved;
  }
});

test("held-out: a non-OK answer from the verify endpoint is a failed check, not a status", async () => {
  const saved = globalThis.fetch;
  globalThis.fetch = (async (url: string) => String(url).endsWith("/oauth/token")
    ? { ok: true, status: 200, json: async () => ({ access_token: "t", expires_in: 300 }) }
    : { ok: false, status: 500, json: async () => ({ currently_authoritative: true, status: "ACTIVE" }) }) as any;
  try {
    const v = new PolarisVerifier({ issuerUrl: "http://x", clientId: "c", clientSecret: "s" });
    assert.equal((await v.verifyPresentation(PRES())).decision, "reject");
  } finally {
    globalThis.fetch = saved;
  }
});

test("held-out: a non-OK answer from the token endpoint is a failed check, not a token", async () => {
  // The SDK drill declared this guard and its sibling in onlineStatus unreachable, "no offline
  // suite reaches it". A stubbed fetch reaches both.
  const saved = globalThis.fetch;
  globalThis.fetch = (async (url: string) => String(url).endsWith("/oauth/token")
    ? { ok: false, status: 401, json: async () => ({ access_token: "t", expires_in: 300 }) }
    : { ok: true, status: 200, json: async () => ({ currently_authoritative: true, status: "ACTIVE" }) }) as any;
  try {
    const v = new PolarisVerifier({ issuerUrl: "http://x", clientId: "c", clientSecret: "s" });
    assert.equal((await v.verifyPresentation(PRES())).decision, "reject");
  } finally {
    globalThis.fetch = saved;
  }
});


// 2026-09-23: a held-out round on verifyHolder dropped each fact `proved` needs; 8 of 10
// survived. Only the key match and the nonce were ever isolated. Same tests as the Python
// SDK's, on the same two genuinely signed chains.
const EARLY = JSON.parse(readFileSync(join(ROOT, "sdk", "testdata", "holder-chain-early-binding.json"), "utf8"));
const flip = (o: any) => ({ ...o, signature_hex: (o.signature_hex[0] !== "0" ? "0" : "1") + o.signature_hex.slice(1) });
const earlyProved = (kw: any = {}) => verifyHolder(kw.credential ?? EARLY.credential, kw.binding ?? EARLY.binding,
  kw.proof ?? EARLY.proof, "held-out-nonce", kw.context ?? 1, kw.now ?? "2026-05-01T00:00:10Z").proved;

test("held-out: the genuine holder chain proves", () => {
  assert.equal(earlyProved(), true);
});

test("held-out: each link of the holder chain alone refuses", () => {
  for (const [label, kw] of [["binding not authentic", { binding: flip(EARLY.binding) }],
                             ["proof not authentic", { proof: flip(EARLY.proof) }],
                             ["binding about another token", { credential: { ...EARLY.credential, token_value: "X" } }],
                             ["binding by another issuer", { credential: { ...EARLY.credential, public_key_hex: "ab".repeat(1952) } }],
                             ["another context", { context: 2 }]] as [string, any][]) {
    assert.equal(earlyProved(kw), false, label);
  }
});

test("held-out: the holder proof window is five minutes and a minute of skew", () => {
  for (const [now, proved] of [["2026-05-01T00:05:00Z", true], ["2026-05-01T00:05:01Z", false],
                               ["2026-04-30T23:59:00Z", true], ["2026-04-30T23:58:59Z", false]] as [string, boolean][]) {
    assert.equal(earlyProved({ now }), proved, now);
  }
});

test("held-out: a binding not yet valid refuses while the proof is fresh", () => {
  const at = (now: string) => verifyHolder(conf("holder-credential.json"), conf("holder-binding-valid.json"),
    conf("holder-proof-valid.json"), "rp-nonce-1", null, now);
  assert.equal(at("2026-05-01T00:00:10Z").proved, true);
  const v = at("2026-04-30T23:59:30Z");
  assert.equal(v.bindingFresh, false);
  assert.equal(v.proved, false);
});


// 2026-09-23: the same held-out round on verifyCrossAuthority, over the same genuinely signed
// variants (sdk/testdata/federation-variants.json), each differing from the base in one way.
const FED = JSON.parse(readFileSync(join(ROOT, "sdk", "testdata", "federation-variants.json"), "utf8"));
const fedDecide = (kw: any = {}) => verifyCrossAuthority(
  FED.pack, FED._fixture.context_id, [FED.manifests[kw.manifest ?? "base"]],
  kw.anchors ?? [FED.trusted_anchor], FED.feeds[kw.feed ?? "clean"], FED._fixture.now,
  kw.requireSigned ?? false).decision;

test("held-out: the base federation setup is accepted", () => {
  assert.equal(fedDecide(), "accept");
});

test("held-out: each federation variant is refused", () => {
  for (const [label, kw] of [["a stale manifest", { manifest: "stale" }],
                             ["an attestation of another key", { manifest: "other_key" }],
                             ["a badly signed attestation", { manifest: "bad_attestation_signature" }],
                             ["trust in a RETIRED anchor", { anchors: [FED.retired_anchor] }],
                             ["an unsigned edge when signed edges are required", { requireSigned: true }],
                             ["a stale revocation feed", { feed: "stale" }],
                             ["a feed signed by another issuer", { feed: "other_issuer" }],
                             ["a feed that is not authentic", { feed: "not_authentic" }]] as [string, any][]) {
    assert.equal(fedDecide(kw), "reject", label);
  }
});


// 2026-09-27: verifyCrossAuthority never read a signed edge's `valid_until`, so an edge its
// authority time-boxed kept granting acceptance after the box closed while the manifest carrying
// it was fresh (WIRE-SPEC 3.14). One signed edge in three windows, each under a fresh manifest.
const EDGE = JSON.parse(readFileSync(join(ROOT, "sdk", "testdata", "federation-edge-window.json"), "utf8"));
const edgeDecide = (w: string) => verifyCrossAuthority(EDGE.pack, EDGE._fixture.context_id,
  [EDGE.manifests[w]], [EDGE.trusted_anchor], null, EDGE._fixture.now).decision;

test("a signed edge counts only inside its own window", () => {
  assert.equal(edgeDecide("open"), "accept");
  assert.equal(edgeDecide("closed"), "reject", "an edge past its valid_until");
  assert.equal(edgeDecide("unreadable"), "reject", "an edge whose valid_until cannot be read");
});

// 2026-09-28: the window was read only for a SIGNED edge, so an unsigned (legacy) edge its
// authority's own manifest said had ended still granted acceptance. One stating no window is
// legacy and stays accepted, as the published cross-authority vectors require.
test("an unsigned edge is held to the window it states", () => {
  assert.equal(edgeDecide("unsigned-open"), "accept");
  assert.equal(edgeDecide("unsigned-closed"), "reject", "an unsigned edge past its valid_until");
  assert.equal(edgeDecide("unsigned-unreadable"), "reject", "an unsigned edge whose valid_until cannot be read");
  assert.equal(edgeDecide("unsigned-no-window"), "accept", "a legacy edge that states no window");
});

// 2026-09-23: a held-out round on verifyTimestampAnchor. The published witnessed anchor covers
// the rules a test can reach by editing unsigned fields; sdk/testdata/anchor-variants.json holds
// genuinely signed variants for the three it cannot (a head for another log, cosignatures over
// another tree size or root), because a signature verdict cannot be replaced from a test here.
const ANCH = JSON.parse(readFileSync(join(ROOT, "sdk", "testdata", "anchor-variants.json"), "utf8"));
const witnessedTs = () => JSON.parse(JSON.stringify(conf("timestamp-anchor-witnessed.json")));
const bothWitnesses = (ts: any) => ts.anchor.cosignatures.map((c: any) => c.public_key_hex);

test("held-out: the genuine anchor is anchored and witnessed", () => {
  const ts = witnessedTs();
  const v = verifyTimestampAnchor(ts, null, bothWitnesses(ts), 2);
  assert.equal(v.anchored, true);
  assert.equal(v.witnessed, true);
});

test("held-out: an anchor refuses a proof for another entry, another root, a bad head, another log key", () => {
  const cases: [string, (ts: any) => void, string | null][] = [
    ["another entry", (ts) => { ts.anchor.proof.entry_hex = "00".repeat(32); }, null],
    ["another root in the proof", (ts) => { ts.anchor.proof.root_hash_hex = "00".repeat(32); }, null],
    ["an unauthentic head", (ts) => { const s = ts.anchor.sth.signature_hex; ts.anchor.sth.signature_hex = (s[0] !== "0" ? "0" : "1") + s.slice(1); }, null],
    ["another log key", () => {}, "ab".repeat(1952)],
  ];
  for (const [label, edit, logKey] of cases) {
    const ts = witnessedTs();
    edit(ts);
    assert.equal(verifyTimestampAnchor(ts, logKey, bothWitnesses(ts), 2).anchored, false, label);
  }
});

test("held-out: only trusted, distinct witnesses over this exact head count", () => {
  const ts = witnessedTs();
  const one = verifyTimestampAnchor(ts, null, bothWitnesses(ts).slice(0, 1), 2);
  assert.deepEqual([one.cosignerCount, one.witnessed], [1, false], "an untrusted cosigner counted");
  ts.anchor.cosignatures = [ts.anchor.cosignatures[0], { ...ts.anchor.cosignatures[0] }];
  const dup = verifyTimestampAnchor(ts, null, bothWitnesses(witnessedTs()), 2);
  assert.deepEqual([dup.cosignerCount, dup.witnessed], [1, false], "one witness counted twice");
  for (const variant of ["cosig_other_size", "cosig_other_root"]) {
    const v = verifyTimestampAnchor(ANCH[variant], ANCH.log_key, ANCH.witnesses, 2);
    assert.deepEqual([v.anchored, v.cosignerCount, v.witnessed], [true, 1, false], variant);
  }
  assert.equal(verifyTimestampAnchor(ANCH.base, ANCH.log_key, ANCH.witnesses, 2).witnessed, true);
});

test("held-out: a genuinely signed head for another log does not anchor", () => {
  assert.equal(verifyTimestampAnchor(ANCH.other_log, ANCH.log_key, ANCH.witnesses, 2).anchored, false);
});


test("held-out: grant actions are exact strings", () => {
  // A held-out mutation matching actions case-insensitively survived both SDKs (2026-09-23).
  for (const action of ["READ:STATUS", "read:status ", "read"]) {
    assert.equal(grantCovers(GRANT, action), false, action);
  }
});


test("an impossible date is refused, as the Python kit refuses it", () => {
  // Date.UTC rolled these over into real dates; datetime.fromisoformat refuses every one.
  for (const s of ["2026-02-31T00:00:00Z", "2026-13-01T00:00:00Z", "2026-01-01T25:00:00Z",
                   "2026-01-01T12:60:00Z", "2026-02-29T00:00:00Z"]) {
    assert.equal(__isoToEpochForTest(s), null, s);
  }
  assert.equal(__isoToEpochForTest("2028-02-29T00:00:00Z"), Date.UTC(2028, 1, 29) / 1000,
               "control: a real leap day is accepted");
});


test("the ISO instant grammar both reference SDKs share", () => {
  const cases = JSON.parse(readFileSync(join(ROOT, "sdk", "testdata", "iso-instants.json"), "utf8")).cases;
  for (const c of cases) {
    const got = __isoToEpochForTest(c.input);
    assert.equal(got === null ? null : Math.round(got), c.epoch, c.input);
  }
});

// WIRE-SPEC 3.7 (2026-09-27): a pack's token_value is a credential serial. A pack is signed over
// SHA3-256(token_value) and every other artifact over SHA3-256 of its canonical JSON statement,
// so without this rule an authority-signed artifact, its signature re-wrapped as a pack whose
// token_value is its canonical statement, verified as an authentic credential.
test("a token value is a credential serial (the same rule as the Python verifiers)", () => {
  for (const t of ["POLARIS-VECTOR-VALID-0001", "A".repeat(128), "TKN-\u00e9-1", "}{", "x{"]) {
    assert.equal(tokenValueSerialProblem(t), null, t);
  }
  for (const t of ['{"format":"x"}', "{", "", "A".repeat(129), "\u00e9".repeat(65), "TKN-\n", "TKN-\x7f",
                   "TKN-\u0085", "TKN-\ud800", null, 1, ["x"]]) {
    assert.notEqual(tokenValueSerialProblem(t), null, JSON.stringify(t));
  }
});

test("a transplanted artifact signature is not a credential", () => {
  const m = JSON.parse(readFileSync(join(ROOT, "conformance", "vectors", "federation-manifest-valid.json"), "utf8"));
  // Positive control: the manifest's own signature is genuine, so the refusal below is the
  // serial rule's and not a bad signature's.
  assert.equal(verifySignedArtifact(m).authentic, true);
  const keys = ["format", "authority", "anchors", "attestations", "epoch", "revocation", "issued_at", "expires_at", "algorithm"];
  const stmt: Record<string, unknown> = {};
  for (const k of keys) stmt[k] = m[k] ?? null;
  const pack = { token_value: __canonicalJsonForTest(stmt), algorithm: m.algorithm,
                 signature_hex: m.signature_hex, public_key_hex: m.public_key_hex };
  const v = verifyAuthenticity(pack, [m.public_key_hex]);
  assert.equal(v.authentic, false);
  assert.equal(v.issuerTrusted, null);
  assert.match(v.note ?? "", /not a credential serial/);
});

test("an artifact whose format is not a string, or names a prototype member, is unknown", () => {
  const conf = (n: string) => JSON.parse(readFileSync(join(ROOT, "conformance", "vectors", n), "utf8"));
  const ck = conf("epoch-checkpoint-valid.json");
  const now = "2026-06-01T00:00:00Z";
  const good = verifySignedArtifact(ck, now);
  assert.equal(good.authentic, true, good.note ?? "");
  assert.equal(good.fresh, true);
  for (const format of [[ck.format], { a: 1 }, 5, "constructor", "toString", "__proto__", "hasOwnProperty"]) {
    const v = verifySignedArtifact({ ...ck, format }, now);
    assert.equal(v.authentic, false, String(format));
    assert.equal(v.fresh, null, "fresh is not evaluated for an unknown artifact: " + String(format));
    assert.match(v.note ?? "", /unknown or unsupported artifact/, String(format));
  }
});


// 2026-09-29: branches no unit test reached. The conformance runner drives most of these
// formats, but through `node src/conformance.ts` in a child process per case, which this
// suite's coverage does not see; each test pins one here, with a genuine artifact beside
// every refusal so the refusal is the rule's and not a broken fixture's.
test("a registry is authentic only when an active authority of its publisher signed it", () => {
  assert.equal(verifySignedArtifact(conf("registry-valid.json")).authentic, true);
  assert.equal(verifySignedArtifact(conf("registry-impostor.json")).authentic, false,
    "signed by a key the registry does not list for its publisher");
});

test("a trust list is authentic only when an active key of its publisher signed it", () => {
  assert.equal(verifySignedArtifact(conf("trust-list-valid.json")).authentic, true);
  assert.equal(verifySignedArtifact(conf("trust-list-impostor.json")).authentic, false);
});

test("a federation status bundle must commit to the members it carries", () => {
  assert.equal(verifySignedArtifact(conf("federation-status-bundle-valid.json")).authentic, true);
  assert.equal(verifySignedArtifact(conf("federation-status-bundle-commitment-mismatch.json")).authentic, false);
});

test("a pack without a token or signature, or under an unknown algorithm, is refused with its reason", () => {
  const good = vec("ml-dsa-65-valid.json");
  assert.equal(verifyAuthenticity(good).authentic, true);
  const bare = verifyAuthenticity({ ...good, token_value: "" });
  assert.equal(bare.authentic, false);
  assert.match(bare.note ?? "", /missing token_value or signature_hex/);
  const alien = verifyAuthenticity({ ...good, algorithm: "RSA-2048" });
  assert.equal(alien.authentic, false);
  assert.match(alien.note ?? "", /unknown or unaccepted signature algorithm/);
});

test("a signature or key that does not decode is a verification error, never a throw", () => {
  const now = "2026-06-01T00:00:00Z";
  const sa = conf("status-assertion-valid.json");
  assert.equal(verifyStatusAssertion(sa, now).authentic, true);
  const bad = verifyStatusAssertion({ ...sa, signature_hex: "abc" }, now);
  assert.equal(bad.authentic, false);
  assert.match(bad.note ?? "", /verification error/);
  const reg = conf("registry-valid.json");
  const art = verifySignedArtifact({ ...reg, public_key_hex: "abc" });
  assert.equal(art.authentic, false);
  assert.match(art.note ?? "", /verification error/);
});

test("an id-token of another format, or whose signature fails, carries the reason", () => {
  assert.equal(verifyIdToken(conf("id-token-valid.json")).authentic, true);
  const other = verifyIdToken({ format: "polaris-trust-list/1" });
  assert.equal(other.authentic, false);
  assert.match(other.note ?? "", /not a polaris-id-token\/1/);
  const forged = verifyIdToken(conf("id-token-tampered.json"));
  assert.equal(forged.authentic, false);
  assert.equal(forged.fresh, null, "freshness is not judged for a token that is not authentic");
});

test("a cosignature from another witness, or one that does not decode, is not authentic", () => {
  const c = conf("timestamp-anchor-witnessed.json").anchor.cosignatures[0];
  assert.equal(verifyCosignature(c).authentic, true);
  assert.equal(verifyCosignature(c, c.public_key_hex).authentic, true);
  const other = verifyCosignature(c, "00".repeat(32));
  assert.equal(other.authentic, false);
  assert.match(other.note ?? "", /not from the expected witness/);
  const bad = verifyCosignature({ ...c, signature_hex: "abc" });
  assert.equal(bad.authentic, false);
  assert.match(bad.note ?? "", /verification error/);
});

test("a timestamp anchor that is missing, misshapen, for another entry or another log is not anchored", () => {
  const ts = witnessedTs();
  assert.equal(verifyTimestampAnchor(ts, null, bothWitnesses(ts), 2).anchored, true);
  const cases: [any, RegExp][] = [
    [null, /must be an object/],
    [{ ...ts, anchor: null }, /carries no anchor/],
    [{ ...ts, anchor: { ...ts.anchor, proof: null } }, /must be objects/],
    [{ ...ts, anchor: { ...ts.anchor, proof: { ...ts.anchor.proof, entry_hex: "00" } } }, /not for this timestamp/],
    [{ ...ts, anchor: { ...ts.anchor, proof: { ...ts.anchor.proof, log_id: "another-log" } } }, /is not a polaris-timestamp-log head/],
    [{ ...ts, anchor: { ...ts.anchor, proof: { ...ts.anchor.proof, proof_hex: ["abc"] } } }, /malformed proof/],
  ];
  for (const [t, why] of cases) {
    const v = verifyTimestampAnchor(t, null, bothWitnesses(ts), 2);
    assert.equal(v.anchored, false, String(why));
    assert.match(v.note ?? "", why);
  }
});

test("a holder chain of the wrong formats, an unknown algorithm or an undecodable proof is not proved", () => {
  const cred = conf("holder-credential.json"), b = conf("holder-binding-valid.json"), p = conf("holder-proof-valid.json");
  const at = (binding: any, proof: any) => verifyHolder(cred, binding, proof, "rp-nonce-1", null, "2026-05-01T00:00:10Z");
  assert.equal(at(b, p).proved, true);
  const cases: [any, any, RegExp][] = [
    [{ ...b, format: "polaris-trust-list/1" }, p, /needs a polaris-holder-binding\/1/],
    [b, { ...p, algorithm: "RSA-2048" }, /unknown or unaccepted signature algorithm/],
    [b, { ...p, signature_hex: "abc" }, /verification error/],
  ];
  for (const [binding, proof, why] of cases) {
    const v = at(binding, proof);
    assert.equal(v.proved, false, String(why));
    assert.match(v.note ?? "", why);
  }
});

test("a trust attestation for another attesting agency or another key, or undecodable, is not authentic", () => {
  const a = conf("trust-attestation-valid.json");
  assert.equal(verifyAttestation(a, a.attesting_agency_id, a.attested_public_key_hex).authentic, true);
  const cases: [any, number | null, string | null, RegExp][] = [
    [a, a.attesting_agency_id + 1, null, /different attesting agency/],
    [a, a.attesting_agency_id, "00".repeat(32), /different attested key/],
    [{ ...a, signature_hex: "abc" }, null, null, /verification error/],
  ];
  for (const [att, agency, key, why] of cases) {
    const v = verifyAttestation(att, agency, key);
    assert.equal(v.authentic, false, String(why));
    assert.match(v.note ?? "", why);
  }
});

test("the right-most leaf of an unbalanced tree is proved by its one-node path", () => {
  // Size 5: the root is H(H(H(l0,l1),H(l2,l3)), l4), so leaf 4's path is the left subtree
  // alone, and the walk climbs the levels where leaf 4 has no sibling.
  const node = (a: Uint8Array, b: Uint8Array) => sha3_256(Uint8Array.of(1, ...a, ...b));
  const l = [0, 1, 2, 3, 4].map((i) => new Uint8Array(32).fill(i + 1));
  const left = node(node(l[0], l[1]), node(l[2], l[3]));
  const root = node(left, l[4]);
  assert.equal(verifyInclusion(4, 5, l[4], root, [left]), true);
  assert.equal(verifyInclusion(4, 5, l[4], node(l[4], left), [left]), false, "the order of a node's children matters");
  assert.equal(verifyInclusion(3, 5, l[4], root, [left]), false, "the same path does not prove another index");
});

test("an OK status answer decides the presentation: active accepts, anything else rejects", async () => {
  const saved = globalThis.fetch;
  const answer = (body: any) => (async (url: string) => String(url).endsWith("/oauth/token")
    ? { ok: true, status: 200, json: async () => ({ access_token: "t", expires_in: 300 }) }
    : { ok: true, status: 200, json: async () => body }) as any;
  try {
    const v = () => new PolarisVerifier({ issuerUrl: "http://x", clientId: "c", clientSecret: "s" });
    globalThis.fetch = answer({ currently_authoritative: true, status: "ACTIVE" });
    const yes = await v().verifyPresentation(PRES());
    assert.equal(yes.decision, "accept");
    assert.equal(yes.status, "ACTIVE");
    globalThis.fetch = answer({ currently_authoritative: false, status: "REVOKED" });
    const no = await v().verifyPresentation(PRES());
    assert.equal(no.decision, "reject");
    assert.match((no.reasons ?? []).join(" "), /status=REVOKED/);
  } finally {
    globalThis.fetch = saved;
  }
});

test("a hex field holds hex digits and nothing else", () => {
  // parseInt stops at the first character it cannot read, so "eg" decoded as 0x0e: a genuine
  // signature re-spelled that way verified here and in no other verifier. A space between
  // bytes, which the Python verifiers used to skip, is refused too.
  const good = vec("ml-dsa-65-valid.json");
  assert.equal(verifyAuthenticity(good).authentic, true);
  const sig: string = good.signature_hex, pk: string = good.public_key_hex;
  const zero = (h: string) => [...h].findIndex((c, k) => k % 2 === 0 && c === "0");
  const respell = (h: string) => { const i = zero(h); return h.slice(0, i) + h[i + 1] + "g" + h.slice(i + 2); };
  for (const pack of [{ ...good, signature_hex: respell(sig) }, { ...good, public_key_hex: respell(pk) },
                      { ...good, signature_hex: sig.slice(0, 2) + " " + sig.slice(2) }]) {
    const v = verifyAuthenticity(pack);
    assert.equal(v.authentic, false);
    assert.match(v.note ?? "", /bad hex/);
  }
});

// Code scanning (js/polynomial-redos, 2026-09-30): the constructor trimmed the issuer URL with
// /\/+$/, which takes time quadratic in a run of slashes that is not at the end. It is the
// caller's own configuration, so this is hygiene rather than an attack, but the replacement has
// to trim exactly what the expression trimmed, and in linear time.
test("the issuer URL loses its trailing slashes and nothing else", async () => {
  const saved = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = (async (url: string) => {
    urls.push(url);
    return { ok: true, status: 200, json: async () => ({ access_token: "t", expires_in: 300 }) };
  }) as any;
  try {
    for (const [given, base] of [["http://x", "http://x"], ["http://x/", "http://x"],
                                 ["http://x///", "http://x"], ["http://x/a//b/", "http://x/a//b"],
                                 ["http://x/a", "http://x/a"]]) {
      const v = new PolarisVerifier({ issuerUrl: given, clientId: "c", clientSecret: "s" });
      await (v as any).accessToken();
      assert.equal(urls.pop(), `${base}/api/v1/oauth/token`, given);
    }
  } finally {
    globalThis.fetch = saved;
  }
});

test("a long run of slashes inside the issuer URL is trimmed in linear time", () => {
  const url = "http://x" + "/".repeat(200_000) + "y" + "/".repeat(3);
  const started = Date.now();
  const v = new PolarisVerifier({ issuerUrl: url });
  assert.ok(Date.now() - started < 1000, `took ${Date.now() - started} ms`);
  assert.equal((v as any).issuerUrl, url.slice(0, -3));
});


import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyAuthenticity, PolarisVerifier, pairwiseHandle, handlesLink,
         nullifiersLink, grantCovers, grantWithinLimits, revocationEndsGrant,
         verifyInclusion, verifyStatusAssertion, verifyIdToken,
         verifySignedArtifact, verifyCosignature,
         verifyAttestation, verifyCrossAuthority,
         __canonicalJsonForTest, __isoToEpochForTest, expiresIn } from "../src/index.ts";

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

test("only the holder who signed a grant can revoke it", () => {
  const rev = { format: "polaris-grant-revocation/1", grant_id: "g1", public_key_hex: "AB".repeat(32) };
  assert.equal(revocationEndsGrant(rev, GRANT), true, "hex case must not defeat a revocation");
  assert.equal(revocationEndsGrant({ ...rev, public_key_hex: "cd".repeat(32) }, GRANT), false,
    "a stranger's key must not end someone else's grant");
  assert.equal(revocationEndsGrant({ ...rev, grant_id: "other" }, GRANT), false,
    "a revocation naming another grant must not end this one");
  assert.equal(revocationEndsGrant({ ...rev, format: "polaris-status-assertion/1" }, GRANT), false);
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

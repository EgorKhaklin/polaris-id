import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { verifyAuthenticity, PolarisVerifier, pairwiseHandle, handlesLink,
         nullifiersLink, grantCovers, grantWithinLimits, revocationEndsGrant } from "../src/index.ts";

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

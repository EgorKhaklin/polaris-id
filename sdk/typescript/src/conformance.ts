/**
 * node src/conformance.ts -- the verifier CLI the conformance suite drives.
 *
 * Reads ONE conformance case as JSON on stdin, dispatches on its `artifact` (default
 * "authenticity-pack"), and prints the verdict as JSON on stdout:
 *   {"artifact":"authenticity-pack","pack":{...},"anchors":[...]?}
 *       -> {"authentic":bool,"issuer_trusted":bool|null}
 *   {"artifact":"status-assertion","assertion":{...},"now":"<iso>"}
 *       -> {"authentic":bool,"fresh":bool|null,"active":bool|null}
 * See conformance/SPEC.md. This is the TypeScript counterpart of the Python SDK's
 * `python -m polaris_verify.conformance`; the same runner drives either.
 */
import { verifyAttestation, verifyAuthenticity, verifyIdToken, verifyStatusAssertion, verifySignedArtifact, verifyCrossAuthority,
  verifyTimestampAnchor, verifyHolder, type Pack } from "./index.ts";

const SIGNED_ARTIFACTS = new Set([
  "epoch-checkpoint", "revocation-feed", "federation-manifest", "federation-status-bundle", "transparency-sth", "timestamp", "registry", "exchange-request", "signed-document", "id-token", "trust-list", "exchange-receipt", "exchange-mint", "holder-binding", "holder-proof", "epoch-leaves",
  // P9.8: delegation. Signed by the holder's key and the agent's, never the issuer's.
  "agent-grant", "grant-revocation", "agent-proof"]);

let input = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (input += c));
process.stdin.on("end", () => {
  let caseObj: any;
  try {
    caseObj = JSON.parse(input);
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: "could not read case: " + (e as Error).message }) + "\n");
    process.exit(2);
  }
  const artifact = (caseObj && caseObj.artifact) || "authenticity-pack";
  if (artifact === "authenticity-pack") {
    const pack: Pack = caseObj && caseObj.pack ? caseObj.pack : caseObj;
    const anchors = caseObj && caseObj.anchors ? caseObj.anchors : null;
    const v = verifyAuthenticity(pack ?? {}, anchors);
    process.stdout.write(JSON.stringify({ authentic: v.authentic, issuer_trusted: v.issuerTrusted }) + "\n");
  } else if (artifact === "status-assertion") {
    const v = verifyStatusAssertion(caseObj.assertion ?? {}, caseObj.now ?? null);
    process.stdout.write(JSON.stringify({ authentic: v.authentic, fresh: v.fresh, active: v.active }) + "\n");
  } else if (artifact === "trust-attestation") {
    // v9.421: see the Python dispatcher. A genuine edge between two OTHER agencies
    // verifies perfectly and is still not the edge being relied on.
    const v = verifyAttestation(caseObj.object ?? {}, caseObj.attesting_agency_id ?? null,
      caseObj.expected_key ?? null);
    process.stdout.write(JSON.stringify({ authentic: v.authentic, fresh: v.fresh }) + "\n");
  } else if (artifact === "id-token") {
    // v9.420: see the Python dispatcher. A signature-only check passes a token
    // minted for another relying party, which is the whole attack.
    let idAnchors = caseObj.anchors ?? null;
    if (idAnchors === "self") idAnchors = [(caseObj.object ?? {}).public_key_hex];
    const v = verifyIdToken(caseObj.object ?? {}, caseObj.audience ?? null,
      caseObj.nonce ?? null, caseObj.now ?? null, idAnchors);
    process.stdout.write(JSON.stringify({ authentic: v.authentic, audience_matches: v.audienceMatches,
      nonce_matches: v.nonceMatches, fresh: v.fresh,
      issuer_trusted: v.issuerTrusted ?? null }) + "\n");
  } else if (SIGNED_ARTIFACTS.has(artifact)) {
    let anchors = caseObj.anchors ?? null;
    if (anchors === "self") anchors = [(caseObj.object ?? {}).public_key_hex];
    const v = verifySignedArtifact(caseObj.object ?? {}, caseObj.now ?? null, anchors);
    process.stdout.write(JSON.stringify({ authentic: v.authentic, fresh: v.fresh,
                                          issuer_trusted: v.issuerTrusted ?? null }) + "\n");
  } else if (artifact === "timestamp-anchor") {
    const v = verifyTimestampAnchor(caseObj.timestamp ?? {}, caseObj.log_key ?? null,
      caseObj.trusted_witnesses ?? null, Number(caseObj.threshold ?? 1));
    process.stdout.write(JSON.stringify({ anchored: v.anchored, witnessed: v.witnessed }) + "\n");
  } else if (artifact === "holder-chain") {
    const v = verifyHolder(caseObj.credential ?? {}, caseObj.binding ?? {}, caseObj.proof ?? {},
      caseObj.expected_nonce ?? null, caseObj.expected_context ?? null, caseObj.now ?? null);
    process.stdout.write(JSON.stringify({ proved: v.proved }) + "\n");
  } else if (artifact === "cross-authority") {
    const v = verifyCrossAuthority(caseObj.pack ?? {}, caseObj.context_id, caseObj.manifests ?? [],
      caseObj.trusted_anchors ?? null, caseObj.revocation_feed ?? null, caseObj.now ?? null);
    process.stdout.write(JSON.stringify({ decision: v.decision, authentic: v.authentic, issuer_trusted: v.issuerTrusted }) + "\n");
  } else {
    process.stdout.write(JSON.stringify({ error: "unknown artifact: " + artifact }) + "\n");
    process.exit(2);
  }
});

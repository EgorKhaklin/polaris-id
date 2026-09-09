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
import { verifyAuthenticity, verifyStatusAssertion, verifySignedArtifact, verifyCrossAuthority, type Pack } from "./index.ts";

const SIGNED_ARTIFACTS = new Set([
  "epoch-checkpoint", "revocation-feed", "federation-manifest", "federation-status-bundle", "transparency-sth",, "timestamp", "registry", "exchange-request"]);

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
  } else if (SIGNED_ARTIFACTS.has(artifact)) {
    const v = verifySignedArtifact(caseObj.object ?? {}, caseObj.now ?? null);
    process.stdout.write(JSON.stringify({ authentic: v.authentic, fresh: v.fresh }) + "\n");
  } else if (artifact === "cross-authority") {
    const v = verifyCrossAuthority(caseObj.pack ?? {}, caseObj.context_id, caseObj.manifests ?? [],
      caseObj.trusted_anchors ?? null, caseObj.revocation_feed ?? null, caseObj.now ?? null);
    process.stdout.write(JSON.stringify({ decision: v.decision, authentic: v.authentic, issuer_trusted: v.issuerTrusted }) + "\n");
  } else {
    process.stdout.write(JSON.stringify({ error: "unknown artifact: " + artifact }) + "\n");
    process.exit(2);
  }
});

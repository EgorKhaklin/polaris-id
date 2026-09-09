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
import { verifyAuthenticity, verifyStatusAssertion, type Pack } from "./index.ts";

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
  } else {
    process.stdout.write(JSON.stringify({ error: "unknown artifact: " + artifact }) + "\n");
    process.exit(2);
  }
});

/**
 * node src/conformance.ts -- the verifier CLI the conformance suite drives.
 *
 * Reads ONE conformance case as JSON on stdin -- {"pack": {...}, "anchors": [...]?}
 * -- and prints the offline AUTHENTICITY verdict as JSON on stdout:
 * {"authentic": true|false, "issuer_trusted": true|false|null}. See
 * conformance/SPEC.md. This is the TypeScript counterpart of the Python SDK's
 * `python -m polaris_verify.conformance`; the same runner drives either.
 */
import { verifyAuthenticity, type Pack } from "./index.ts";

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
  const pack: Pack = caseObj && caseObj.pack ? caseObj.pack : caseObj;
  const anchors = caseObj && caseObj.anchors ? caseObj.anchors : null;
  const v = verifyAuthenticity(pack ?? {}, anchors);
  process.stdout.write(JSON.stringify({ authentic: v.authentic, issuer_trusted: v.issuerTrusted }) + "\n");
});

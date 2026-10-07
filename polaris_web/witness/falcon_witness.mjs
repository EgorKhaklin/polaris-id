// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//
// The second, independent witness for the experimental FN-DSA family signer (Falcon-padded-1024).
// liboqs signs and verifies in Python; this verifies the same bytes with @noble/post-quantum, a
// separate implementation, so an issued Falcon signature is two-witnessed like an ML-DSA one.
//
//   node falcon_witness.mjs <path to @noble/post-quantum>
//
// Long-lived: one request per line on stdin, {"pk": hex, "digest": hex, "sig": hex}, one answer
// per line on stdout, {"ok": true|false}. Starting Node per signature cost ~70 ms, which made a
// population migration onto Falcon 20 times slower than onto ML-DSA-87 (2026-10-06, the
// quantum-event drill); a single process answers in well under a millisecond. Failing to load the
// library exits non-zero with nothing on stdout, which the caller reads as "no witness" and
// refuses to issue: a missing witness is never a pass.
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const { falcon1024padded } = await import(pathToFileURL(join(process.argv[2], "falcon.js")).href);
const bin = (h) => {
  if (typeof h !== "string" || h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new Error("not hex");
  return Uint8Array.from(Buffer.from(h, "hex"));
};
for await (const line of createInterface({ input: process.stdin })) {
  let ok;
  try {
    const q = JSON.parse(line);
    ok = falcon1024padded.verify(bin(q.sig), bin(q.digest), bin(q.pk)) === true;
  } catch {
    ok = false;
  }
  process.stdout.write(JSON.stringify({ ok }) + "\n");
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//
// The second, independent witness for the experimental FN-DSA family signer (Falcon-padded-1024).
// liboqs signs and verifies in Python; this verifies the same bytes with @noble/post-quantum, a
// separate implementation, so an issued Falcon signature is two-witnessed like an ML-DSA one.
//
//   node falcon_witness.mjs <path to @noble/post-quantum>  <  {"pk": hex, "digest": hex, "sig": hex}
//   -> {"ok": true|false}
//
// Any failure to load the library or parse the input exits non-zero with nothing on stdout, which
// the caller reads as "no witness" and refuses to issue: a missing witness is never a pass.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { join } from "node:path";

const base = process.argv[2];
const { falcon1024padded } = await import(pathToFileURL(join(base, "falcon.js")).href);
const q = JSON.parse(readFileSync(0, "utf8"));
const bin = (h) => {
  if (typeof h !== "string" || h.length % 2 || /[^0-9a-fA-F]/.test(h)) throw new Error("not hex");
  return Uint8Array.from(Buffer.from(h, "hex"));
};
let ok;
try {
  ok = falcon1024padded.verify(bin(q.sig), bin(q.digest), bin(q.pk)) === true;
} catch {
  ok = false;
}
process.stdout.write(JSON.stringify({ ok }) + "\n");

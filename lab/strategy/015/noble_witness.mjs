// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
// The second witness for record 015: @noble/post-quantum, the independent TypeScript implementation
// the TS SDK already depends on. Reads JSON requests on stdin, one per line, writes one answer per line:
//   {"op":"verify","alg":"falcon512","pk":hex,"msg":hex,"sig":hex} -> {"ok":bool}
//   {"op":"sign","alg":"falcon512","msg":hex}                      -> {"pk":hex,"sig":hex}
import { createInterface } from "node:readline";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const base = resolve(process.env.POLARIS_NOBLE_DIR || "sdk/typescript/node_modules/@noble/post-quantum");
const falcon = await import(pathToFileURL(resolve(base, "falcon.js")).href);
const slh = await import(pathToFileURL(resolve(base, "slh-dsa.js")).href);
const impl = { ...falcon, ...slh };
const hex = (u) => Buffer.from(u).toString("hex");
const bin = (h) => Uint8Array.from(Buffer.from(h, "hex"));

for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue;
  const q = JSON.parse(line);
  const a = impl[q.alg];
  try {
    if (!a) throw new Error("unknown algorithm " + q.alg);
    if (q.op === "verify") {
      console.log(JSON.stringify({ ok: a.verify(bin(q.sig), bin(q.msg), bin(q.pk)) }));
    } else {
      const { publicKey, secretKey } = a.keygen();
      console.log(JSON.stringify({ pk: hex(publicKey), sig: hex(a.sign(bin(q.msg), secretKey)) }));
    }
  } catch (e) {
    console.log(JSON.stringify({ error: String(e.message || e) }));
  }
}

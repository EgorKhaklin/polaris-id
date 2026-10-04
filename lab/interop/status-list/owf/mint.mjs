// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//
// Status List Tokens signed with the OpenWallet Foundation's @sd-jwt/jwt-status-list, for
// decide.py to hand to polaris-oid4vp. The library builds and compresses each list and shapes
// the header and payload (createHeaderAndPayload); this file only fills the lists, signs ES256
// with WebCrypto and writes JSON to stdout. Statuses come from a seeded generator, so a run is
// reproducible; the keys are new every run.
import { StatusList, createHeaderAndPayload } from '@sd-jwt/jwt-status-list';

const ISSUER = 'https://issuer.example';
const b64u = (bytes) => Buffer.from(bytes).toString('base64url');

function generator(seed) {           // mulberry32
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

async function sign(header, payload, privateKey) {
  const input = b64u(JSON.stringify(header)) + '.' + b64u(JSON.stringify(payload));
  // WebCrypto's ECDSA signature is r || s, which is what a JWS carries.
  const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey,
                                             new TextEncoder().encode(input));
  return input + '.' + b64u(signature);
}

// The indices decide.py asks about: every non-zero entry (sampled when there are many), as many
// zero entries, and the last entry.
function checksFor(statuses, rnd, cap = 300) {
  const nonZero = [];
  const zero = [];
  statuses.forEach((value, index) => (value ? nonZero : zero).push(index));
  const pick = (list) => {
    if (list.length <= cap) return list;
    const chosen = new Set();
    while (chosen.size < cap) chosen.add(list[Math.floor(rnd() * list.length)]);
    return [...chosen];
  };
  const indices = new Set([...pick(nonZero), ...pick(zero), statuses.length - 1]);
  return [...indices].sort((a, b) => a - b).map((index) => [index, statuses[index]]);
}

const LISTS = [
  // name, bits, entries, share of entries that are not VALID, values a non-VALID entry takes
  ['1-bit, 2^20 entries, sparse', 1, 1 << 20, 0.0001, [1]],
  ['1-bit, 2^20 entries, 5% revoked', 1, 1 << 20, 0.05, [1]],
  ['1-bit, 2^20 entries, 10% revoked', 1, 1 << 20, 0.10, [1]],
  ['2-bit, 2^17 entries, 5% not valid', 2, 1 << 17, 0.05, [1, 2, 3]],
  ['4-bit, 2^14 entries, 20% not valid', 4, 1 << 14, 0.20, [...Array(15).keys()].map((v) => v + 1)],
  ['8-bit, 2^12 entries, every value', 8, 1 << 12, 1.0, [...Array(255).keys()].map((v) => v + 1)],
];

const algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
const key = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
const otherKey = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify']);
const now = Math.floor(Date.now() / 1000);
const rnd = generator(20261004);
const out = { library: '@sd-jwt/jwt-status-list', issuer: ISSUER,
              jwk: await crypto.subtle.exportKey('jwk', key.publicKey), lists: [], controls: {} };

for (const [name, bits, entries, share, values] of LISTS) {
  const statuses = Array.from({ length: entries },
    () => (rnd() < share ? values[Math.floor(rnd() * values.length)] : 0));
  const list = new StatusList(statuses, bits);
  const sub = `${ISSUER}/statuslists/${out.lists.length + 1}`;
  const { header, payload } = createHeaderAndPayload(
    list, { iss: ISSUER, sub, iat: now, exp: now + 86400, ttl: 3600 },
    { alg: 'ES256', typ: 'statuslist+jwt' });
  out.lists.push({ name, bits, entries, sub, payload_bytes: JSON.stringify(payload).length,
                   token: await sign(header, payload, key.privateKey),
                   checks: checksFor(statuses, rnd) });
}

// The controls: the first list signed by a key the verifier does not trust, and the first list
// again with an expiry that has passed.
const first = StatusList.decompressStatusList(
  JSON.parse(Buffer.from(out.lists[0].token.split('.')[1], 'base64url')).status_list.lst, 1);
for (const [label, privateKey, times] of [
  ['other_key', otherKey.privateKey, { iat: now, exp: now + 86400 }],
  ['expired', key.privateKey, { iat: now - 7200, exp: now - 3600 }],
]) {
  const { header, payload } = createHeaderAndPayload(
    first, { iss: ISSUER, sub: out.lists[0].sub, ttl: 3600, ...times },
    { alg: 'ES256', typ: 'statuslist+jwt' });
  out.controls[label] = await sign(header, payload, privateKey);
}

process.stdout.write(JSON.stringify(out));

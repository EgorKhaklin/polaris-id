// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
//
// lab/interop/negative-vectors/adapters/sd_jwt_js.cjs: the vectors against the OpenWallet Foundation's
// SD-JWT VC library for JavaScript (@sd-jwt/sd-jwt-vc), with signatures checked by its own Node helper
// (@sd-jwt/crypto-nodejs), as its documentation shows. Run by run_vectors.py:
//
//     SD_JWT_JS_MODULES=<a folder holding node_modules with both packages> node sd_jwt_js.cjs vectors.json
//
// It prints one JSON object: {id: [verdict, reason]}. The issuer's key comes from the vectors' JWK, so the
// x5c chain and the binding of iss to its leaf (layers haip-x509 and x5c-issuer) are the caller's job here,
// and so is a status check under a vector's policy (layer status-list): those vectors are n/a.
"use strict";
const fs = require("fs");
const path = require("path");
const { createRequire } = require("module");

const load = createRequire(path.join(process.env.SD_JWT_JS_MODULES || ".", "node_modules", "x.js"));
const { SDJwtVcInstance } = load("@sd-jwt/sd-jwt-vc");
const { ES256, digest } = load("@sd-jwt/crypto-nodejs");

async function judge(vector, settings) {
  if (["haip-x509", "x5c-issuer", "status-list"].includes(vector.layer)) return ["n/a", `the ${vector.layer} layer is the caller's`];
  const issuerJwk = Object.fromEntries(Object.entries(settings.issuer_jwks[0]).filter(([k]) => ["kty", "crv", "x", "y"].includes(k)));
  const sdjwt = new SDJwtVcInstance({
    hasher: digest,
    verifier: await ES256.getVerifier(issuerJwk),
    kbVerifier: async (data, sig, payload) => (await ES256.getVerifier(payload.cnf.jwk))(data, sig),
  });
  try {
    await sdjwt.verify(vector.presentation, {
      keyBindingNonce: settings.nonce,
      expectedKeyBindingAudience: settings.audience,
      expectedVct: settings.vct,
      currentDate: settings.now,
      skewSeconds: settings.max_skew_seconds,
      requiredClaimKeys: [],
    });
    return ["accept", ""];
  } catch (e) {
    return ["reject", String((e && e.message) || e).replace(/\s+/g, " ").slice(0, 120)];
  }
}

(async () => {
  const doc = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const out = {};
  for (const v of doc.vectors) out[v.id] = await judge(v, doc.settings);
  process.stdout.write(JSON.stringify(out) + "\n");
})();

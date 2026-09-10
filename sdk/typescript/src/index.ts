/**
 * polaris-verify -- a server-side SDK to verify Polaris identity credentials.
 *
 * A relying party (a bank, a border kiosk, an online service) uses this to answer
 * one narrow question about a credential a holder presented: is it authentic, and
 * is it authoritative right now? It never returns a person's data.
 *
 *   - AUTHENTICITY (offline, cacheable): the ML-DSA-65 signature over
 *     SHA3-256(token_value), verified with @noble/post-quantum, optionally against
 *     a set of trusted issuer anchor keys. No network.
 *   - AUTHORIZATION (online, fresh): the issuer's POST /api/v1/verify,
 *     authenticating as a registered organization with OAuth2 client-credentials.
 *
 * `accept` requires both; without a reachable issuer the verdict is `provisional`.
 * Runtime-agnostic: only @noble/post-quantum plus the platform's fetch/btoa
 * (Node >= 22.6, Deno, Bun, browsers/workers).
 *
 *   import { PolarisVerifier } from "@polaris/verify";
 *   const v = new PolarisVerifier({ issuerUrl, clientId, clientSecret, anchors });
 *   const verdict = await v.verifyPresentation(presentation); // -> { decision: "accept", ... }
 *
 * Conformance: `node src/conformance.ts` implements the language-agnostic verifier
 * CLI the published conformance suite drives (see conformance/SPEC.md).
 */
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";
import { sha3_256 } from "@noble/hashes/sha3.js";

export const ALGORITHM = "ML-DSA-65";
/** P8.8a: the accepted FIPS 204 parameter sets. ML-DSA-44 is below the floor and is rejected
 * like any unknown algorithm; a verifier never guesses a parameter set. */
export const ACCEPTED_ALGORITHMS: Record<string, typeof ml_dsa65> = { "ML-DSA-65": ml_dsa65, "ML-DSA-87": ml_dsa87 };
function verifierFor(alg: unknown): typeof ml_dsa65 | null {
  return typeof alg === "string" && Object.prototype.hasOwnProperty.call(ACCEPTED_ALGORITHMS, alg)
    ? ACCEPTED_ALGORITHMS[alg] : null;
}
export const PLACEHOLDER_LABEL = "DETERMINISTIC-PLACEHOLDER-SHA3-256";

export type AuthenticityVerdict = {
  authentic: boolean;
  issuerTrusted: boolean | null; // null when no anchors were supplied
  algorithm: string | null;
  note?: string;
};

export type Decision = "accept" | "reject" | "provisional";

export type Verdict = {
  decision: Decision;
  authentic: boolean;
  issuerTrusted: boolean | null;
  currentlyAuthoritative: boolean | null;
  status?: string | null;
  reasons?: string[];
};

export type Pack = {
  token_value?: string;
  algorithm?: string;
  signature_hex?: string;
  public_key_hex?: string | null;
};

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string" || hex.length % 2 !== 0) throw new Error("bad hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) throw new Error("bad hex");
    out[i] = b;
  }
  return out;
}

/** Verify a Polaris authenticity pack OFFLINE. `anchors` (optional) are trusted
 * issuer public keys as hex; issuerTrusted says whether the pack's key is one. */
export function verifyAuthenticity(pack: Pack, anchors?: string[] | null): AuthenticityVerdict {
  const tok = pack.token_value;
  const alg = pack.algorithm ?? null;
  const sigHex = pack.signature_hex;
  const pkHex = pack.public_key_hex;
  if (alg === PLACEHOLDER_LABEL || !pkHex) {
    return { authentic: false, issuerTrusted: null, algorithm: alg,
             note: "placeholder credential -- not authenticatable offline" };
  }
  if (!tok || !sigHex) {
    return { authentic: false, issuerTrusted: null, algorithm: alg, note: "pack missing token_value or signature_hex" };
  }
  const impl = verifierFor(alg);
  if (!impl) {
    return { authentic: false, issuerTrusted: null, algorithm: alg,
             note: "unknown or unaccepted signature algorithm: " + String(alg) };
  }
  let ok: boolean;
  try {
    const digest = sha3_256(new TextEncoder().encode(tok));
    ok = impl.verify(hexToBytes(sigHex), digest, hexToBytes(pkHex));
  } catch (e) {
    return { authentic: false, issuerTrusted: null, algorithm: alg,
             note: "verification error: " + (e as Error).message };
  }
  let issuerTrusted: boolean | null = null;
  let note: string | undefined;
  if (anchors != null) {
    const set = new Set(anchors.map((a) => a.toLowerCase()));
    issuerTrusted = set.has(pkHex.toLowerCase());
    if (ok && !issuerTrusted) note = "signature is genuine but its key is not in the trusted issuer anchors";
  }
  return { authentic: ok, issuerTrusted, algorithm: alg, note };
}

// --- Signed statements (P8.1) -----------------------------------------------
// Every signed artifact except the authenticity pack signs SHA3-256(canonical), where
// canonical is the sorted-keys compact JSON of its signed fields (docs/reference/WIRE-SPEC.md).
export type StatusAssertionVerdict = {
  authentic: boolean;
  fresh: boolean | null;
  active: boolean | null;
  status?: string | null;
  note?: string;
};

const STATUS_ASSERTION_KEYS = ["format", "token_value", "status", "issued_at", "expires_at"];

/** Recursive canonical JSON: sorted keys at every level, compact separators. Matches
 * Python's json.dumps(value, sort_keys=True, separators=(",",":")) byte for byte, which is
 * what the signer used. JSON.stringify alone would NOT sort nested object keys, so a signed
 * statement with nested values (epoch, anchors, members) needs this. */
function canonicalJson(value: any): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(value[k])).join(",") + "}";
}

/** The canonical bytes a signer signs: the sorted-keys compact JSON of the signed fields. */
function canonicalBytes(obj: any, keys: string[]): Uint8Array {
  const statement: Record<string, unknown> = {};
  for (const k of keys) statement[k] = obj?.[k] ?? null;
  return new TextEncoder().encode(canonicalJson(statement));
}

function bytesToHex(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += x.toString(16).padStart(2, "0");
  return s;
}

function isoToEpoch(s: unknown): number | null {
  if (typeof s !== "string") return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t / 1000;
}

function withinWindow(obj: any, now?: string | null): boolean | null {
  const ia = isoToEpoch(obj?.issued_at);
  const ea = isoToEpoch(obj?.expires_at);
  if (ia === null || ea === null) return null;
  const n = now != null ? isoToEpoch(now) : Date.now() / 1000;
  if (n === null) return null;
  return ia <= n && n < ea;
}

/** Verify a Polaris status assertion OFFLINE (P3.6, wire spec section 3.5): the ML-DSA-65
 * signature over SHA3-256(canonical statement of {format, token_value, status, issued_at,
 * expires_at}); freshness (now within [issued_at, expires_at)); and ACTIVE status. `now` is
 * an ISO-8601 string or null for the current time. No network. */
export function verifyStatusAssertion(assertion: any, now?: string | null): StatusAssertionVerdict {
  const a = assertion ?? {};
  const status = a.status ?? null;
  if (a.algorithm === PLACEHOLDER_LABEL || !a.public_key_hex) {
    return { authentic: false, fresh: null, active: null, status, note: "placeholder -- not authenticatable offline" };
  }
  if (a.format !== "polaris-status-assertion/1") {
    return { authentic: false, fresh: null, active: null, status, note: "not a polaris-status-assertion/1" };
  }
  const impl = verifierFor(a.algorithm);
  if (!impl) {
    return { authentic: false, fresh: null, active: null, status,
             note: "unknown or unaccepted signature algorithm: " + String(a.algorithm) };
  }
  let ok: boolean;
  try {
    const digest = sha3_256(canonicalBytes(a, STATUS_ASSERTION_KEYS));
    ok = impl.verify(hexToBytes(a.signature_hex), digest, hexToBytes(a.public_key_hex));
  } catch (e) {
    return { authentic: false, fresh: null, active: null, status, note: "verification error: " + (e as Error).message };
  }
  return { authentic: ok, fresh: withinWindow(a, now), active: status === "ACTIVE", status };
}

const ARTIFACT_KEYS: Record<string, string[]> = {
  "polaris-epoch-checkpoint/1": ["format", "authority", "epoch", "prev", "as_of", "issued_at", "expires_at", "algorithm"],
  "polaris-revocation-feed/1": ["format", "authority", "epoch_number", "as_of", "revoked_root_hex", "revoked_count", "revoked_leaves", "issued_at", "expires_at", "algorithm"],
  "polaris-federation-manifest/1": ["format", "authority", "anchors", "attestations", "epoch", "revocation", "issued_at", "expires_at", "algorithm"],
  "polaris-federation-status-bundle/1": ["format", "publisher", "members_root_hex", "member_count", "issued_at", "expires_at", "algorithm"],
  "polaris-transparency-sth/1": ["format", "log_id", "tree_size", "root_hash_hex", "timestamp"],
  "polaris-timestamp/1": ["format", "authority", "digest_hex", "digest_algorithm", "nonce", "issued_at", "algorithm"],
  "polaris-registry/1": ["format", "publisher", "instance", "authorities", "contexts", "trust", "relying_parties", "issued_at", "expires_at", "algorithm"],
  "polaris-exchange-request/1": ["format", "requester", "target", "context_id", "request_hash", "nonce", "issued_at", "algorithm"],
  "polaris-signed-document/1": ["format", "document", "signer", "on_behalf_of", "purpose", "signed_at", "algorithm"],
  "polaris-id-token/1": ["format", "iss", "sub", "aud", "nonce", "context_id", "disclosure_level", "acr", "enrollment", "auth_time", "iat", "exp", "algorithm"],
  "polaris-trust-list/1": ["format", "publisher", "keys", "issued_at", "expires_at", "algorithm"],
  "polaris-exchange-receipt/1": ["format", "requester", "responder", "context_id", "request_hash", "response_hash", "authorized_via", "occurred_at", "algorithm"],
  "polaris-exchange-mint/1": ["format", "requester_public_key_hex", "context_id", "request_hash", "response_hash", "responder_agency_id", "occurred_at"],
  // P9.5: the attesting agency's own signature over a federation trust edge.
  "polaris-trust-attestation/1": ["format", "attesting_agency_id", "attested_agency_id", "attested_public_key_hex", "context_id", "attested_date", "valid_until", "algorithm"],
  // P9.1: the issuer's binding of a holder key, and the holder's own proof of it.
  "polaris-holder-binding/1": ["format", "token_value", "holder_public_key_hex", "holder_algorithm", "bound_at", "status", "issued_at", "expires_at", "algorithm"],
  "polaris-holder-proof/1": ["format", "token_value", "context_id", "verifier_nonce", "issued_at", "algorithm"],
  // P9.2: the published anonymity set a holder proves against on their own device.
  "polaris-epoch-leaves/1": ["format", "authority", "epoch_id", "context_id", "merkle_root", "leaf_count", "leaves_root_hex", "issued_at", "expires_at", "algorithm"],
};

export type ArtifactVerdict = { authentic: boolean; fresh: boolean | null; note?: string };

function revokedRoot(leaves: any): string {
  const arr: string[] = Array.isArray(leaves) ? leaves.map((x) => String(x).toLowerCase()) : [];
  const uniq = [...new Set(arr)].sort();
  return bytesToHex(sha3_256(new TextEncoder().encode(uniq.join("\n"))));
}

function membersRoot(members: any): string {
  const arr = Array.isArray(members) ? members : [];
  const digs = arr.map((m) => bytesToHex(sha3_256(new TextEncoder().encode(canonicalJson(m))))).sort();
  return bytesToHex(sha3_256(new TextEncoder().encode(digs.join("\n"))));
}

/** Verify a Polaris signed artifact's AUTHENTICITY OFFLINE (P8.1, wire spec section 3): for the
 * epoch checkpoint, revocation feed, federation manifest, status bundle, or transparency STH,
 * recompute the canonical statement for its `format`, verify the ML-DSA-65 signature over its
 * SHA3-256, check freshness for a windowed artifact, and check the commitment (feed/bundle) or
 * self-consistency (manifest). The federation TRUST decision is a separate composite check. */
export type IdTokenVerdict = {
  authentic: boolean;
  audienceMatches: boolean | null;
  nonceMatches: boolean | null;
  fresh: boolean | null;
  sub: string | null;
  acr: string | null;
  note?: string;
};

/** Verify a polaris-id-token/1 (P8.4) as a relying party, offline: the issuing agency's
 * signature, that it was issued to THIS audience, that it carries the login's nonce, and
 * freshness (iat <= now < exp). The subject is a credential hash, never a person. */
export function verifyIdToken(tok: any, audience?: string | null, nonce?: string | null, now?: string | null): IdTokenVerdict {
  const t = tok ?? {};
  if (t.format !== "polaris-id-token/1") {
    return { authentic: false, audienceMatches: null, nonceMatches: null, fresh: null, sub: t.sub ?? null, acr: t.acr ?? null, note: "not a polaris-id-token/1" };
  }
  const base = verifySignedArtifact(t, now);
  if (!base.authentic) {
    return { authentic: false, audienceMatches: null, nonceMatches: null, fresh: null, sub: t.sub ?? null, acr: t.acr ?? null, note: base.note };
  }
  const ia = isoToEpoch(t.iat), ea = isoToEpoch(t.exp);
  const n = now != null ? isoToEpoch(now) : Date.now() / 1000;
  const fresh = ia !== null && ea !== null && n !== null ? ia <= n && n < ea : null;
  return { authentic: true, audienceMatches: audience != null ? t.aud === audience : null,
           nonceMatches: nonce != null ? t.nonce === nonce : null, fresh, sub: t.sub ?? null, acr: t.acr ?? null };
}

export function verifySignedArtifact(obj: any, now?: string | null): ArtifactVerdict {
  const o = obj ?? {};
  const keys = ARTIFACT_KEYS[o.format];
  if (!keys) return { authentic: false, fresh: null, note: "unknown or unsupported artifact: " + o.format };
  if (o.algorithm === PLACEHOLDER_LABEL || !o.public_key_hex) {
    return { authentic: false, fresh: null, note: "placeholder -- not authenticatable offline" };
  }
  const impl = verifierFor(o.algorithm);
  if (!impl) {
    return { authentic: false, fresh: null, note: "unknown or unaccepted signature algorithm: " + String(o.algorithm) };
  }
  let ok: boolean;
  try {
    const digest = sha3_256(canonicalBytes(o, keys));
    ok = impl.verify(hexToBytes(o.signature_hex), digest, hexToBytes(o.public_key_hex));
  } catch (e) {
    return { authentic: false, fresh: null, note: "verification error: " + (e as Error).message };
  }
  if (ok && o.format === "polaris-epoch-leaves/1") {
    // P9.2: the leaves ride outside the signed statement, committed to by leaves_root_hex.
    const leaves = Array.isArray(o.all_leaves_hex) ? o.all_leaves_hex : [];
    ok = revokedRoot(leaves) === String(o.leaves_root_hex ?? "").toLowerCase() && leaves.length === o.leaf_count;
    if (!ok) return { authentic: false, fresh: null, note: "the published leaves do not match the committed set" };
  }
  if (ok && o.format === "polaris-revocation-feed/1") {
    ok = revokedRoot(o.revoked_leaves) === String(o.revoked_root_hex ?? "").toLowerCase();
  } else if (ok && o.format === "polaris-federation-status-bundle/1") {
    ok = membersRoot(o.members) === String(o.members_root_hex ?? "").toLowerCase();
  } else if (ok && o.format === "polaris-federation-manifest/1") {
    const active = new Set(
      (Array.isArray(o.anchors) ? o.anchors : [])
        .filter((a: any) => a && (a.status ?? "active") === "active")
        .map((a: any) => String(a.public_key_hex ?? "").toLowerCase()),
    );
    ok = active.has(String(o.public_key_hex ?? "").toLowerCase());
  } else if (ok && o.format === "polaris-registry/1") {
    const pub = o.publisher && typeof o.publisher === "object" ? o.publisher : {};
    const listed = new Set<string>(
      (Array.isArray(o.authorities) ? o.authorities : [])
        .filter((a: any) => a && a.agency_id === pub.agency_id && (a.status ?? "active") === "active")
        .map((a: any) => String(a.public_key_hex ?? "").toLowerCase()),
    );
    ok = listed.has(String(o.public_key_hex ?? "").toLowerCase());
  } else if (ok && o.format === "polaris-trust-list/1") {
    const pub = o.publisher && typeof o.publisher === "object" ? o.publisher : {};
    const active = new Set<string>(
      (Array.isArray(o.keys) ? o.keys : [])
        .filter((k: any) => k && k.agency_id === pub.agency_id && k.status === "active")
        .map((k: any) => String(k.public_key_hex ?? "").toLowerCase()),
    );
    ok = active.has(String(o.public_key_hex ?? "").toLowerCase());
  }
  return { authentic: ok, fresh: withinWindow(o, now) };
}

// --- P9.6: timestamp anchor verification (was P8.5c) --------------------------------
// A timestamp alone does not settle long-term validation: whoever holds the timestamp
// authority's key can mint a backdated one. An ANCHORED timestamp is an entry in an
// append-only log whose head is published and cosigned by witnesses, so a forgery has to
// be absent from every witnessed head of its claimed era. Until now only Polaris's own
// detached verifier could check that. Here it is in the SDK an outsider installs.
const TIMESTAMP_LOG_ID = "polaris-timestamp-log";
const COSIGNATURE_FORMAT = "polaris-transparency-cosignature/1";
const COSIGNATURE_KEYS = ["format", "log_id", "tree_size", "root_hash_hex"];

/** A timestamp's entry in the timestamp transparency log: the SHA3-256 hex of the same
 * canonical statement its signature covers. */
export function timestampHash(ts: any): string {
  return bytesToHex(sha3_256(canonicalBytes(ts ?? {}, ARTIFACT_KEYS["polaris-timestamp/1"])));
}

/** RFC 6962 leaf hash, SHA3-256(0x00 || entry), the entry taken as its UTF-8 bytes. */
function leafHash(entryHex: string): Uint8Array {
  const e = new TextEncoder().encode(String(entryHex));
  const buf = new Uint8Array(1 + e.length);
  buf[0] = 0x00;
  buf.set(e, 1);
  return sha3_256(buf);
}

/** RFC 6962 interior node hash, SHA3-256(0x01 || left || right). */
function nodeHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  const buf = new Uint8Array(1 + left.length + right.length);
  buf[0] = 0x01;
  buf.set(left, 1);
  buf.set(right, 1 + left.length);
  return sha3_256(buf);
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** RFC 6962 section 2.1.1: is `leaf` the entry at `idx` in a tree of `treeSize` whose head
 * is `root`? Total on hostile input: a malformed path is false, never a throw. */
export function verifyInclusion(idx: number, treeSize: number, leaf: Uint8Array, root: Uint8Array, proof: Uint8Array[]): boolean {
  if (!Number.isInteger(idx) || !Number.isInteger(treeSize) || idx < 0 || idx >= treeSize) return false;
  let fn = idx, sn = treeSize - 1, r = leaf;
  for (const p of proof) {
    if (sn === 0 || !(p instanceof Uint8Array)) return false;
    if ((fn & 1) !== 0 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && sameBytes(r, root);
}

/** Verify a witness cosignature over a log head: the ML-DSA signature over the SHA3-256 of
 * the canonical (format, log_id, tree_size, root_hash_hex), and with `witnessKey` that it
 * came from the expected witness. */
export function verifyCosignature(cosig: any, witnessKey?: string | null): ArtifactVerdict {
  const c = cosig ?? {};
  if (c.format !== COSIGNATURE_FORMAT) return { authentic: false, fresh: null, note: "not a " + COSIGNATURE_FORMAT };
  if (c.algorithm === PLACEHOLDER_LABEL || !c.public_key_hex) {
    return { authentic: false, fresh: null, note: "placeholder cosignature -- not authenticatable offline" };
  }
  const impl = verifierFor(c.algorithm);
  if (!impl) return { authentic: false, fresh: null, note: "unknown or unaccepted signature algorithm: " + String(c.algorithm) };
  let ok: boolean;
  try {
    ok = impl.verify(hexToBytes(c.signature_hex), sha3_256(canonicalBytes(c, COSIGNATURE_KEYS)), hexToBytes(c.public_key_hex));
  } catch (e) {
    return { authentic: false, fresh: null, note: "verification error: " + (e as Error).message };
  }
  if (ok && witnessKey != null && String(c.public_key_hex).toLowerCase() !== String(witnessKey).toLowerCase()) {
    return { authentic: false, fresh: null, note: "the cosignature is not from the expected witness" };
  }
  return { authentic: ok, fresh: null, note: ok ? undefined : "cosignature signature is invalid" };
}

export type AnchorVerdict = {
  anchored: boolean;
  sthAuthentic: boolean;
  witnessed: boolean | null;
  cosignerCount: number;
  timestampHash: string | null;
  index: number | null;
  treeSize: number | null;
  note?: string;
};

/** Verify OFFLINE that a timestamp is ANCHORED in the timestamp transparency log: its unsigned
 * `anchor` carries an inclusion proof and a Signed Tree Head, the proof is for this timestamp's
 * own hash, the head is an authentic head of that log (with `logKey`, signed by the expected
 * authority), and the proof reconstructs the head. With `trustedWitnesses`, the head must also
 * be cosigned by `threshold` DISTINCT trusted witnesses: a stolen authority key can sign a fresh
 * head over a fabricated log, but it cannot make a witness have cosigned that head at the
 * claimed time. No network. Total on hostile input. */
export function verifyTimestampAnchor(ts: any, logKey?: string | null, trustedWitnesses?: string[] | null,
                                      threshold: number = 1): AnchorVerdict {
  const v: AnchorVerdict = { anchored: false, sthAuthentic: false, witnessed: null, cosignerCount: 0,
                             timestampHash: null, index: null, treeSize: null };
  if (ts === null || typeof ts !== "object") { v.note = "timestamp must be an object"; return v; }
  const anchor = ts.anchor;
  if (anchor === null || typeof anchor !== "object") {
    v.note = "the timestamp carries no anchor (unanchored: the authority kept no record of it)";
    return v;
  }
  const proof = anchor.proof, sth = anchor.sth;
  if (proof === null || typeof proof !== "object" || sth === null || typeof sth !== "object") {
    v.note = "anchor.proof and anchor.sth must be objects";
    return v;
  }
  v.timestampHash = timestampHash(ts);
  if (String(proof.entry_hex ?? "").toLowerCase() !== v.timestampHash) {
    v.note = "the proof is not for this timestamp";
    return v;
  }
  const sv = verifySignedArtifact(sth);
  v.sthAuthentic = sv.authentic;
  if (sth.log_id !== TIMESTAMP_LOG_ID || (proof.log_id != null && proof.log_id !== TIMESTAMP_LOG_ID)) {
    v.note = "the head is not a " + TIMESTAMP_LOG_ID + " head";
    return v;
  }
  const idx = Number(proof.index), size = Number(proof.tree_size);
  let root: Uint8Array, path: Uint8Array[];
  try {
    root = hexToBytes(String(sth.root_hash_hex));
    path = (Array.isArray(proof.proof_hex) ? proof.proof_hex : []).map((x: any) => hexToBytes(String(x)));
  } catch (e) {
    v.note = "malformed proof";
    return v;
  }
  v.index = Number.isInteger(idx) ? idx : null;
  v.treeSize = Number.isInteger(size) ? size : null;
  if (size !== sth.tree_size ||
      String(proof.root_hash_hex ?? "").toLowerCase() !== String(sth.root_hash_hex ?? "").toLowerCase()) {
    v.note = "the proof and the head describe different trees";
    return v;
  }
  if (!v.sthAuthentic) { v.note = sv.note ?? "the head is not authentic"; return v; }
  if (logKey != null && String(sth.public_key_hex ?? "").toLowerCase() !== String(logKey).toLowerCase()) {
    v.note = "the head is not signed by the expected log key";
    return v;
  }
  v.anchored = verifyInclusion(idx, size, leafHash(v.timestampHash), root, path);
  if (!v.anchored) { v.note = "the inclusion proof does not reconstruct the head"; return v; }
  if (trustedWitnesses != null) {
    const trusted = new Set(trustedWitnesses.map((t) => String(t).toLowerCase()));
    const seen = new Set<string>();
    for (const c of (Array.isArray(anchor.cosignatures) ? anchor.cosignatures : [])) {
      if (c === null || typeof c !== "object" || !verifyCosignature(c).authentic) continue;
      if (c.log_id === sth.log_id && c.tree_size === sth.tree_size &&
          String(c.root_hash_hex ?? "").toLowerCase() === String(sth.root_hash_hex ?? "").toLowerCase()) {
        const w = String(c.public_key_hex ?? "").toLowerCase();
        if (trusted.has(w)) seen.add(w);
      }
    }
    v.cosignerCount = seen.size;
    v.witnessed = v.cosignerCount >= (threshold || 1);
    if (!v.witnessed) {
      v.note = "only " + v.cosignerCount + " trusted witness cosignature(s) over this head, need " + threshold;
    }
  }
  return v;
}

export type CrossAuthorityVerdict = {
  decision: string; // "accept" | "reject"
  authentic: boolean;
  issuerTrusted: boolean;
  via?: unknown;
  reason?: string;
};

/** Decide a FOREIGN credential across authorities OFFLINE (P8.1, wire spec section 4). Accept
 * iff the authenticity pack is genuine, some federation manifest the relying party trusts
 * (authentic, fresh, signed by a trusted anchor) attests the credential's signing key in the
 * presented context (non-transitive), and -- if a revocation feed is supplied -- the credential
 * is not revoked (feed authentic, fresh, and bound to the issuer key). No network. */
export type HolderVerdict = {
  proved: boolean;
  bindingAuthentic: boolean | null;
  boundToCredential: boolean | null;
  bindingFresh: boolean | null;
  proofAuthentic: boolean | null;
  keyMatchesBinding: boolean | null;
  nonceMatches: boolean | null;
  note?: string;
};

/** Decide the holder key chain offline (P9.1): issuer anchor -> binding -> holder key -> proof.
 *
 * Polaris was issuer-centric until v9.349: a holder held a credential, not a key pair, so
 * presenting the file was the whole of the proof. A holder proof answers a different question,
 * whether the party presenting it holds the key the ISSUER bound to that credential. The proof
 * is signed over the credential, the context, the verifier's nonce and the instant, and
 * deliberately NOT over the presented code, so a coerced presentation stays
 * byte-indistinguishable from a consenting one. */
export function verifyHolder(credential: any, binding: any, proof: any, expectedNonce?: string | null,
                             expectedContext?: any, now?: string | null,
                             maxAgeSeconds: number = 300): HolderVerdict {
  const v: HolderVerdict = { proved: false, bindingAuthentic: null, boundToCredential: null,
                             bindingFresh: null, proofAuthentic: null, keyMatchesBinding: null,
                             nonceMatches: null };
  const b = binding ?? {}, pr = proof ?? {};
  if (b.format !== "polaris-holder-binding/1" || pr.format !== "polaris-holder-proof/1") {
    v.note = "a holder chain needs a polaris-holder-binding/1 and a polaris-holder-proof/1";
    return v;
  }
  const bv = verifySignedArtifact(b, now);
  v.bindingAuthentic = bv.authentic;
  v.bindingFresh = bv.fresh;
  const cred = credential ?? {};
  v.boundToCredential = String(b.token_value) === String(cred.token_value)
    && String(b.public_key_hex ?? "").toLowerCase() === String(cred.public_key_hex ?? "").toLowerCase();
  const impl = verifierFor(pr.algorithm);
  if (!impl) {
    v.note = "unknown or unaccepted signature algorithm: " + String(pr.algorithm);
    return v;
  }
  try {
    const digest = sha3_256(canonicalBytes(pr, ARTIFACT_KEYS["polaris-holder-proof/1"]));
    v.proofAuthentic = impl.verify(hexToBytes(pr.signature_hex), digest, hexToBytes(pr.public_key_hex));
  } catch (e) {
    v.note = "verification error: " + (e as Error).message;
    return v;
  }
  v.keyMatchesBinding = String(pr.public_key_hex ?? "").toLowerCase()
    === String(b.holder_public_key_hex ?? "").toLowerCase() && (b.status ?? "active") === "active";
  if (expectedNonce != null) v.nonceMatches = String(pr.verifier_nonce) === String(expectedNonce);
  const ctxOk = expectedContext == null || pr.context_id === expectedContext;
  const issued = Date.parse(String(pr.issued_at ?? ""));
  const ref = now ? Date.parse(now) : Date.now();
  const fresh = Number.isFinite(issued) && Number.isFinite(ref)
    && issued <= ref + 60_000 && (ref - issued) / 1000 <= maxAgeSeconds;
  v.proved = !!(v.bindingAuthentic && v.bindingFresh && v.boundToCredential && v.proofAuthentic
                && v.keyMatchesBinding && v.nonceMatches !== false && ctxOk && fresh);
  if (!v.proved) v.note = "the holder proof does not chain to a fresh issuer-signed binding for this credential";
  return v;
}

/** Verify that a federation attestation carries the ATTESTING agency's own signature over
 * the attested key, the context and the window (P9.5). Before v9.348 an attestation was a row
 * an operator recorded, and the manifest that published it signed whatever the table held, so
 * a row inserted straight into a database was indistinguishable from one made through the
 * ceremony. An unsigned attestation is legacy, not a failure: `authentic` is false with a
 * note, and the caller decides whether to require a signature. */
export function verifyAttestation(att: any, attestingAgencyId?: number | null,
                                  expectedKey?: string | null): ArtifactVerdict {
  const a = att ?? {};
  if (!a.signature_hex && !a.public_key_hex) {
    return { authentic: false, fresh: null, note: "unsigned legacy attestation (recorded before v9.348)" };
  }
  if (a.format !== "polaris-trust-attestation/1") {
    return { authentic: false, fresh: null, note: "not a polaris-trust-attestation/1" };
  }
  if (a.algorithm === PLACEHOLDER_LABEL) {
    return { authentic: false, fresh: null, note: "placeholder attestation signature -- not authenticatable offline" };
  }
  const impl = verifierFor(a.algorithm);
  if (!impl) return { authentic: false, fresh: null, note: "unknown or unaccepted signature algorithm: " + String(a.algorithm) };
  let ok: boolean;
  try {
    const digest = sha3_256(canonicalBytes(a, ARTIFACT_KEYS["polaris-trust-attestation/1"]));
    ok = impl.verify(hexToBytes(a.signature_hex), digest, hexToBytes(a.public_key_hex));
  } catch (e) {
    return { authentic: false, fresh: null, note: "verification error: " + (e as Error).message };
  }
  if (ok && attestingAgencyId != null && a.attesting_agency_id !== attestingAgencyId) {
    return { authentic: false, fresh: null, note: "the attestation names a different attesting agency than the manifest that published it" };
  }
  if (ok && expectedKey != null &&
      String(a.attested_public_key_hex ?? "").toLowerCase() !== String(expectedKey).toLowerCase()) {
    return { authentic: false, fresh: null, note: "the attestation is signed over a different attested key" };
  }
  return { authentic: ok, fresh: null, note: ok ? undefined : "the attestation signature is invalid" };
}

export function verifyCrossAuthority(
  pack: any, contextId: any, manifests: any[], trustedAnchors?: string[] | null,
  revocationFeed?: any, now?: string | null, requireSignedAttestation: boolean = false,
): CrossAuthorityVerdict {
  const p = pack ?? {};
  if (!verifyAuthenticity(p).authentic) {
    return { decision: "reject", authentic: false, issuerTrusted: false, reason: "credential is not authentic" };
  }
  const tokenKey = String(p.public_key_hex ?? "").toLowerCase();
  const trusted = trustedAnchors != null ? new Set(trustedAnchors.map((t) => t.toLowerCase())) : null;
  let via: unknown = null;
  for (const mm of (manifests ?? []).map((m) => m ?? {})) {
    const mv = verifySignedArtifact(mm, now);
    if (!(mv.authentic && mv.fresh)) continue;
    const active = new Set<string>(
      (Array.isArray(mm.anchors) ? mm.anchors : [])
        .filter((x: any) => x && (x.status ?? "active") === "active")
        .map((x: any) => String(x.public_key_hex ?? "").toLowerCase()),
    );
    if (trusted != null && ![...active].some((x: string) => trusted!.has(x))) continue;
    for (const att of Array.isArray(mm.attestations) ? mm.attestations : []) {
      if (att && String(att.attested_public_key_hex ?? "").toLowerCase() === tokenKey
          && (contextId == null || att.context_id === contextId)) {
        // P9.5: is the edge signed by the agency that made it, or is it the operator's
        // word carried by the manifest's signature?
        const unsigned = !att.signature_hex && !att.public_key_hex;
        const av = verifyAttestation(att, mm.authority?.agency_id ?? null, tokenKey);
        if (!unsigned && !av.authentic) continue;
        if (requireSignedAttestation && unsigned) continue;
        via = mm.authority;
        break;
      }
    }
    if (via != null) break;
  }
  if (via == null) {
    return { decision: "reject", authentic: true, issuerTrusted: false,
             reason: "no trusted authority attests to this credential's issuer in this context" };
  }
  if (revocationFeed != null) {
    const rf = revocationFeed ?? {};
    const rv = verifySignedArtifact(rf, now);
    const bound = String(rf.public_key_hex ?? "").toLowerCase() === tokenKey;
    if (!(rv.authentic && rv.fresh && bound)) {
      return { decision: "reject", authentic: true, issuerTrusted: true, via,
               reason: "the revocation feed is not authentic, fresh, and bound to the issuer key" };
    }
    const leaf = bytesToHex(sha3_256(new TextEncoder().encode(String(p.token_value ?? ""))));
    const leaves = new Set((Array.isArray(rf.revoked_leaves) ? rf.revoked_leaves : []).map((x: any) => String(x).toLowerCase()));
    if (leaves.has(leaf)) {
      return { decision: "reject", authentic: true, issuerTrusted: true, via, reason: "credential is revoked" };
    }
  }
  return { decision: "accept", authentic: true, issuerTrusted: true, via };
}

export type VerifierOptions = {
  issuerUrl?: string;
  clientId?: string;
  clientSecret?: string;
  anchors?: string[] | null;
  timeoutMs?: number;
};

export class PolarisVerifier {
  private issuerUrl?: string;
  private clientId?: string;
  private clientSecret?: string;
  private anchors: string[] | null;
  private timeoutMs: number;
  private bearer: string | null = null;
  private bearerExp = 0;

  constructor(opts: VerifierOptions = {}) {
    this.issuerUrl = opts.issuerUrl ? opts.issuerUrl.replace(/\/+$/, "") : undefined;
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret;
    this.anchors = opts.anchors ?? null;
    this.timeoutMs = opts.timeoutMs ?? 30000;
  }

  private async accessToken(): Promise<string> {
    if (this.bearer && Date.now() < this.bearerExp - 5000) return this.bearer;
    const creds = btoa(`${this.clientId}:${this.clientSecret}`);
    const r = await fetch(`${this.issuerUrl}/api/v1/oauth/token`, {
      method: "POST",
      headers: { Authorization: `Basic ${creds}`, "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=client_credentials",
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!r.ok) throw new Error(`token endpoint returned ${r.status}`);
    const body = await r.json();
    this.bearer = body.access_token;
    this.bearerExp = Date.now() + (body.expires_in ?? 300) * 1000;
    return this.bearer as string;
  }

  private async onlineStatus(cred: Pack): Promise<any> {
    const r = await fetch(`${this.issuerUrl}/api/v1/verify`, {
      method: "POST",
      headers: { Authorization: `Bearer ${await this.accessToken()}`, "Content-Type": "application/json" },
      body: JSON.stringify({ token_value: cred.token_value, signature_hex: cred.signature_hex }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!r.ok) throw new Error(`verify endpoint returned ${r.status}`);
    return r.json();
  }

  /** Decide accept / reject / provisional for a holder's presentation (a wallet
   * presentation object, or a bare authenticity pack). */
  async verifyPresentation(presentation: any): Promise<Verdict> {
    const cred: Pack = presentation && presentation.credential ? presentation.credential : (presentation ?? {});
    const a = verifyAuthenticity(cred, this.anchors);
    const reasons: string[] = [];
    if (!a.authentic) {
      reasons.push(a.note ?? "not authentic");
      return { decision: "reject", authentic: false, issuerTrusted: a.issuerTrusted, currentlyAuthoritative: null, reasons };
    }
    if (a.issuerTrusted === false) {
      reasons.push(a.note ?? "issuer not trusted");
      return { decision: "reject", authentic: true, issuerTrusted: false, currentlyAuthoritative: null, reasons };
    }
    if (!this.issuerUrl) {
      reasons.push("status not checked (offline) -- authenticity only, not a full accept");
      return { decision: "provisional", authentic: true, issuerTrusted: a.issuerTrusted, currentlyAuthoritative: null, reasons };
    }
    let status: any;
    try {
      status = await this.onlineStatus(cred);
    } catch (e) {
      reasons.push("status check failed: " + (e as Error).message);
      return { decision: "reject", authentic: true, issuerTrusted: a.issuerTrusted, currentlyAuthoritative: null, reasons };
    }
    const current = Boolean(status.currently_authoritative);
    if (!current) reasons.push(`not currently authoritative (revoked/inactive): status=${status.status}`);
    return {
      decision: current ? "accept" : "reject",
      authentic: true,
      issuerTrusted: a.issuerTrusted,
      currentlyAuthoritative: current,
      status: status.status ?? null,
      reasons: reasons.length ? reasons : undefined,
    };
  }
}

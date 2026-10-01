// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
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
 *   import { PolarisVerifier } from "polaris-sdk-ts";
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

// A hex field holds hex digits and nothing else. parseInt alone stops at the first character
// it cannot read, so "eg" decoded as 0x0e and a signature carrying it verified here while both
// Python verifiers refused it (and they accepted a space between bytes, which this refused).
const HEX_DIGITS = /^[0-9a-fA-F]*$/;

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !HEX_DIGITS.test(hex)) throw new Error("bad hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const b = parseInt(hex.substr(i * 2, 2), 16);
    if (Number.isNaN(b)) throw new Error("bad hex");
    out[i] = b;
  }
  return out;
}

/** The longest credential serial, in bytes of UTF-8: IdentityToken.token_value is VARCHAR(128). */
export const TOKEN_VALUE_MAX_BYTES = 128;

/** Why `tokenValue` is not a credential serial, or null when it is one (WIRE-SPEC 3.7).
 *
 * A pack is signed over SHA3-256(token_value) with no domain, and every other signed artifact
 * over SHA3-256 of its canonical JSON statement, so without this rule any authority-signed
 * artifact re-wrapped as a pack (token_value: its canonical statement) verified as an authentic
 * credential (2026-09-27, measured with real ML-DSA-65). A serial is a non-empty string of at
 * most 128 bytes of UTF-8, not beginning with "{", with no control character (U+0000-U+001F,
 * U+007F-U+009F). Every signed statement begins with "{". Same rule as the Python verifiers. */
export function tokenValueSerialProblem(tokenValue: unknown): string | null {
  if (typeof tokenValue !== "string") {
    return "token_value must be a string, got " + (tokenValue === null ? "null" : typeof tokenValue);
  }
  if (tokenValue.length === 0) return "token_value is empty";
  for (let i = 0; i < tokenValue.length; i++) {
    const c = tokenValue.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = i + 1 < tokenValue.length ? tokenValue.charCodeAt(i + 1) : 0;
      if (d >= 0xdc00 && d <= 0xdfff) { i++; continue; }
      return "token_value is not valid Unicode (an unpaired surrogate)";
    }
    if (c >= 0xdc00 && c <= 0xdfff) return "token_value is not valid Unicode (an unpaired surrogate)";
  }
  if (tokenValue[0] === "{") {
    return "token_value begins with '{', so it is a signed JSON statement, not a credential serial";
  }
  const n = new TextEncoder().encode(tokenValue).length;
  if (n > TOKEN_VALUE_MAX_BYTES) {
    return "token_value is " + n + " bytes of UTF-8; a credential serial is at most " + TOKEN_VALUE_MAX_BYTES;
  }
  for (let i = 0; i < tokenValue.length; i++) {
    const c = tokenValue.charCodeAt(i);
    if (c < 0x20 || (c >= 0x7f && c <= 0x9f)) return "token_value contains a control character";
  }
  return null;
}

/** Verify a Polaris authenticity pack OFFLINE. `anchors` (optional) are trusted
 * issuer public keys as hex; issuerTrusted says whether the pack's key is one. */
export function verifyAuthenticity(pack: Pack, anchors?: string[] | null): AuthenticityVerdict {
  // A verdict, never an exception, on input that is not an object: `null.token_value` threw here
  // where the Python SDK answered not authentic (2026-10-01).
  if (pack === null || typeof pack !== "object" || Array.isArray(pack)) {
    return { authentic: false, issuerTrusted: null, algorithm: null, note: "the credential is not an object" };
  }
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
  // WIRE-SPEC 3.7, 2026-09-27: decided before any signature is checked.
  const serialProblem = tokenValueSerialProblem(tok);
  if (serialProblem !== null) {
    return { authentic: false, issuerTrusted: null, algorithm: alg,
             note: "not an authentic credential: " + serialProblem };
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
    issuerTrusted = hexIn(pkHex, anchors.map((a) => hexText(a)));
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

/** A JSON string literal escaped the way Python's `json.dumps(..., ensure_ascii=True)`
 * escapes it: every code unit above 0x7e as `\uXXXX`, lower case hex, surrogate pairs kept
 * as two escapes.
 *
 * This did not exist until 2026-09-17 and the omission was a real interoperability break.
 * `canonicalJson` used `JSON.stringify` for strings, which emits raw UTF-8, while the wire
 * specification pins the canonical form to Python's `json.dumps(statement, sort_keys=True,
 * separators=(",", ":")).encode("utf-8")` and warns that "a one-byte drift means the signer
 * and every independent verifier disagree". Measured with real ML-DSA-65 signatures: an
 * artifact whose signer is "Ministere des Affaires Etrangeres" with its accent, or whose
 * purpose is written in Japanese, verified in Python and was REJECTED here. An accent in an
 * agency name is ordinary in a federation of national agencies, and no JSON fixture in the
 * tree carries a non-ASCII byte, which is why nothing caught it.
 *
 * Note this is NOT what RFC 8785 would ask for. The contract is the wire specification, and
 * the wire specification is Python's default. Changing which one is authoritative is a
 * protocol decision, not something a verifier gets to take on its own. */
export function __canonicalJsonStringForTest(s: string): string {
  return pythonJsonString(s);
}

function pythonJsonString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ch = s[i];
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (c < 0x20 || c > 0x7e) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}

/** Recursive canonical JSON: sorted keys at every level, compact separators. Matches
 * Python's json.dumps(value, sort_keys=True, separators=(",",":")) byte for byte, which is
 * what the signer used. JSON.stringify alone would NOT sort nested object keys, so a signed
 * statement with nested values (epoch, anchors, members) needs this; nor would it escape
 * non-ASCII, which is the other half and the half that was missing. */
/** @internal Exported so the differential test can compare this byte for byte with
 * Python's json.dumps. It is not part of the SDK's public surface. */
export function __canonicalJsonForTest(value: any): string {
  return canonicalJson(value);
}

/** A number as Python's json.dumps writes it. Both languages pick the shortest digits that
 * round-trip, but Python switches to exponent form below 1e-4 with at least two exponent
 * digits ("1.5e-05", "1e-07") where JavaScript waits until 1e-6 and writes "1e-7", so a
 * statement signed with 0.000015 in it failed here (2026-10-01). Integral values are the other
 * known limit, and hasIntegralNumber names them. */
function pythonJsonNumber(x: number): string {
  if (Number.isFinite(x) && !Number.isInteger(x) && Math.abs(x) < 1e-4) {
    const [mant, exp] = x.toExponential().split("e");
    const e = Number(exp);
    return mant + "e" + (e < 0 ? "-" : "+") + String(Math.abs(e)).padStart(2, "0");
  }
  return JSON.stringify(x);
}

/** Python's sort_keys orders keys by code point; JavaScript's sort() by UTF-16 unit, which puts
 * a key outside the Basic Multilingual Plane before "\uffff" where Python puts it after. */
function codePointOrder(a: string, b: string): number {
  const x = Array.from(a, (c) => c.codePointAt(0) as number);
  const y = Array.from(b, (c) => c.codePointAt(0) as number);
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

function canonicalJson(value: any): string {
  if (typeof value === "string") return pythonJsonString(value);
  if (typeof value === "number") return pythonJsonNumber(value);
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(value).sort(codePointOrder);
  return "{" + keys.map((k) => pythonJsonString(k) + ":" + canonicalJson(value[k])).join(",") + "}";
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

/** True when a signed statement carries a number JavaScript cannot render the way the wire
 * format does: an INTEGRAL float. Python distinguishes `4` from `4.0` and renders them
 * differently; JavaScript has one number type and `JSON.parse("4.0")` is indistinguishable
 * from `JSON.parse("4")`. Non-integral values are fine: `-0.5` renders identically.
 *
 * It is reachable. `polaris-agent-grant/1` signs `limits`, and `max_amount` is a monetary
 * amount an issuer may well write as `100.0`. This SDK cannot verify such a grant, and the
 * worst outcome would be reporting it inauthentic with no reason, which reads as a forgery.
 * So the fact is named in the note instead. */
function hasIntegralNumber(value: any, depth = 0): boolean {
  if (depth > 32) return false;
  if (typeof value === "number") return Number.isInteger(value);
  if (Array.isArray(value)) return value.some((v) => hasIntegralNumber(v, depth + 1));
  if (value && typeof value === "object") {
    return Object.values(value).some((v) => hasIntegralNumber(v, depth + 1));
  }
  return false;
}

/** Seconds since the epoch, reading an instant the way the Python reference does.
 *
 * `Date.parse` alone was wrong in two directions, both measured on 2026-09-17 with real
 * signatures. It reads a date-time carrying NO offset as LOCAL time, where the Python side
 * stamps it UTC, so an epoch checkpoint whose window closed three hours earlier verified as
 * FRESH for any verifier west of UTC and stale for any verifier east of it. And it accepts
 * shapes Python refuses outright, including RFC 2822 and US slash dates, so the two sides
 * disagreed on 12 of 33 freshness cases.
 *
 * The wire specification says a verifier MUST reject an artifact unless
 * `issued_at <= now < expires_at`. A window that means something different depending on
 * where the verifier is standing is not that. */
/** @internal Exported for the differential test; not public surface. */
export function __isoToEpochForTest(s: unknown): number | null {
  return isoToEpoch(s);
}

function isoToEpoch(s: unknown): number | null {
  if (typeof s !== "string") return null;
  // ISO 8601 only, and the same subset Python's fromisoformat accepts: a date, optionally a
  // time, optionally fractional seconds, optionally an offset. Anything else is refused
  // rather than guessed at.
  // The whole string, as written: `trim()` removed a different set of characters than the
  // Python verifiers' `strip()` (a byte-order mark here, a file separator there), and RFC
  // 3339 has no surrounding whitespace (2026-10-01).
  const m = /^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,6}))?)?)?(?:([Zz])|([+-])(\d{2}):?(\d{2}))?$/.exec(s);
  if (!m) return null;
  const [, y, mo, d, hh, mi, ss, frac, z, sign, oh, om] = m;
  // An offset of 24 hours or 60 minutes is not one RFC 3339 allows, and Python refuses it.
  if (sign && (Number(oh) > 23 || Number(om) > 59)) return null;
  // Year 0 does not exist in the Python reference; years 1 to 99 do, and Date.UTC reads them as
  // 1901 to 1999, so a credential dated 0099 was refused here and read as 0099 there.
  if (Number(y) === 0) return null;
  let t = Date.UTC(Number(y), Number(mo) - 1, Number(d),
                   Number(hh || 0), Number(mi || 0), Number(ss || 0), 0);
  if (Number(y) < 100) {
    const fixed = new Date(t);
    fixed.setUTCFullYear(Number(y));
    t = fixed.getTime();
  }
  // The fraction to the microsecond, as the Python verifiers read it. Until 2026-10-01 it was
  // rounded to the millisecond here, so an artifact dated 100 microseconds ahead of `now` was
  // fresh in this SDK and not yet valid in both Python verifiers: the same bytes, two answers.
  const micro = frac ? Number(frac.padEnd(6, "0")) : 0;
  if (Number.isNaN(t)) return null;
  // Date.UTC rolls an impossible date over instead of refusing it: "2026-02-31" became
  // 3 March and "T25:00" the next day, where Python's fromisoformat, whose subset this
  // parser promises to accept, refuses all of them. So an artifact dated 31 February read as
  // fresh here and as unreadable in the Python kit. The fields must come back unchanged.
  const back = new Date(t);
  if (back.getUTCFullYear() !== Number(y) || back.getUTCMonth() !== Number(mo) - 1 ||
      back.getUTCDate() !== Number(d) || back.getUTCHours() !== Number(hh || 0) ||
      back.getUTCMinutes() !== Number(mi || 0) || back.getUTCSeconds() !== Number(ss || 0)) {
    return null;
  }
  if (sign) {
    // An explicit offset is applied; no offset at all means UTC, which is the whole fix.
    const shift = (Number(oh) * 60 + Number(om)) * 60000;
    t += sign === "+" ? -shift : shift;
  } else if (!z) {
    // Deliberately nothing: Date.UTC already read it as UTC. Named so that a later reader
    // does not "helpfully" reintroduce local time here.
  }
  return t / 1000 + micro / 1e6;
}

/** Formats whose freshness is a REPLAY WINDOW rather than a validity interval, with the
 * age bound in seconds. A holder proof carries `issued_at` and no `expires_at`: it is a
 * presentation made for one verifier at one moment, and the question is not "has it
 * expired" but "is this the one just made for me, or one replayed from earlier".
 *
 * v9.430, matching the Python SDK and the detached verifier. Before this all three did not
 * agree: the detached verifier bounded a holder proof's age at 300 seconds and both SDKs
 * reported `fresh: null`, so an integrator following an SDK got no replay protection on
 * presentations. No published case asked about freshness until v9.430, which is why two
 * shipped reference verifiers could disagree about it unnoticed. */
const REPLAY_WINDOW_SECONDS: Record<string, number> = { "polaris-holder-proof/1": 300 };

/** A proof may be up to this far ahead of the verifier's clock. Matches the other two; a
 * skew allowance they did not share would be the same bug again, smaller. */
const CLOCK_SKEW_SECONDS = 60;

/** The longest an access token is cached before the client asks for a new one, whatever the
 * issuer says, and the conservative fallback when it says something unusable.
 *
 * 2026-09-17. `(body.expires_in ?? 300) * 1000` believed the issuer. `JSON.parse` in
 * JavaScript refuses the bare literals `NaN` and `Infinity`, which is stricter than Python,
 * but `1e400` is ordinary JSON grammar and becomes `Infinity` here exactly as it does there:
 * the cached token was then pinned past the life of the process, so a client whose
 * credentials had been revoked kept presenting a token it should have stopped using. A
 * string or an object gave `NaN`, and `Date.now() < NaN` is false, so the opposite happened
 * and the client fetched a new token on every single call.
 *
 * The numbers match `_expires_in` in the Python kit deliberately. An integrator who picks
 * one kit is not making a security decision, and a lifetime the two disagreed about would be
 * one more line in the corrections table. */
const MAX_TOKEN_CACHE_SECONDS = 24 * 3600;
const DEFAULT_TOKEN_CACHE_SECONDS = 300;

export function expiresIn(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    return DEFAULT_TOKEN_CACHE_SECONDS;
  }
  return Math.min(Math.trunc(value), MAX_TOKEN_CACHE_SECONDS);
}

/** A table entry for a sender's `format`: only for a string, and only an own key. A list coerced
 * to its string (`["polaris-epoch-checkpoint/1"]` found the checkpoint's keys and reported
 * `fresh` for an artifact the Python SDK calls unknown), and a name such as "constructor"
 * found the prototype's member. ACCEPTED_ALGORITHMS has had this guard; these had not. */
function ownEntry<T>(table: Record<string, T>, key: unknown): T | undefined {
  return typeof key === "string" && Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

function withinReplayWindow(obj: any, now?: string | null): boolean | null {
  const seconds = ownEntry(REPLAY_WINDOW_SECONDS, obj?.format);
  if (seconds === undefined) return null;
  const issued = isoToEpoch(obj?.issued_at);
  if (issued === null) return null;
  const n = now != null ? isoToEpoch(now) : Date.now() / 1000;
  if (n === null) return null;
  return issued <= n + CLOCK_SKEW_SECONDS && n - issued <= seconds;
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
 * an ISO-8601 string or null for the current time. No network. A relying party deciding
 * authorization offline also requires it bound to the presented credential: the same
 * token_value, signed by the credential's own public_key_hex (WIRE-SPEC 3.5). */
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
  // P9.8: delegation. Signed by the HOLDER's key and the AGENT's, never the issuer's.
  "polaris-agent-grant/1": ["format", "grant_id", "agent_public_key_hex", "agent_algorithm", "actions", "limits", "context_id", "issued_at", "expires_at", "algorithm"],
  "polaris-grant-revocation/1": ["format", "grant_id", "revoked_at", "algorithm"],
  "polaris-agent-proof/1": ["format", "grant_id", "action", "service_nonce", "issued_at", "algorithm"],
  // P9.2: the published anonymity set a holder proves against on their own device.
  "polaris-epoch-leaves/1": ["format", "authority", "epoch_id", "context_id", "merkle_root", "leaf_count", "leaves_root_hex", "issued_at", "expires_at", "algorithm"],
};

/** `issuerTrusted` is null when the caller supplied no anchors, which is the honest answer
 * to a question nobody asked. v9.430: the SDK could not answer it for any windowed
 * artifact, so a caller learned a trust list, registry, manifest, timestamp, ID token,
 * holder binding or epoch bundle carried a valid signature and had no way to learn whose.
 * The detached verifier has always taken anchors for all seven. A genuine signature by a
 * stranger is genuine and worthless. */
export type ArtifactVerdict = { authentic: boolean; fresh: boolean | null; note?: string;
                                issuerTrusted?: boolean | null };

/** WIRE-SPEC 3.3 and 3.16: a revoked leaf and an epoch leaf are each a SHA3-256, so a list of
 * 64 hex digits in either case. `String(null)` is "null" here and `str(None)` "None" in Python,
 * so a leaf of another type gave one signed feed two verdicts (2026-10-01). */
function leavesAreHex(leaves: unknown): boolean {
  return Array.isArray(leaves) && leaves.every((x) => typeof x === "string" && /^[0-9a-fA-F]{64}$/.test(x));
}

function revokedRoot(leaves: any): string {
  const arr: string[] = Array.isArray(leaves) ? leaves.map((x) => String(x).toLowerCase()) : [];
  const uniq = [...new Set(arr)].sort();
  return bytesToHex(sha3_256(new TextEncoder().encode(uniq.join("\n"))));
}

/** An inclusion proof's index or tree size as a JSON integer, or null: never a boolean, a
 * string, null or a fraction, each of which `Number()` would have turned into an integer. */
function wireInt(x: unknown): number | null {
  return typeof x === "number" && Number.isInteger(x) ? x : null;
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
  /** v9.431: whether the agency that signed the token is one this relying party trusts.
   * Null when no anchors were supplied. A genuine token from an agency you have never
   * heard of is genuine and meaningless. */
  issuerTrusted?: boolean | null;
};

/** Verify a polaris-id-token/1 (P8.4) as a relying party, offline: the issuing agency's
 * signature, that it was issued to THIS audience, that it carries the login's nonce, and
 * freshness (iat <= now < exp). The subject is a credential hash, never a person. */
export function verifyIdToken(tok: any, audience?: string | null, nonce?: string | null,
                              now?: string | null, anchors?: string[] | null): IdTokenVerdict {
  const t = tok ?? {};
  if (t.format !== "polaris-id-token/1") {
    return { authentic: false, audienceMatches: null, nonceMatches: null, fresh: null, sub: t.sub ?? null, acr: t.acr ?? null, note: "not a polaris-id-token/1" };
  }
  const base = verifySignedArtifact(t, now, anchors);
  if (!base.authentic) {
    return { authentic: false, audienceMatches: null, nonceMatches: null, fresh: null, sub: t.sub ?? null, acr: t.acr ?? null, note: base.note, issuerTrusted: base.issuerTrusted ?? null };
  }
  const ia = isoToEpoch(t.iat), ea = isoToEpoch(t.exp);
  const n = now != null ? isoToEpoch(now) : Date.now() / 1000;
  const fresh = ia !== null && ea !== null && n !== null ? ia <= n && n < ea : null;
  return { authentic: true, audienceMatches: audience != null ? t.aud === audience : null,
           nonceMatches: nonce != null ? t.nonce === nonce : null, fresh, sub: t.sub ?? null,
           acr: t.acr ?? null, issuerTrusted: base.issuerTrusted ?? null };
}

export function verifySignedArtifact(obj: any, now?: string | null,
                                     anchors?: string[] | null): ArtifactVerdict {
  const o = obj ?? {};
  const keys = ownEntry(ARTIFACT_KEYS, o.format);
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
  let commitmentNote: string | undefined;
  if (!ok) {
    // One reason a GENUINE artifact fails here and the signer is not at fault: the wire
    // format's canonicalisation distinguishes `4` from `4.0` and JavaScript cannot. An
    // agent grant signing `limits: {max_amount: 100.0}` is the reachable case. Reporting
    // `authentic: false` with no reason reads as a forgery, so the fact is named.
    const statement: Record<string, unknown> = {};
    for (const k of keys) statement[k] = o?.[k] ?? null;
    if (hasIntegralNumber(statement)) {
      commitmentNote = "the signature does not verify, AND this statement carries a whole " +
        "number: JavaScript cannot tell 4 from 4.0 and the canonical form does, so a " +
        "genuine artifact whose signer wrote a float here cannot be checked by this SDK. " +
        "Verify it with the Python reference before treating it as a forgery";
    }
  }
  if (ok && o.format === "polaris-epoch-leaves/1") {
    // P9.2: the leaves ride outside the signed statement, committed to by leaves_root_hex.
    const leaves = Array.isArray(o.all_leaves_hex) ? o.all_leaves_hex : [];
    ok = leavesAreHex(o.all_leaves_hex)
      && revokedRoot(leaves) === hexText(o.leaves_root_hex) && leaves.length === o.leaf_count;
    // NOT an early return. This is one of five commitment checks in this function and the
    // other four fall through to the tail, so returning here reported `fresh: null` where
    // its four siblings report the window's answer: the same class of failure, two
    // different freshness verdicts, inside one implementation. The Python SDK falls
    // through for all five, so the disagreement was also across the two reference SDKs,
    // on a key no published case constrains, which is why nothing caught it.
    if (!ok) commitmentNote = "the published leaves do not match the committed set";
  }
  if (ok && o.format === "polaris-revocation-feed/1") {
    // WIRE-SPEC 3.3: revoked_count MUST equal the number of distinct leaves; only the root was
    // compared until 2026-09-30, where the detached verifier compared both.
    const leaves = Array.isArray(o.revoked_leaves) ? o.revoked_leaves : [];
    ok = leavesAreHex(o.revoked_leaves)
      && revokedRoot(leaves) === hexText(o.revoked_root_hex)
      && typeof o.revoked_count === "number"
      && o.revoked_count === new Set(leaves.map((x: any) => String(x).toLowerCase())).size;
  } else if (ok && o.format === "polaris-agent-grant/1") {
    // WIRE-SPEC 3.17: grant_id is the revocation handle and names this grant alone. A grant
    // without one as text could never be revoked once a revocation names a grant as text
    // (2026-10-01), so it is not a grant.
    ok = wireText(o.grant_id) !== null;
  } else if (ok && o.format === "polaris-signed-document/1") {
    // WIRE-SPEC 3.12: the document's digest_algorithm MUST be SHA3-256 and digest_hex its
    // lowercase hex, as for a timestamp. No verifier here checked either until 2026-10-01.
    const d = o.document !== null && typeof o.document === "object" ? o.document : {};
    ok = d.digest_algorithm === "SHA3-256" && typeof d.digest_hex === "string"
      && /^[0-9a-f]{64}$/.test(d.digest_hex);
  } else if (ok && o.format === "polaris-timestamp/1") {
    // WIRE-SPEC 3.9: digest_algorithm MUST be SHA3-256 and digest_hex its lowercase hex; and the
    // instant must be one. Until 2026-09-30 none of the three was checked here.
    ok = o.digest_algorithm === "SHA3-256" && typeof o.digest_hex === "string"
      && /^[0-9a-f]{64}$/.test(o.digest_hex) && isoToEpoch(o.issued_at) !== null;
  } else if (ok && o.format === "polaris-federation-status-bundle/1") {
    // 2026-09-30: WIRE-SPEC 3.4 says member_count MUST equal the number of members, and only
    // the detached verifier checked it: a bundle whose signed count and listed members
    // disagreed was authentic here and in the Python SDK.
    const members = Array.isArray(o.members) ? o.members : [];
    ok = membersRoot(members) === hexText(o.members_root_hex)
      && typeof o.member_count === "number" && o.member_count === members.length;
  } else if (ok && o.format === "polaris-federation-manifest/1") {
    const active = new Set<string | null>(
      (Array.isArray(o.anchors) ? o.anchors : [])
        .filter((a: any) => a && (a.status ?? "active") === "active")
        .map((a: any) => hexText(a.public_key_hex)),
    );
    ok = hexIn(o.public_key_hex, active);
  } else if (ok && o.format === "polaris-registry/1") {
    const pub = o.publisher && typeof o.publisher === "object" ? o.publisher : {};
    const listed = new Set<string>(
      (Array.isArray(o.authorities) ? o.authorities : [])
        .filter((a: any) => a && sameId(a.agency_id, pub.agency_id) && (a.status ?? "active") === "active")
        .map((a: any) => hexText(a.public_key_hex)),
    );
    ok = hexIn(o.public_key_hex, listed);
  } else if (ok && o.format === "polaris-trust-list/1") {
    const pub = o.publisher && typeof o.publisher === "object" ? o.publisher : {};
    const active = new Set<string>(
      (Array.isArray(o.keys) ? o.keys : [])
        .filter((k: any) => k && sameId(k.agency_id, pub.agency_id) && k.status === "active")
        .map((k: any) => hexText(k.public_key_hex)),
    );
    ok = hexIn(o.public_key_hex, active);
  }
  // A replay-windowed format answers freshness the other way round; withinWindow needs
  // both ends of an interval and such an artifact has only its issuance.
  const replay = withinReplayWindow(o, now);
  // Same rule as the detached verifier and the Python SDK: the key that signed it,
  // lowercased, is in the anchor set. Null when the caller supplied none.
  const issuerTrusted = anchors == null
    ? null
    : hexIn(o.public_key_hex, anchors.map((a) => hexText(a)));
  return { authentic: ok, fresh: replay !== null ? replay : withinWindow(o, now),
           issuerTrusted, ...(commitmentNote ? { note: commitmentNote } : {}) };
}

// --- P9.6: timestamp anchor verification (was P8.5c) --------------------------------
// A timestamp alone does not settle long-term validation: whoever holds the timestamp
// authority's key can mint a backdated one. An ANCHORED timestamp is an entry in an
// append-only log whose head is published and cosigned by witnesses, so a forgery has to
// be absent from every witnessed head of its claimed era. Until now only Polaris's own
// detached verifier could check that. Here it is in the SDK an outsider installs.
const TIMESTAMP_LOG_ID = "polaris-timestamp-log";
const STH_FORMAT = "polaris-transparency-sth/1";
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
  // 2026-09-17: there was no type check anywhere on this path, and `verifyInclusion` is
  // exported. Two hex STRINGS of equal length compared EQUAL: `"d"[i] ^ "c"[i]` coerces each
  // character to NaN, `NaN | 0` is 0, and every position "matched", so
  // `verifyInclusion(0, 1, "deadbeef", "cafebabe", [])` reported the leaf INCLUDED. Passing
  // hex is the natural mistake, because that is the form the values arrive in inside the
  // proof JSON. The Python reference returns false for all of them.
  //
  // The guard that a test can see is in `verifyInclusion`, the exported entry point and the
  // only caller. This one is behind it and cannot be reached with the wrong type, so the
  // mutation drill would call it unprotected; it is kept because this function's whole job
  // is to compare BYTES and a silent coercion here is the bug it just had.
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

/** RFC 6962 section 2.1.1: is `leaf` the entry at `idx` in a tree of `treeSize` whose head
 * is `root`? Total on hostile input: a malformed path is false, never a throw. */
export function verifyInclusion(idx: number, treeSize: number, leaf: Uint8Array, root: Uint8Array, proof: Uint8Array[]): boolean {
  if (!Number.isInteger(idx) || !Number.isInteger(treeSize) || idx < 0 || idx >= treeSize) return false;
  // The docstring says "false, never a throw" and it threw: `null` reached a property read,
  // and a non-iterable `proof` reached the for-of before the per-element instanceof check
  // inside the loop could run. Both are verdicts now, as the Python reference gives.
  if (!(leaf instanceof Uint8Array) || !(root instanceof Uint8Array)) return false;
  if (!Array.isArray(proof)) return false;
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
  if (ok && witnessKey != null && !sameHex(c.public_key_hex, witnessKey)) {
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
  if (hexText(proof.entry_hex) !== v.timestampHash) {
    v.note = "the proof is not for this timestamp";
    return v;
  }
  // A head is a signed tree head: its log_id, tree_size and root are what its signature covers.
  // Any other artifact the log key signed carries those fields UNSIGNED, so "signed by the log
  // key" is not "a head of the log". Until 2026-09-30 a timestamp signed by that key, with a tree
  // invented beside it, anchored itself; the detached verifier refused it.
  if (sth.format !== STH_FORMAT) {
    v.note = "the head is not a " + STH_FORMAT;
    return v;
  }
  const sv = verifySignedArtifact(sth);
  v.sthAuthentic = sv.authentic;
  if (sth.log_id !== TIMESTAMP_LOG_ID || (proof.log_id != null && proof.log_id !== TIMESTAMP_LOG_ID)) {
    v.note = "the head is not a " + TIMESTAMP_LOG_ID + " head";
    return v;
  }
  // 2026-09-30: the index and tree size are JSON integers, read strictly, and a path that is
  // not a list is malformed. `Number()` read null and false as 0 and a non-list path as empty,
  // where the Python verifiers' `int()` read 1.5 and true as 1: the same inclusion proof was
  // anchored under one Polaris verifier and refused under another. All three share one rule.
  const idx = wireInt(proof.index), size = wireInt(proof.tree_size);
  let root: Uint8Array, path: Uint8Array[];
  try {
    if (idx === null || size === null) throw new Error("not a JSON integer");
    root = hexToBytes(String(sth.root_hash_hex));
    if (proof.proof_hex != null && !Array.isArray(proof.proof_hex)) throw new Error("the path is not a list");
    path = (proof.proof_hex ?? []).map((x: any) => hexToBytes(String(x)));
  } catch (e) {
    v.note = "malformed proof";
    return v;
  }
  v.index = idx;
  v.treeSize = size;
  if (size !== sth.tree_size ||
      !sameHex(proof.root_hash_hex, sth.root_hash_hex)) {
    v.note = "the proof and the head describe different trees";
    return v;
  }
  if (!v.sthAuthentic) { v.note = sv.note ?? "the head is not authentic"; return v; }
  if (logKey != null && !sameHex(sth.public_key_hex, logKey)) {
    v.note = "the head is not signed by the expected log key";
    return v;
  }
  v.anchored = verifyInclusion(idx, size, leafHash(v.timestampHash), root, path);
  if (!v.anchored) { v.note = "the inclusion proof does not reconstruct the head"; return v; }
  if (trustedWitnesses != null) {
    const trusted = new Set(trustedWitnesses.map((t) => hexText(t)));
    const seen = new Set<string>();
    for (const c of (Array.isArray(anchor.cosignatures) ? anchor.cosignatures : [])) {
      if (c === null || typeof c !== "object" || !verifyCosignature(c).authentic) continue;
      if (c.log_id === sth.log_id && c.tree_size === sth.tree_size &&
          sameHex(c.root_hash_hex, sth.root_hash_hex)) {
        const w = hexText(c.public_key_hex);
        if (w !== null && trusted.has(w)) seen.add(w);
      }
    }
    v.cosignerCount = seen.size;
    // A threshold is a whole number of witnesses, at least one: -1 was met by no cosignature at
    // all, and the two SDKs disagreed at 0.5 (2026-09-30).
    if (!(typeof threshold === "number" && Number.isInteger(threshold) && threshold >= 1)) {
      v.witnessed = false;
      v.note = "the witness threshold must be a whole number of at least 1, got " + String(threshold);
    } else {
      v.witnessed = v.cosignerCount >= threshold;
      if (!v.witnessed) {
        v.note = "only " + v.cosignerCount + " trusted witness cosignature(s) over this head, need " + threshold;
      }
    }
  }
  return v;
}

/** P9.5: `attestationSigned` says whether the trust edge was signed by the agency that made
 * it, or is an unsigned legacy row the manifest's signature carries on an operator's behalf.
 * null when no edge was found. */
export type CrossAuthorityVerdict = {
  decision: string; // "accept" | "reject"
  authentic: boolean;
  issuerTrusted: boolean | null; // null when no trust anchors were given
  via?: unknown;
  reason?: string;
  attestationSigned?: boolean | null;
};

export type HolderVerdict = {
  proved: boolean;
  bindingAuthentic: boolean | null;
  boundToCredential: boolean | null;
  bindingFresh: boolean | null;
  proofAuthentic: boolean | null;
  keyMatchesBinding: boolean | null;
  nonceMatches: boolean | null;
  note?: string;
  credentialAuthentic?: boolean | null;
  issuerTrusted?: boolean | null; // null when no anchors were given
};

/** Decide the holder key chain offline (P9.1): issuer anchor -> binding -> holder key -> proof.
 *
 * Polaris was issuer-centric until v9.349: a holder held a credential, not a key pair, so
 * presenting the file was the whole of the proof. A holder proof answers a different question,
 * whether the party presenting it holds the key the ISSUER bound to that credential. The proof
 * is signed over the credential, the context, the verifier's nonce and the instant, and
 * deliberately NOT over the presented code, so a coerced presentation stays
 * byte-indistinguishable from a consenting one.
 *
 * `proved` needs the credential's own signature to verify and the verifier's own `expectedNonce`
 * to match: a proof checked against no nonce is replayable, and a chain whose credential does not
 * verify binds a key to nothing. With `anchors`, the credential's issuer must also be one of them
 * (`issuerTrusted`); without, `issuerTrusted` is null. */
export function verifyHolder(credential: any, binding: any, proof: any, expectedNonce?: string | null,
                             expectedContext?: any, now?: string | null,
                             maxAgeSeconds: number = 300, anchors?: string[] | null): HolderVerdict {
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
  // 2026-09-30: the credential was compared with the binding and never verified, and no nonce was
  // required, so a chain an attacker signed end to end under a key of their own, replayed without
  // the verifier's challenge, was proved.
  const av = verifyAuthenticity(cred, anchors ?? null);
  v.credentialAuthentic = av.authentic;
  v.issuerTrusted = av.issuerTrusted;
  v.boundToCredential = wireTextEqual(b.token_value, cred.token_value)
    && sameHex(b.public_key_hex, cred.public_key_hex);
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
  // The proof names the credential it is about (token_value, which the holder signed); it must
  // be this one. Until 2026-09-30 only the key was compared, so a proof made for one credential
  // passed with another bound to the same holder key.
  v.keyMatchesBinding = sameHex(pr.public_key_hex, b.holder_public_key_hex)
    && wireTextEqual(pr.token_value, b.token_value) && (b.status ?? "active") === "active";
  // A nonce and a context read as the Python verifiers read them: String() spelled true "true"
  // and 1e-05 "0.00001" where str() spells them "True" and "1e-05", and Python's == read true as
  // context 1 (2026-10-01).
  if (expectedNonce != null) v.nonceMatches = wireTextEqual(pr.verifier_nonce, expectedNonce);
  const ctxOk = expectedContext == null || sameId(pr.context_id, expectedContext);
  // isoToEpoch, as every other freshness path here reads time. Date.parse read an issued_at with
  // no offset as LOCAL time, so the replay window moved with the machine's time zone: a proof
  // seven hours old was stale under UTC and fresh in Los Angeles (2026-09-30).
  const issued = isoToEpoch(pr.issued_at);
  const ref = now ? isoToEpoch(now) : Date.now() / 1000;
  const fresh = issued !== null && ref !== null && issued <= ref + 60 && (ref - issued) <= maxAgeSeconds;
  v.proved = !!(v.credentialAuthentic && v.issuerTrusted !== false
                && v.bindingAuthentic && v.bindingFresh && v.boundToCredential && v.proofAuthentic
                && v.keyMatchesBinding && v.nonceMatches === true && ctxOk && fresh);
  if (!v.proved) {
    v.note = expectedNonce == null ? "no nonce was expected: a holder proof checked against no challenge is replayable"
      : !v.credentialAuthentic ? "the credential's own signature does not verify"
      : v.issuerTrusted === false ? "the credential's issuer key is not in the anchors"
      : "the holder proof does not chain to a fresh issuer-signed binding for this credential";
  }
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
  if (ok && attestingAgencyId != null && !sameId(a.attesting_agency_id, attestingAgencyId)) {
    return { authentic: false, fresh: null, note: "the attestation names a different attesting agency than the manifest that published it" };
  }
  if (ok && expectedKey != null &&
      !sameHex(a.attested_public_key_hex, expectedKey)) {
    return { authentic: false, fresh: null, note: "the attestation is signed over a different attested key" };
  }
  return { authentic: ok, fresh: null, note: ok ? undefined : "the attestation signature is invalid" };
}

/** Decide a FOREIGN credential across authorities OFFLINE (P8.1, wire spec section 4). Accept
 * iff the authenticity pack is genuine, some federation manifest the relying party trusts
 * (authentic, fresh, signed by one of `trustedAnchors`) attests the credential's signing key in
 * the presented context (non-transitive), and -- if a revocation feed is supplied -- the
 * credential is not revoked (feed authentic, fresh, and bound to the issuer key). With no
 * `trustedAnchors` nothing is trusted: the decision is reject and `issuerTrusted` is null. No
 * network. */
export function verifyCrossAuthority(
  pack: any, contextId: any, manifests: any[], trustedAnchors?: string[] | null,
  revocationFeed?: any, now?: string | null, requireSignedAttestation: boolean = false,
): CrossAuthorityVerdict {
  const p = pack ?? {};
  if (!verifyAuthenticity(p).authentic) {
    return { decision: "reject", authentic: false, issuerTrusted: false, reason: "credential is not authentic" };
  }
  const tokenKey = hexText(p.public_key_hex);
  if (trustedAnchors == null) {
    // No root, no trusted authority. Every manifest is signed by a key it lists itself, so with no
    // anchor the relying party chose, an attacker's own manifest attesting the attacker's own
    // credential decided (2026-09-30). The detached verifier's equivalent takes
    // `trusted_manifests`, a set its caller vouches for by name; this function takes the manifests
    // a presentation brought, so it trusts none of them unaided.
    return { decision: "reject", authentic: true, issuerTrusted: null,
             reason: "no trust anchors were given: a manifest vouches for nothing by itself" };
  }
  const trusted = new Set(trustedAnchors.map((t) => hexText(t)));
  let via: unknown = null;
  let signedEdge: boolean | null = null;
  // A manifest set that is not an array is no manifests, as in the detached verifier:
  // `?? []` let `false` or an object through to `.map`, which threw (2026-09-30).
  for (const mm of (Array.isArray(manifests) ? manifests : []).map((m) => m ?? {})) {
    const mv = verifySignedArtifact(mm, now);
    if (!(mv.authentic && mv.fresh)) continue;
    // Trusted iff the key that SIGNED the manifest (one of its own active anchors, which
    // verifySignedArtifact requires) is one the relying party trusts. Until 2026-09-30 it was
    // any key the manifest merely LISTED, so an attacker's manifest that listed the relying
    // party's anchor beside the attacker's own root was trusted (WIRE-SPEC section 4).
    if (!hexIn(mm.public_key_hex, trusted)) continue;
    for (const att of Array.isArray(mm.attestations) ? mm.attestations : []) {
      if (att && tokenKey !== null && hexText(att.attested_public_key_hex) === tokenKey
          && sameId(att.context_id, contextId)) {
        // In-context means a context was presented (WIRE-SPEC section 4); before 2026-09-27
        // a missing one matched an edge from ANY context.
        // P9.5: is the edge signed by the agency that made it, or is it the operator's
        // word carried by the manifest's signature?
        const unsigned = !att.signature_hex && !att.public_key_hex;
        const av = verifyAttestation(att, mm.authority?.agency_id ?? null, tokenKey);
        // A signed edge is the attesting agency's only if one of ITS roots signed it: the key must
        // be among the carrying manifest's active anchors (2026-09-30; until then any key's valid
        // signature counted, so a stranger met requireSignedAttestation).
        const roots = new Set<string>((Array.isArray(mm.anchors) ? mm.anchors : [])
          .filter((x: any) => x && (x.status ?? "active") === "active")
          .map((x: any) => hexText(x.public_key_hex)));
        if (!unsigned && (!av.authentic || !hexIn(att.public_key_hex, roots))) continue;
        // An edge whose own window has closed is not an edge, however fresh the manifest
        // carrying it (WIRE-SPEC section 4). Until 2026-09-27 this decision never read
        // `valid_until`, and until 2026-09-28 it read it only for a SIGNED edge. A legacy edge
        // that states no window stays open.
        if (!attestationOpen(att, now)) continue;
        if (requireSignedAttestation && unsigned) continue;
        signedEdge = !unsigned;
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
    const bound = tokenKey !== null && hexText(rf.public_key_hex) === tokenKey;
    if (!(rv.authentic && rv.fresh && bound)) {
      return { decision: "reject", authentic: true, issuerTrusted: true, via,
               reason: "the revocation feed is not authentic, fresh, and bound to the issuer key",
               attestationSigned: signedEdge };
    }
    const leaf = bytesToHex(sha3_256(new TextEncoder().encode(String(p.token_value ?? ""))));
    const leaves = new Set((Array.isArray(rf.revoked_leaves) ? rf.revoked_leaves : []).map((x: any) => hexText(x)));
    if (leaves.has(leaf)) {
      return { decision: "reject", authentic: true, issuerTrusted: true, via, reason: "credential is revoked",
               attestationSigned: signedEdge };
    }
  }
  return { decision: "accept", authentic: true, issuerTrusted: true, via, attestationSigned: signedEdge };
}

export type VerifierOptions = {
  issuerUrl?: string;
  clientId?: string;
  clientSecret?: string;
  anchors?: string[] | null;
  timeoutMs?: number;
};

// The issuer URL's trailing slashes, removed in one pass. /\/+$/ did the same in time
// quadratic in a run of slashes that is not at the end, which is all a regular
// expression engine can do with it.
function trimTrailingSlashes(url: string): string {
  let end = url.length;
  while (end > 0 && url.charCodeAt(end - 1) === 47) end--;
  return url.slice(0, end);
}

export class PolarisVerifier {
  private issuerUrl?: string;
  private clientId?: string;
  private clientSecret?: string;
  private anchors: string[] | null;
  private timeoutMs: number;
  private bearer: string | null = null;
  private bearerExp = 0;

  constructor(opts: VerifierOptions = {}) {
    this.issuerUrl = opts.issuerUrl ? trimTrailingSlashes(opts.issuerUrl) : undefined;
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
    this.bearerExp = Date.now() + expiresIn(body.expires_in) * 1000;
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
    // A `credential` key that is present decides, as it does in the Python SDK: an object that
    // names a credential and supplies none (`credential: null`) was read here as a bare pack,
    // so the same bytes were provisional in this SDK and rejected in the other. Without the
    // key, the object itself is the pack, as before.
    const named = presentation !== null && typeof presentation === "object" && "credential" in presentation;
    const chosen = named ? presentation.credential : presentation;
    const cred: Pack = chosen !== null && typeof chosen === "object" ? chosen : {};
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
    // Only the JSON boolean true. Boolean() read {} and "false" as true; the Python SDK
    // read "false" as true too, and {} as false (2026-10-01).
    const current = status.currently_authoritative === true;
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

// ---------------------------------------------------------------------------
// P9.3 — the scoped nullifier, for a relying party that enforces one person once.
//
// This SDK cannot verify a Plonky2 proof: that needs the polaris_zk crate, and a
// verifier without it must ABSTAIN rather than guess, which is what the detached
// verifier does. What an SDK integrator DOES need is the one rule that is easy to
// get wrong by hand, so it lives here rather than in prose someone may not read.
// ---------------------------------------------------------------------------

/**
 * Do two nullifiers name the same person, in the same scope and epoch?
 *
 * Exact match on lowercase hex, and nothing else. Three warnings, because each is
 * a mistake a relying party can make while believing it is being careful:
 *
 * 1. Never compare PREFIXES. A nullifier is a Poseidon hash; a shared prefix
 *    means nothing, and treating it as a partial match would refuse strangers.
 * 2. Never compare ACROSS SCOPES. Two verifiers' nullifiers for one person are
 *    uncorrelated by construction. Comparing them cannot return information, and
 *    a `false` from such a comparison must not be read as "different person": the
 *    honest answer is that you cannot tell, which is the whole point of the scope.
 * 3. Never carry a ledger ACROSS EPOCHS. The nullifier rotates each epoch so that
 *    membership does not become a permanent identifier. A ledger that outlives its
 *    epoch quietly turns the privacy feature into a lifelong one.
 *
 * So: key your ledger by (your scope, epoch), keep only the nullifiers, and
 * compare with this.
 */
export function nullifiersLink(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return asciiTrim(a).toLowerCase() === asciiTrim(b).toLowerCase();
}

// ---------------------------------------------------------------------------
// P9.4 — the pairwise handle, for a relying party keying its own records.
// ---------------------------------------------------------------------------

/** Trim ASCII whitespace only, as the Python verifiers do: `trim()` also removed a byte-order
 * mark, and Python's `strip()` a file separator, so one scope gave two handles (2026-10-01).
 * A scan from each end, not a regular expression: `[ \t...]+$` retries every run of whitespace
 * that is not at the end, quadratic in its length. */
function asciiTrim(s: string): string {
  const ws = " \t\n\r\v\f";
  let i = 0;
  let j = s.length;
  while (i < j && ws.includes(s[i])) i++;
  while (j > i && ws.includes(s[j - 1])) j--;
  return s.slice(i, j);
}

const PAIRWISE_TAG = "polaris-pairwise/1";

/**
 * The per-verifier handle to key your records by, instead of the token value.
 *
 * `SHA3-256("polaris-pairwise/1|" || holderPublicKeyHex || "|" || verifierScope)`.
 * Recompute it yourself from the holder binding you verified; never take the
 * holder's word for it.
 *
 * What it buys: your stored records cannot be matched against another verifier's.
 * That is the realistic threat, because stored values are what get pooled, sold,
 * subpoenaed and breached.
 *
 * What it does not buy: a plain presentation still SHOWS you a stable token value,
 * issuer signature and holder key. Two verifiers who deliberately keep the raw
 * material can still correlate. Withholding it needs the zero-knowledge path, where
 * the scoped nullifier is the handle. The detached verifier's `verify_presentation`
 * reports which of the two applies, under `correlation`; do not assume the stronger.
 *
 * Returns null on unusable input rather than the hash of an empty string, which
 * would collide every holder into one record.
 */
export function pairwiseHandle(holderPublicKeyHex: unknown, verifierScope: unknown): string | null {
  if (typeof holderPublicKeyHex !== "string" || asciiTrim(holderPublicKeyHex) === "") return null;
  if (verifierScope === null || verifierScope === undefined || asciiTrim(String(verifierScope)) === "") return null;
  const material = `${PAIRWISE_TAG}|${asciiTrim(holderPublicKeyHex).toLowerCase()}|${asciiTrim(String(verifierScope))}`;
  return bytesToHex(sha3_256(new TextEncoder().encode(material)));
}

/**
 * Do two pairwise handles name the same holder at the same verifier?
 *
 * Exact hex, and only within one scope. Comparing handles across verifiers is
 * meaningless: the values are uncorrelated by construction, so a `false` cannot be
 * read as "different person". Across scopes the honest answer is that you cannot tell.
 */
export function handlesLink(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  return asciiTrim(a).toLowerCase() === asciiTrim(b).toLowerCase();
}

// ---------------------------------------------------------------------------
// P9.8 — the delegated agent grant.
// ---------------------------------------------------------------------------

/**
 * Does this grant's signed `actions` list cover the action being requested?
 *
 * An absent or empty list grants NOTHING. A verifier that read it as unrestricted
 * would turn a grant back into the unbounded credential hand-over that grants exist
 * to replace, and the mistake would be invisible because everything would work.
 */
export function grantCovers(grant: any, action: unknown): boolean {
  if (!grant || typeof grant !== "object") return false;
  const actions = (grant as any).actions;
  if (!Array.isArray(actions) || actions.length === 0) return false;
  // As text on both sides, as the Python verifiers read them: String() spelled true "true" where
  // str() spells it "True", so a signed `actions: [true]` covered "true" here only (2026-10-01).
  const want = wireText(action);
  return want !== null && actions.some((a: unknown) => wireText(a) === want);
}

/**
 * Are the grant's stated limits still satisfied? Returns `[ok, note]`.
 *
 * Unknown limit keys are REFUSED, not ignored. A grant that says `max_transfers: 3`
 * to a service that has never heard of `max_transfers` must not be treated as
 * unlimited; that is how a bounded grant silently becomes an unbounded one.
 */
export function grantWithinLimits(grant: any, usesSoFar = 0, amount?: number): [boolean, string | null] {
  // 2026-09-30: a `limits` that was a string or a number read as no limits, while the Python
  // verifiers also read a list that way; the same grant answered differently. Absent means
  // unlimited; anything present that is not a plain object is refused.
  if (!grant || typeof grant !== "object" || Array.isArray(grant)) {
    return [false, "the grant is not an object"];
  }
  const raw = grant.limits;
  if (raw !== undefined && raw !== null && (typeof raw !== "object" || Array.isArray(raw))) {
    return [false, "the grant's limits are not an object; refusing rather than ignoring them"];
  }
  const limits = (raw ?? {}) as Record<string, unknown>;
  const unknown = Object.keys(limits).filter((k) => k !== "max_uses" && k !== "max_amount").sort();
  if (unknown.length) {
    return [false, `the grant carries limits this verifier does not understand (${unknown.join(", ")}); refusing rather than ignoring them`];
  }
  const maxUses = limits["max_uses"];
  if (maxUses !== null && maxUses !== undefined) {
    // 2026-09-17: `usesSoFar` was not guarded, only `maxUses`, so a NaN use count cleared
    // the limit here exactly as a NaN limit cleared it in the Python reference. Each SDK had
    // a hole the other did not. `Number([2])` is 2 and `Number("")` is 0, so the value is
    // required to BE a finite number rather than be coercible to one: a one-element array
    // and a fractional count both slipped through before.
    if (typeof maxUses !== "number" || !Number.isFinite(maxUses) || !Number.isInteger(maxUses)) {
      return [false, "max_uses is not a whole finite number"];
    }
    if (typeof usesSoFar !== "number" || !Number.isFinite(usesSoFar) || !Number.isInteger(usesSoFar)) {
      return [false, "the use count is not a whole finite number"];
    }
    if (usesSoFar >= maxUses) return [false, `the grant's use limit (${maxUses}) is exhausted`];
  }
  const maxAmount = limits["max_amount"];
  // Each value that is present is a finite number, whether or not the other side of its
  // comparison is: read only in pairs, `max_amount: "100"` with no amount, or a NaN amount with
  // no limit, passed here where the Python SDK refuses both (2026-10-01).
  // The use count too: with no max_uses it went unread, so a NaN, "3" or true count passed here
  // where both Python verifiers refuse it (2026-10-01).
  for (const [label, value] of [["the use count", usesSoFar], ["max_amount", maxAmount],
                                ["the requested amount", amount]] as const) {
    if (value !== null && value !== undefined && (typeof value !== "number" || !Number.isFinite(value))) {
      return [false, `${label} is not a finite number`];
    }
  }
  if (maxAmount !== null && maxAmount !== undefined && amount !== undefined) {
    if (typeof maxAmount !== "number" || !Number.isFinite(maxAmount)
        || typeof amount !== "number" || !Number.isFinite(amount)) {
      return [false, "max_amount or the requested amount is not a number"];
    }
    if (Number(amount) > Number(maxAmount)) return [false, `the requested amount exceeds the grant's limit (${maxAmount})`];
  }
  return [true, null];
}

/**
 * Does this revocation end THIS grant, and was it signed by the right key?
 *
 * Signature verification is the caller's usual `verifySignedArtifact` step; this is the
 * binding check that must accompany it. Anyone may publish bytes claiming to revoke a
 * grant, but only the holder who signed the grant may end it, so the revocation's
 * signing key must equal the grant's.
 */
export function revocationEndsGrant(revocation: any, grant: any): boolean {
  if (!revocation || typeof revocation !== "object" || !grant || typeof grant !== "object") return false;
  if (revocation.format !== "polaris-grant-revocation/1") return false;
  // As text, as the Python verifiers read it: String(x ?? "") and str(x or "") disagreed on 0, true
  // and integers beyond 2**53 (2026-10-01).
  if (!wireTextEqual(revocation.grant_id, grant.grant_id)) return false;
  return sameHex(revocation.public_key_hex, grant.public_key_hex);
}

/**
 * Is this agent proof bound to THIS grant, this action and this service's nonce?
 *
 * Signature verification is the caller's `verifySignedArtifact` step; this is the binding
 * that must accompany it, or a copied grant is a bearer token. The proof must name the
 * grant, be signed by the agent key the grant names, under the algorithm the HOLDER
 * authorized, and, when the service supplies them, name the requested action and nonce.
 */
export function grantPrincipalBound(grant: any, binding: any, credential: any, now?: string | null): boolean {
  // The key that signed the grant must be the holder key an ISSUER bound to this credential,
  // under a binding that is genuine, fresh and ACTIVE; a revoked binding speaks for nobody.
  if (!grant || typeof grant !== "object" || !binding || typeof binding !== "object"
      || !credential || typeof credential !== "object") return false;
  if (binding.format !== "polaris-holder-binding/1") return false;
  // 2026-09-30: the credential's own signature, the first link WIRE-SPEC 3.17 names. It was
  // compared with the binding and never verified, so a chain signed end to end under an
  // attacker's key, with a credential whose signature does not verify, was bound. Whether its
  // issuer is one you trust is the caller's verifyAuthenticity(credential, anchors).
  if (!verifyAuthenticity(credential).authentic) return false;
  const bv = verifySignedArtifact(binding, now ?? null, null);
  // Fresh means CHECKED fresh: a binding with no window, or a `now` that is not an instant, left
  // `fresh` null and `!== false` read it as fresh, so a binding that expired in 2024 was bound
  // (2026-09-30).
  return !!(bv.authentic && bv.fresh === true && (binding.status ?? "active") === "active"
    && sameHex(binding.holder_public_key_hex, grant.public_key_hex)
    && wireTextEqual(binding.token_value, credential.token_value)
    && sameHex(binding.public_key_hex, credential.public_key_hex));
}

/** A hex field (a key or a digest) as all three verifiers compare it: a non-empty string, in lower
 * case; anything else null. String() reads a one-element list as its element where Python's str()
 * writes the brackets, so a signed `public_key_hex: [K]` matched K here alone (2026-10-01). */
function hexText(x: unknown): string | null {
  return typeof x === "string" && x !== "" ? x.toLowerCase() : null;
}

/** Both are hex text and the same in any case; a value with none matches nothing. */
function sameHex(a: unknown, b: unknown): boolean {
  const t = hexText(a);
  return t !== null && t === hexText(b);
}

/** `x` is hex text and one of `texts`; a value with none is in no collection, even one holding null. */
function hexIn(x: unknown, texts: Set<string | null> | readonly (string | null)[]): boolean {
  const t = hexText(x);
  if (t === null) return false;
  return texts instanceof Set ? texts.has(t) : texts.includes(t);
}

/** @internal Exported for the hex-text test; not public surface. Every caller reaches hexIn after a
 * signature check that a value with no hex text has already failed, so only a direct test can
 * hold its first refusal (the SDK mutation drill, 2026-10-01). */
export function __hexInForTest(x: unknown, texts: Set<string | null> | readonly (string | null)[]): boolean {
  return hexIn(x, texts);
}

/** Two agency or context ids name the same one only when both are strings, or both integers
 * held exactly, and equal: `===` let two missing ids match, where the Python SDK read a null
 * against a missing one as equal, and true as 1 (2026-10-01). */
function sameId(a: unknown, b: unknown): boolean {
  return (typeof a === "string" || Number.isSafeInteger(a)) && a === b;
}

/** A string, or an integer held exactly, as text, else null: the one reading of a signed id,
 * nonce or action that the Python verifiers share. `String(x ?? "")` here and `str(x or "")`
 * there disagreed on 0, 1.0 and true, and both let a proof that names no grant match a grant that
 * has none. Beyond 2**53 this SDK reads the nearest double and Python the exact integer. */
function wireText(x: unknown): string | null {
  if (typeof x === "string") return x;
  if (Number.isSafeInteger(x)) return String(x);
  return null;
}

/** The signed field names the expected value: both have a wire text and it is the same. A value
 * with none matches nothing; compared bare, null === null let a proof naming no nonce match an
 * expected nonce of 1.5 (2026-10-01). */
function wireTextEqual(signed: unknown, expected: unknown): boolean {
  const t = wireText(signed);
  return t !== null && t === wireText(expected);
}

export function agentProofProves(proof: any, grant: any, action?: unknown, nonce?: unknown): boolean {
  if (!proof || typeof proof !== "object" || !grant || typeof grant !== "object") return false;
  if (proof.format !== "polaris-agent-proof/1") return false;
  if (!wireTextEqual(proof.grant_id, grant.grant_id)) return false;
  if (!sameHex(proof.public_key_hex, grant.agent_public_key_hex)) return false;
  if (grant.agent_algorithm !== undefined && grant.agent_algorithm !== null
      && proof.algorithm !== grant.agent_algorithm) return false;
  if (nonce !== undefined && nonce !== null && !wireTextEqual(proof.service_nonce, nonce)) return false;
  if (action !== undefined && action !== null && !wireTextEqual(proof.action, action)) return false;
  return true;
}

// --- P8.2: the exchange in use (1.0.0-rc.64) ------------------------------------------
// The exchange artifacts were verified here for their signature and nothing else, while the
// detached verifier answers every question a party holding one has to ask: is it by the
// requester or responder expected, was the requester attested in this context by an
// authority trusted at the instant of the decision, and do the bodies held match what was
// committed. These answer the same questions, and nothing past authenticity for an object
// its signer did not sign. See the Python SDK for the same three functions.

export type ExchangeRequestVerdict = { authentic: boolean; requesterMatches: boolean | null;
  requesterAuthorized: boolean | null; bodyBound: boolean | null; note?: string };
export type ExchangeReceiptVerdict = { authentic: boolean; responderMatches: boolean | null;
  requesterAuthorized: boolean | null; via: any; requestBound: boolean | null;
  responseBound: boolean | null; responder: any; note?: string };
export type ExchangeMintVerdict = { authentic: boolean; responderMatches: boolean | null; note?: string };

function attestationOpen(att: any, now?: string | null): boolean {
  // The attestation's own window: none stated is open; one nobody can read is closed.
  if (att.valid_until === undefined || att.valid_until === null) return true;
  const u = isoToEpoch(att.valid_until);
  const n = now != null ? isoToEpoch(now) : Date.now() / 1000;
  return u !== null && n !== null && u >= n;
}

/** The authority of every manifest the caller trusts that is genuine and fresh at `now` and
 * attests `keyHex` in EXACTLY `contextId`, inside the attestation's own window, in order. */
function exchangeAuthorities(keyHex: unknown, contextId: unknown, manifests: unknown, now?: string | null): any[] {
  const want = hexText(keyHex);
  const found: any[] = [];
  if (!want) return found;
  for (const raw of Array.isArray(manifests) ? manifests : []) {
    const m = raw && typeof raw === "object" ? raw : {};
    const mv = verifySignedArtifact(m, now ?? null, null);
    if (!(mv.authentic && mv.fresh === true)) continue;
    const atts = Array.isArray(m.attestations) ? m.attestations : [];
    if (atts.some((att: any) => att && typeof att === "object"
        && hexText(att.attested_public_key_hex) === want
        && sameId(att.context_id, contextId)
        && attestationOpen(att, now))) {
      found.push(m.authority ?? null);
    }
  }
  return found;
}

/** Truth as the Python reference reads it: an empty object or list names nothing. */
function named(a: unknown): boolean {
  if (a === null || a === undefined || a === false || a === 0 || a === "") return false;
  if (Array.isArray(a)) return a.length > 0;
  if (typeof a === "object") return Object.keys(a as object).length > 0;
  return true;
}

function sameKey(a: unknown, b: unknown): boolean {
  return typeof a === "string" && typeof b === "string" && a.toLowerCase() === b.toLowerCase();
}

function sha3Hex(body: unknown): string {
  const raw = body instanceof Uint8Array ? body : new TextEncoder().encode(String(body));
  return bytesToHex(sha3_256(raw));
}

/** Verify a requester-signed exchange envelope OFFLINE (wire spec 3.11): the signature under
 * the key the envelope's signed `requester` names; with `requesterKey`, the requester
 * expected; with `trustedManifests`, attested in the envelope's context by one of them,
 * genuine and fresh at `now`; with `body`, that `request_hash` is the SHA3-256 of its
 * canonical JSON. */
export function verifyExchangeRequest(envelope: any, requesterKey?: string | null,
                                      trustedManifests?: any[] | null, body?: unknown,
                                      now?: string | null): ExchangeRequestVerdict {
  const e = envelope && typeof envelope === "object" ? envelope : {};
  const none = { requesterMatches: null, requesterAuthorized: null, bodyBound: null };
  if (e.format !== "polaris-exchange-request/1") {
    return { authentic: false, ...none, note: "not a polaris-exchange-request/1" };
  }
  const req = e.requester && typeof e.requester === "object" ? e.requester : {};
  // The verifying key must be the one the SIGNED statement claims for the requester, or a
  // stranger's signature speaks in the requester's name.
  if (!sameKey(e.public_key_hex, req.public_key_hex)) {
    return { authentic: false, ...none, note: "the envelope's key is not the requester it names" };
  }
  const base = verifySignedArtifact(e, now ?? null, null);
  if (!base.authentic) return { authentic: false, ...none, note: base.note };
  const v: ExchangeRequestVerdict = { authentic: true, ...none };
  if (requesterKey !== undefined && requesterKey !== null) v.requesterMatches = sameKey(e.public_key_hex, requesterKey);
  if (trustedManifests !== undefined && trustedManifests !== null) {
    v.requesterAuthorized = exchangeAuthorities(e.public_key_hex, e.context_id, trustedManifests, now).length > 0;
  }
  if (body !== undefined && body !== null) {
    v.bodyBound = sha3Hex(canonicalJson(body)) === hexText(e.request_hash);
  }
  return v;
}

/** Verify a responder-signed exchange receipt OFFLINE (wire spec 3.8): the signature; with
 * `responderKey`, the responder expected; with `trustedManifests`, the REQUESTER attested in
 * exactly the receipt's context (a receipt stating no context is not authorized by an
 * attestation from another) and by whom (`via`); with a body, that its commitment binds. A
 * receipt commits to the body bytes as exchanged, so a body is hashed as given. */
export function verifyExchangeReceipt(receipt: any, now?: string | null, trustedManifests?: any[] | null,
                                      responderKey?: string | null, requestBody?: unknown,
                                      responseBody?: unknown): ExchangeReceiptVerdict {
  const r = receipt && typeof receipt === "object" ? receipt : {};
  const none = { responderMatches: null, requesterAuthorized: null, via: null, requestBound: null,
                 responseBound: null, responder: null };
  if (r.format !== "polaris-exchange-receipt/1") {
    return { authentic: false, ...none, note: "not a polaris-exchange-receipt/1" };
  }
  const base = verifySignedArtifact(r, now ?? null, null);
  if (!base.authentic) return { authentic: false, ...none, note: base.note };
  const v: ExchangeReceiptVerdict = { authentic: true, ...none };
  if (responderKey !== undefined && responderKey !== null) v.responderMatches = sameKey(r.public_key_hex, responderKey);
  // A receipt names its responder in the statement its signer wrote, so the name is the signer's
  // claim until `responderKey` shows the signer IS that responder. Until 2026-09-30 a receipt
  // signed by a stranger reported the victim agency it named as its responder.
  if (v.responderMatches === true) v.responder = r.responder ?? null;
  if (requestBody !== undefined && requestBody !== null) {
    v.requestBound = sha3Hex(requestBody) === hexText(r.request_hash);
  }
  if (responseBody !== undefined && responseBody !== null) {
    v.responseBound = sha3Hex(responseBody) === hexText(r.response_hash);
  }
  if (trustedManifests !== undefined && trustedManifests !== null) {
    const req = r.requester && typeof r.requester === "object" ? r.requester : {};
    // `via` names the authority, so a manifest that names none answers nothing.
    const by = exchangeAuthorities(req.public_key_hex, r.context_id, trustedManifests, now).filter(named);
    v.via = by.length ? by[0] : null;
    v.requesterAuthorized = by.length > 0;
  }
  return v;
}

/** Verify a responder-signed mint statement OFFLINE (wire spec 3.8.1): the signature, and with
 * `responderKey`, that the expected responder's key signed it. */
export function verifyExchangeMint(mint: any, responderKey?: string | null): ExchangeMintVerdict {
  const m = mint && typeof mint === "object" ? mint : {};
  if (m.format !== "polaris-exchange-mint/1") {
    return { authentic: false, responderMatches: null, note: "not a polaris-exchange-mint/1" };
  }
  const base = verifySignedArtifact(m, null, null);
  if (!base.authentic) return { authentic: false, responderMatches: null, note: base.note };
  return { authentic: true,
           responderMatches: responderKey !== undefined && responderKey !== null ? sameKey(m.public_key_hex, responderKey) : null };
}

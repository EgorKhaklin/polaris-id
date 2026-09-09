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
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { sha3_256 } from "@noble/hashes/sha3.js";

export const ALGORITHM = "ML-DSA-65";
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
  let ok: boolean;
  try {
    const digest = sha3_256(new TextEncoder().encode(tok));
    ok = ml_dsa65.verify(hexToBytes(sigHex), digest, hexToBytes(pkHex));
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
  let ok: boolean;
  try {
    const digest = sha3_256(canonicalBytes(a, STATUS_ASSERTION_KEYS));
    ok = ml_dsa65.verify(hexToBytes(a.signature_hex), digest, hexToBytes(a.public_key_hex));
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
export function verifySignedArtifact(obj: any, now?: string | null): ArtifactVerdict {
  const o = obj ?? {};
  const keys = ARTIFACT_KEYS[o.format];
  if (!keys) return { authentic: false, fresh: null, note: "unknown or unsupported artifact: " + o.format };
  if (o.algorithm === PLACEHOLDER_LABEL || !o.public_key_hex) {
    return { authentic: false, fresh: null, note: "placeholder -- not authenticatable offline" };
  }
  let ok: boolean;
  try {
    const digest = sha3_256(canonicalBytes(o, keys));
    ok = ml_dsa65.verify(hexToBytes(o.signature_hex), digest, hexToBytes(o.public_key_hex));
  } catch (e) {
    return { authentic: false, fresh: null, note: "verification error: " + (e as Error).message };
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
  }
  return { authentic: ok, fresh: withinWindow(o, now) };
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
export function verifyCrossAuthority(
  pack: any, contextId: any, manifests: any[], trustedAnchors?: string[] | null,
  revocationFeed?: any, now?: string | null,
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

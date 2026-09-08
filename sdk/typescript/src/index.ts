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

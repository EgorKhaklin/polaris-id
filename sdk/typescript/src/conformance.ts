// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Egor Khaklin and the Polaris contributors
/**
 * node src/conformance.ts -- the verifier CLI the conformance suite drives.
 *
 * Reads ONE conformance case as JSON on stdin, dispatches on its `artifact` (default
 * "authenticity-pack"), and prints the verdict as JSON on stdout:
 *   {"artifact":"authenticity-pack","pack":{...},"anchors":[...]?}
 *       -> {"authentic":bool,"issuer_trusted":bool|null}
 *   {"artifact":"status-assertion","assertion":{...},"now":"<iso>"}
 *       -> {"authentic":bool,"fresh":bool|null,"active":bool|null}
 * See conformance/SPEC.md. This is the TypeScript counterpart of the Python SDK's
 * `python -m polaris_verify.conformance`; the same runner drives either.
 */
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { agentProofProves, verifyExchangeMint, verifyExchangeReceipt, verifyExchangeRequest, grantCovers, grantPrincipalBound, pairwiseHandle, revocationEndsGrant, verifyAttestation, verifyAuthenticity, verifyIdToken, verifyStatusAssertion, verifySignedArtifact, verifyCrossAuthority,
  verifyTimestampAnchor, verifyHolder, type Pack } from "./index.ts";

const SIGNED_ARTIFACTS = new Set([
  "epoch-checkpoint", "revocation-feed", "federation-manifest", "federation-status-bundle", "transparency-sth", "timestamp", "registry", "exchange-request", "signed-document", "id-token", "trust-list", "exchange-receipt", "exchange-mint", "holder-binding", "holder-proof", "epoch-leaves",
  // P9.8: delegation. Signed by the holder's key and the agent's, never the issuer's.
  "agent-grant", "grant-revocation", "agent-proof"]);

/** Decide ONE conformance case: the verdict object the CLI below prints. Exported so a harness
 * can decide many cases in one process; the CLI is the contract the runner drives. */
export function decide(caseObj: any): Record<string, unknown> {
  const artifact = (caseObj && caseObj.artifact) || "authenticity-pack";
  if (artifact === "authenticity-pack") {
    const pack: Pack = caseObj && caseObj.pack ? caseObj.pack : caseObj;
    const anchors = caseObj && caseObj.anchors ? caseObj.anchors : null;
    const v = verifyAuthenticity(pack ?? {}, anchors);
    return { authentic: v.authentic, issuer_trusted: v.issuerTrusted };
  } else if (artifact === "status-assertion") {
    const v = verifyStatusAssertion(caseObj.assertion ?? {}, caseObj.now ?? null);
    return { authentic: v.authentic, fresh: v.fresh, active: v.active };
  } else if (artifact === "trust-attestation") {
    // v9.421: see the Python dispatcher. A genuine edge between two OTHER agencies
    // verifies perfectly and is still not the edge being relied on.
    const v = verifyAttestation(caseObj.object ?? {}, caseObj.attesting_agency_id ?? null,
      caseObj.expected_key ?? null);
    return { authentic: v.authentic, fresh: v.fresh };
  } else if (artifact === "id-token") {
    // v9.420: see the Python dispatcher. A signature-only check passes a token
    // minted for another relying party, which is the whole attack.
    let idAnchors = caseObj.anchors ?? null;
    if (idAnchors === "self") idAnchors = [(caseObj.object ?? {}).public_key_hex];
    const v = verifyIdToken(caseObj.object ?? {}, caseObj.audience ?? null,
      caseObj.nonce ?? null, caseObj.now ?? null, idAnchors);
    return { authentic: v.authentic, audience_matches: v.audienceMatches,
      nonce_matches: v.nonceMatches, fresh: v.fresh,
      issuer_trusted: v.issuerTrusted ?? null };
  } else if (SIGNED_ARTIFACTS.has(artifact)) {
    let anchors = caseObj.anchors ?? null;
    if (anchors === "self") anchors = [(caseObj.object ?? {}).public_key_hex];
    const v = verifySignedArtifact(caseObj.object ?? {}, caseObj.now ?? null, anchors);
    return { authentic: v.authentic, fresh: v.fresh,
                                          issuer_trusted: v.issuerTrusted ?? null };
  } else if (artifact === "agent-grant-use") {
    // 2026-09-27: a grant IN USE; see the Python SDK's conformance CLI for why.
    const grant = caseObj.grant ?? {};
    const now = caseObj.now ?? null;
    const action = caseObj.requested_action ?? null;
    const authentic = verifySignedArtifact(grant, now, null).authentic;
    const verdict: Record<string, boolean | string | null> = {
      authentic, action_in_scope: null, revoked: null, agent_proved: null,
      principal_bound: null, pairwise_handle: null, correlation: null };
    const binding = caseObj.binding ?? null;
    if (authentic && binding !== null) {
      verdict.principal_bound = grantPrincipalBound(grant, binding, caseObj.credential ?? {}, now);
      if (caseObj.verifier_scope !== undefined && caseObj.verifier_scope !== null) {
        // The handle is "of the bound holder key" (SPEC.md): an object whose format says it is not
        // a holder binding names no holder key, as the detached verifier reports it (2026-09-30).
        const holderKey = binding && typeof binding === "object" && binding.format === "polaris-holder-binding/1"
          ? binding.holder_public_key_hex : null;
        verdict.pairwise_handle = pairwiseHandle(holderKey, caseObj.verifier_scope);
        verdict.correlation = "exposed";
      }
    }
    // A grant the holder did not sign grants nothing, so no later question is answered.
    if (authentic && action !== null) verdict.action_in_scope = grantCovers(grant, action);
    if (authentic && caseObj.revocation !== undefined && caseObj.revocation !== null) {
      verdict.revoked = Boolean(verifySignedArtifact(caseObj.revocation, now, null).authentic
        && revocationEndsGrant(caseObj.revocation, grant));
    }
    if (authentic && caseObj.agent_proof !== undefined && caseObj.agent_proof !== null) {
      verdict.agent_proved = Boolean(verifySignedArtifact(caseObj.agent_proof, now, null).authentic
        && agentProofProves(caseObj.agent_proof, grant, action, caseObj.expected_nonce ?? null));
    }
    return verdict;
  } else if (artifact === "exchange-use") {
    // 1.0.0-rc.64: an exchange artifact IN USE; see the Python SDK's conformance CLI for why.
    const obj = caseObj.object ?? {};
    const now = caseObj.now ?? null;
    if (obj.format === "polaris-exchange-receipt/1") {
      const r = verifyExchangeReceipt(obj, now, caseObj.manifests ?? null, caseObj.responder_key ?? null,
        caseObj.request_body ?? null, caseObj.response_body ?? null);
      return { authentic: r.authentic, responder_matches: r.responderMatches,
        requester_authorized: r.requesterAuthorized, via: r.via, request_bound: r.requestBound,
        response_bound: r.responseBound, responder: r.responder };
    } else if (obj.format === "polaris-exchange-mint/1") {
      const m = verifyExchangeMint(obj, caseObj.responder_key ?? null);
      return { authentic: m.authentic, responder_matches: m.responderMatches };
    } else {
      const q = verifyExchangeRequest(obj, caseObj.requester_key ?? null, caseObj.manifests ?? null,
        caseObj.body ?? null, now);
      return { authentic: q.authentic, requester_matches: q.requesterMatches,
        requester_authorized: q.requesterAuthorized, body_bound: q.bodyBound };
    }
  } else if (artifact === "timestamp-anchor") {
    const v = verifyTimestampAnchor(caseObj.timestamp ?? {}, caseObj.log_key ?? null,
      caseObj.trusted_witnesses ?? null, Number(caseObj.threshold ?? 1));
    return { anchored: v.anchored, witnessed: v.witnessed };
  } else if (artifact === "holder-chain") {
    const v = verifyHolder(caseObj.credential ?? {}, caseObj.binding ?? {}, caseObj.proof ?? {},
      caseObj.expected_nonce ?? null, caseObj.expected_context ?? null, caseObj.now ?? null);
    return { proved: v.proved };
  } else if (artifact === "cross-authority") {
    const v = verifyCrossAuthority(caseObj.pack ?? {}, caseObj.context_id, caseObj.manifests ?? [],
      caseObj.trusted_anchors ?? null, caseObj.revocation_feed ?? null, caseObj.now ?? null,
      caseObj.require_signed_attestation === true);
    return { decision: v.decision, authentic: v.authentic, issuer_trusted: v.issuerTrusted };
  } else {
    return { error: "unknown artifact: " + artifact };
  }
}

// The CLI: one case as JSON on stdin, its verdict as JSON on stdout (exit 2 for input it cannot run).
if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
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
    const verdict = decide(caseObj);
    process.stdout.write(JSON.stringify(verdict) + "\n");
    if ("error" in verdict) process.exit(2);
  });
}

"""polaris_web/transparency_routes.py -- the epoch tree and the anchor log.

The eighth block lifted out of app.py (2026-09-18): the ZK epoch surface (/epochs, /api/zk) and
the Merkle anchoring surface (/anchors, /api/anchor), which are the two artifacts a verifier can
check without asking the issuer anything.

THEY BELONG TOGETHER because they are the same shape of claim. An epoch root commits to a set of
credential states at a moment; an anchor commits to a batch of records at a moment. Both are
published, both are recomputable by an outside party, and neither carries any personal data. The
independent Python witness recomputes the epoch root, and a proof of inclusion is checked against
the published root rather than against anything this application says.

_zk_verify_and_consume stayed in app.py: /api/zk/verify uses it and so does the relying-party
API, and a helper with callers on both sides does not belong inside one of them. The single-use
nonce it consumes is what makes an online zero-knowledge verification non-replayable.
"""
import psycopg2
from psycopg2.extras import Json
from flask import jsonify, render_template, request, session

import anchoring
import security
import zk
from app import (
    _json_object,
    _zk_verify_and_consume,
    app,
    db_error_to_message,
    get_db,
    query,
)


# ---------------------------------------------------------------------------
# Anchor batch endpoints (R10-2 / M2-2)
# ---------------------------------------------------------------------------

@app.route('/api/anchor/batch', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_anchor_batch_close():
    """Close a Merkle batch for the pending BlockchainAnchor rows of a
    given signature algorithm. The Merkle root + per-leaf proofs are
    pre-computed by anchoring.py, then handed to close_anchor_batch
    (which holds a per-algorithm advisory lock for the transaction).

    Request: JSON { "algorithm_id": <int> }
    Response: { "batch_id": <int>, "merkle_root": <hex>, "batch_size": <int> }
    """
    payload = _json_object()
    try:
        algorithm_id = int(payload['algorithm_id'])
    except (KeyError, ValueError, TypeError):
        return jsonify(error="algorithm_id (int) is required"), 400

    pending = query("""
        SELECT a.anchor_id, a.commitment_hash
          FROM BlockchainAnchor a
          JOIN IdentityToken    t ON a.token_id = t.token_id
         WHERE a.batch_id IS NULL
           AND t.algorithm_id = %s
         ORDER BY a.anchor_id
    """, (algorithm_id,))

    if not pending:
        return jsonify(error="no pending anchors for that algorithm"), 404

    leaves = [(int(r['anchor_id']), r['commitment_hash']) for r in pending]
    merkle_root, proofs = anchoring.compute_batch(leaves, 'SHA3-256')

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("CALL close_anchor_batch(%s, %s, %s)",
                        (algorithm_id, merkle_root, Json(proofs)))
            conn.commit()
            cur.execute("""
                SELECT batch_id, batch_size FROM AnchorBatch
                 WHERE merkle_root = %s AND algorithm_id = %s
                 ORDER BY batch_id DESC LIMIT 1
            """, (merkle_root, algorithm_id))
            row = cur.fetchone()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(
        batch_id=row['batch_id'],
        merkle_root=merkle_root,
        batch_size=row['batch_size'],
    )


@app.route('/api/anchor/<int:token_id>')
@security.login_required
def api_anchor_get(token_id):
    """Return the BlockchainAnchor row plus the AnchorBatch (if batched)
    for a given token. Useful for clients that need the inclusion proof
    + root to verify off-line."""
    row = query("""
        SELECT a.anchor_id, a.token_id, a.did, a.commitment_hash,
               a.ledger_network, a.anchored_date, a.status,
               a.batch_id, a.merkle_proof,
               b.merkle_root, b.algorithm_id AS batch_algorithm_id,
               b.committed_to_chain, b.external_chain, b.external_chain_tx
          FROM BlockchainAnchor a
          LEFT JOIN AnchorBatch b ON a.batch_id = b.batch_id
         WHERE a.token_id = %s
    """, (token_id,), fetch='one')

    if not row:
        return jsonify(error="no anchor for that token"), 404

    return jsonify(dict(row))


@app.route('/api/anchor/verify/<int:token_id>')
@security.login_required
def api_anchor_verify(token_id):
    """Server-side proof verification: reconstruct the Merkle root from
    the stored leaf + proof and compare to the AnchorBatch root. Returns
    {"verified": true|false, ...}. A pending (not-yet-batched) anchor
    returns verified=false with status='PENDING'."""
    row = query("""
        SELECT a.anchor_id, a.commitment_hash, a.batch_id, a.merkle_proof,
               b.merkle_root
          FROM BlockchainAnchor a
          LEFT JOIN AnchorBatch b ON a.batch_id = b.batch_id
         WHERE a.token_id = %s
    """, (token_id,), fetch='one')

    if not row:
        return jsonify(error="no anchor for that token"), 404

    if row['batch_id'] is None:
        return jsonify(
            verified=False,
            status='PENDING',
            anchor_id=row['anchor_id'],
        )

    leaf = anchoring.leaf_hash(int(row['anchor_id']), row['commitment_hash'])
    proof = row['merkle_proof'] or []
    ok = anchoring.verify_proof(leaf, proof, row['merkle_root'])

    return jsonify(
        verified=bool(ok),
        anchor_id=row['anchor_id'],
        batch_id=row['batch_id'],
        merkle_root=row['merkle_root'],
        leaf=leaf,
    )


# ---------------------------------------------------------------------------
# ZK-SNARK epoch + verification endpoints (R10-1 / M2-1 / v8.23)
#
# C3 + A4 + B3 — transparent setup, Plonky2 SNARK, hybrid-Merkle circuit
# reusing R10-2 infrastructure. The Rust binary `polaris-zk` provides the
# crypto; this layer is the schema + route bridge.
# ---------------------------------------------------------------------------

@app.route('/api/zk/epoch/close', methods=['POST'])
@security.login_required
@security.require_role('admin')
@security.csrf_protect
def api_zk_epoch_close():
    """Close a ZK epoch: snapshot currently-valid ACTIVE tokens with
    their context-permissions, derive per-token leaf seeds, compute the
    Merkle root via the Rust prover, and CALL uc11_close_epoch which
    writes TokenStateEpoch + TokenStateEpochLeaf rows under a
    per-procedure advisory lock.

    Request: JSON { "context_id": <int>, "valid_until": "YYYY-MM-DD HH:MM:SS" }
    Response: { "epoch_id": <int>, "merkle_root": <hex>, "committed_count": <int> }
    """
    payload = _json_object()
    try:
        context_id = int(payload['context_id'])
        valid_until = payload['valid_until']
    except (KeyError, ValueError, TypeError):
        return jsonify(error="required fields: context_id (int), valid_until (timestamp)"), 400

    signed_by = session.get('user_id')
    if signed_by is None:
        return jsonify(error="session missing user_id"), 401

    # Snapshot the active tokens that have permission for the given context.
    rows = query("""
        SELECT t.token_id, t.token_value
          FROM IdentityToken t
          JOIN TokenPermission p ON p.token_id = t.token_id
         WHERE t.status = 'ACTIVE'
           AND p.context_id = %s
           AND NOT EXISTS (SELECT 1 FROM RevocationList r WHERE r.token_id = t.token_id)
         ORDER BY t.token_id
    """, (context_id,))
    if not rows:
        return jsonify(error="no eligible tokens for the given context"), 404

    # Derive per-token leaf commitments (deterministic).
    leaves = [zk.derive_leaf_seed(r['token_id'], r['token_value'], context_id) for r in rows]
    # P2.5 (v9.357): the ROOT only. Materialising an inclusion path per member cost 1.7 KB
    # each, roughly 17 GB of JSON at ten million members, and no query in this application
    # ever read one back: the holder derives their own path from the published leaf set on
    # their own device (P9.2). `compute_epoch_leaves` remains for callers that want the paths.
    root_hex = zk.compute_epoch_root(leaves)

    # Construct the JSONB payload uc11_close_epoch expects. `proof_path` is omitted, which
    # the procedure reads as SQL NULL into a column that has been nullable since migration 011.
    token_leaves = [{'token_id': r['token_id'], 'leaf_hash': leaf}
                    for r, leaf in zip(rows, leaves)]

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(
                "CALL uc11_close_epoch(%s, %s, %s, %s)",
                (root_hex, valid_until, signed_by, Json(token_leaves)),
            )
            conn.commit()
            cur.execute("""
                SELECT epoch_id, committed_count FROM TokenStateEpoch
                 WHERE merkle_root = %s ORDER BY epoch_id DESC LIMIT 1
            """, (root_hex,))
            row = cur.fetchone()
    except psycopg2.Error as e:
        conn.rollback()
        return jsonify(error=db_error_to_message(e)), 400
    finally:
        conn.close()

    return jsonify(
        epoch_id=row['epoch_id'],
        merkle_root=root_hex,
        committed_count=row['committed_count'],
    )


@app.route('/api/zk/epoch/<int:epoch_id>')
@security.login_required
def api_zk_epoch_get(epoch_id):
    """Return the TokenStateEpoch row for inspection (no witness data)."""
    row = query("""
        SELECT epoch_id, merkle_root, valid_from, valid_until,
               committed_count, closed_at, closed_by_user_id
          FROM TokenStateEpoch
         WHERE epoch_id = %s
    """, (epoch_id,), fetch='one')
    if not row:
        return jsonify(error="epoch not found"), 404
    # Coerce timestamps for JSON.
    return jsonify({
        'epoch_id': row['epoch_id'],
        'merkle_root': row['merkle_root'],
        'valid_from': str(row['valid_from']),
        'valid_until': str(row['valid_until']),
        'committed_count': row['committed_count'],
        'closed_at': str(row['closed_at']),
        'closed_by_user_id': row['closed_by_user_id'],
    })


@app.route('/api/zk/verify', methods=['POST'])
@security.login_required
@security.csrf_protect
def api_zk_verify():
    """Verify a ZK-SNARK proof bundle against a specified epoch + context
    + nonce. The caller supplies the proof bundle (from a prover) and
    states which (epoch_id, context_id, nonce) the proof is supposed to
    be bound to. The verifier:
      1. Loads the epoch's merkle_root from TokenStateEpoch.
      2. Checks valid_until >= now (R4 epoch-boundary).
      3. Calls the Rust verifier via zk.verify_proof_against_epoch.

    Request: JSON {
        "epoch_id": <int>,
        "context_id": <int>,
        "nonce": <int>,
        "proof_bundle": <ProofBundle dict>
    }
    Response: { "verified": <bool>, "reason": <optional str> }
    """
    payload = _json_object()
    try:
        epoch_id = int(payload['epoch_id'])
        context_id = int(payload['context_id'])
        nonce = int(payload['nonce'])
        proof_bundle = payload['proof_bundle']
        if not isinstance(proof_bundle, dict):
            raise TypeError("proof_bundle must be a dict")
    except (KeyError, ValueError, TypeError) as e:
        return jsonify(error=f"required fields: epoch_id, context_id, nonce, proof_bundle ({e})"), 400

    ok, reason, status = _zk_verify_and_consume(epoch_id, context_id, nonce, proof_bundle)
    body = {'verified': ok}
    if reason:
        body['reason'] = reason
    return jsonify(**body), status


# ============================================================================
# v2 SUBSTRATE READ-ONLY VIEWS (v8.28 — UI catch-up, graduation phase)
# ============================================================================
# Three read-only HTML surfaces for the v2 substrate that v8.21–v8.24 added
# at the backend but never exposed in the UI: anchor batches (R10-2),
# ZK epochs (R10-1), and the federation attestation graph (R11-3). All three
# are operator+ (no special role gate beyond login_required) — they're
# informational. Duress remains admin/auditor-only via the existing /duress.

@app.route('/anchors')
@security.login_required
def anchors_list():
    """AnchorBatch list (R10-2 / M2-2). Read-only view of the Merkle
    batches that group BlockchainAnchor rows under a per-algorithm
    advisory lock at close. The dashboard's "Anchor Batches" tile links
    here. Order is by created_at DESC (newest first), capped at 200 —
    seed has 2, prod-scale would still keep a single screen useful."""
    rows = query("""
        SELECT b.batch_id, b.merkle_root, b.batch_size, b.created_at,
               b.committed_to_chain, b.external_chain, b.external_chain_tx,
               alg.name AS algorithm_name, alg.quantum_resistant,
               (SELECT COUNT(*) FROM BlockchainAnchor a WHERE a.batch_id = b.batch_id) AS member_count
          FROM AnchorBatch b
          JOIN CryptographicAlgorithm alg ON b.algorithm_id = alg.algorithm_id
         ORDER BY b.created_at DESC, b.batch_id DESC
         LIMIT 200
    """)
    pending_anchors = query(
        "SELECT COUNT(*) AS n FROM BlockchainAnchor WHERE batch_id IS NULL",
        fetch='one')['n']
    return render_template('anchors_list.html', rows=rows,
                           pending_anchors=pending_anchors)


@app.route('/epochs')
@security.login_required
def epochs_list():
    """TokenStateEpoch list (R10-1 / M2-1). Read-only view of the closed
    ZK epochs. Each row carries the Plonky2 Merkle root the SNARK proves
    inclusion against, plus the committed_count (number of token leaves
    rolled into the epoch). Click-through shows the per-token leaves."""
    epoch_id_filter = request.args.get('epoch_id', type=int)
    rows = query("""
        SELECT e.epoch_id, e.merkle_root, e.valid_from, e.valid_until,
               e.committed_count, e.closed_at,
               u.username AS closed_by_username,
               (SELECT COUNT(*) FROM TokenStateEpochLeaf l
                 WHERE l.epoch_id = e.epoch_id) AS leaf_count
          FROM TokenStateEpoch e
          JOIN AppUser u ON e.closed_by_user_id = u.user_id
         ORDER BY e.closed_at DESC, e.epoch_id DESC
         LIMIT 200
    """)
    leaves = []
    if epoch_id_filter is not None:
        leaves = query("""
            SELECT l.leaf_id, l.epoch_id, l.token_id, l.leaf_hash,
                   i.legal_name AS holder_name,
                   t.status AS token_status
              FROM TokenStateEpochLeaf l
              JOIN IdentityToken t ON l.token_id = t.token_id
              JOIN Individual i ON t.individual_id = i.individual_id
             WHERE l.epoch_id = %s
             ORDER BY l.leaf_id
        """, (epoch_id_filter,))
    return render_template('epochs_list.html', rows=rows,
                           leaves=leaves, selected_epoch=epoch_id_filter)

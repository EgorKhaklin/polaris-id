// polaris_zk/src/lib.rs — Plonky2 Merkle-inclusion circuit + prover + verifier.
//
// Implements the C3+A4+B3 ship picked in the M2-1 alignment-exploration
// Sanctum:
//   C3 — transparent setup (no ceremony; Plonky2 is FRI-based)
//   A4 — Plonky2 SNARK family (post-quantum-comfortable hash commitments)
//   B3 — hybrid-Merkle circuit (the issuer commits the valid-token set
//        per epoch to a Merkle root; the SNARK proves membership)
//
// The circuit proves: "I know a secret S whose commitment
// L = Poseidon(S || context_id) sits at some index in the tree with public
// root R, I am bound to the public (epoch_id, context_id, nonce) triple, and
// the public nullifier N = Poseidon(S || scope || epoch_id) is derived from
// that SAME secret."
//
// Public inputs: epoch_root [4], epoch_id, context_id, nonce, scope,
//                nullifier [4]                                  (12 total)
// Private inputs: the holder secret S [4], sibling hashes (the inclusion path)
//
// P9.3 moved the leaf from an opaque SHA3-256 seed to a Poseidon commitment
// the circuit OPENS. That is what makes the nullifier mean anything. While the
// leaf was a SHA3 digest computed outside, the circuit treated it as an opaque
// private value, so a nullifier alongside it could have been derived from any
// secret at all: it would have proved only "I know some number", not "the
// person behind THIS leaf". Constraining both the leaf and the nullifier to one
// secret inside the circuit is the whole construction.
//
// What the nullifier buys, stated exactly: a relying party sees the same N for
// the same person in ITS OWN scope and epoch, so it can refuse a second proof;
// two relying parties with different scopes see values they cannot correlate,
// because distinguishing them needs S. It does NOT hide the holder from the
// ISSUER, who derives S at issuance to build the epoch tree and could compute
// any member's nullifier in any scope. Issuer-blind derivation is a different
// construction and is not claimed here.
//
// Per the R1-R9 audit refinements, the (epoch, context, nonce) binding
// prevents proof substitution: a proof cannot be re-labelled across
// epochs or contexts, or under a different nonce. It does NOT by itself
// prevent replay of the identical bundle — that needs the single-use
// nonce store deferred in threat-model.md T-T2. The witness-leak
// resistance is the SNARK's zero-knowledge property (Plonky2's standard
// FRI commitment scheme).
//
// Hash function: Poseidon (Plonky2 native). Different from the schema's
// SHA3-256 used by R10-2 AnchorBatch — these are distinct commitments
// for distinct primitives. The TokenStateEpoch.merkle_root column
// stores the Poseidon root as a hex-encoded byte sequence.

use anyhow::{anyhow, Result};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::{HashOut, HashOutTarget, MerkleCapTarget};
use plonky2::hash::merkle_proofs::MerkleProofTarget;
use plonky2::hash::merkle_tree::MerkleTree;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData};
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use serde::{Deserialize, Serialize};

pub type F = GoldilocksField;
pub type C = PoseidonGoldilocksConfig;
pub const D: usize = 2;

/// A Poseidon digest, and the holder secret, are 4 Goldilocks elements (32 bytes).
pub const HASH_ELEMENTS: usize = 4;

/// The circuit's public inputs, in registration order:
/// root[0..4], epoch_id, context_id, nonce, scope, nullifier[8..12].
pub const PUBLIC_INPUT_COUNT: usize = 12;

/// Merkle tree depth — the base-2 log of the maximum leaves per epoch
/// (max leaves = 2^depth). Runtime-parameterized (P0.7) so a deployment can
/// size the anonymity set to its population without editing source: Plonky2 is
/// transparent, so a depth change is a config change, not a trusted-setup
/// ceremony. Read ONCE (OnceLock) from `POLARIS_ZK_TREE_DEPTH`, defaulting to
/// 14 (16,384 leaves, covering the schema's 10,000-leaf epoch cap; the
/// anonymity set is a full epoch, not a 16-leaf demo).
///
/// PROFILES (measured numbers in DEVNOTES/zk-soundness.md):
///   demo        depth 10   1,024 leaves      fastest, teaching
///   epoch (dflt) depth 14  16,384 leaves     covers one 10k-leaf epoch
///   national    depth 24   16.7M leaves      a state-scale anonymity set
///
/// PROVER/VERIFIER MUST AGREE on depth: the circuit shape depends on it, so a
/// proof made at depth D verifies only against a verifier built at depth D. A
/// mismatched verifier REJECTS a valid proof (fails safe, never open). The
/// Python second witness reads the same env var; check_zk_tree_depth_synced
/// pins the two defaults together.
pub fn tree_depth() -> usize {
    static DEPTH: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *DEPTH.get_or_init(|| match std::env::var("POLARIS_ZK_TREE_DEPTH") {
        Ok(s) => {
            let d: usize = s.trim().parse().unwrap_or_else(|_| {
                panic!("POLARIS_ZK_TREE_DEPTH must be an integer, got {s:?}")
            });
            // Below 4 the tree is a toy; above 32 the u64 index space and the
            // proving cost both stop making sense. A bad config fails LOUD at
            // first use rather than silently proving at the wrong depth.
            assert!(
                (4..=32).contains(&d),
                "POLARIS_ZK_TREE_DEPTH must be in 4..=32, got {d}"
            );
            d
        }
        Err(_) => 14,
    })
}

/// The default tree depth, used where a compile-time reference reads better
/// than the env lookup (docs, error text). Kept equal to tree_depth()'s
/// fallback; the Python witness mirrors it.
pub const DEFAULT_TREE_DEPTH: usize = 14;

/// Pad leaves with zero-hash entries up to 2^tree_depth() so every tree
/// has the same shape and `tree.prove(i)` returns exactly tree_depth()
/// siblings.
fn pad_leaves_to_full_depth(leaves_hex: &[String]) -> Vec<String> {
    let cap = 1usize << tree_depth();
    let zero_leaf = "0".repeat(64); // 32 bytes of zero
    let mut padded: Vec<String> = leaves_hex.iter().cloned().collect();
    while padded.len() < cap {
        padded.push(zero_leaf.clone());
    }
    padded
}

/// JSON shape of a witness file (private inputs to the prover).
#[derive(Serialize, Deserialize, Debug)]
pub struct WitnessInput {
    /// Hex-encoded 32-byte holder secret. NEVER leaves the prover: the circuit
    /// opens `Poseidon(secret || context_id)` into the leaf and derives the
    /// nullifier from the same value. Before P9.3 this field was the leaf seed
    /// itself, handed in opaquely; a witness written against that shape is
    /// refused rather than reinterpreted, because the two mean different things.
    pub secret_hex: String,
    /// Position of this leaf in the Merkle tree (0-indexed).
    pub leaf_index: usize,
    /// All leaves in the epoch, hex-encoded. The prover reconstructs the
    /// tree from this to derive its proof path. In a production deployment
    /// only the leaf's siblings would be needed; v1 ships the full set
    /// because the witness file is local to the prover.
    pub all_leaves_hex: Vec<String>,
}

/// JSON shape of the public inputs (verifier-visible).
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicInputs {
    /// Hex-encoded epoch Merkle root (4 field elements → 32 bytes → 64 hex chars).
    pub epoch_root_hex: String,
    pub epoch_id: u64,
    pub context_id: u64,
    pub nonce: u64,
    /// The relying party's scope: the nullifier's domain separator.
    pub scope: u64,
    /// Hex-encoded scoped nullifier, `Poseidon(secret || scope || epoch_id)`.
    pub nullifier_hex: String,
}

/// JSON shape of a proof emitted by the prover.
#[derive(Serialize, Deserialize, Debug)]
pub struct ProofBundle {
    /// Hex-encoded serialized proof bytes.
    pub proof_hex: String,
    pub public_inputs: PublicInputs,
}

/// Decode 32-byte hex into 4 Goldilocks field elements (8 bytes each).
fn hex_to_hash_elements(hex_str: &str) -> Result<[F; 4]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(anyhow!("hash bytes must be exactly 32 ({} hex chars)", 64));
    }
    let mut elements = [F::ZERO; 4];
    for i in 0..4 {
        let mut limb_bytes = [0u8; 8];
        limb_bytes.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        // Goldilocks elements fit in u64; mask to be safe.
        let raw = u64::from_le_bytes(limb_bytes);
        // The Goldilocks field modulus is 2^64 - 2^32 + 1; raw u64 values
        // may exceed it. F::from_canonical_u64 panics on overflow; we
        // reduce explicitly.
        elements[i] = F::from_noncanonical_u64(raw);
    }
    Ok(elements)
}

/// Encode 4 Goldilocks field elements as 32 bytes → 64 hex chars.
fn hash_elements_to_hex(elements: &[F; 4]) -> String {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        let raw = elements[i].to_canonical_u64();
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&raw.to_le_bytes());
    }
    hex::encode(bytes)
}

/// The epoch leaf, OUT of circuit: `Poseidon(secret || context_id)`.
///
/// The issuer calls this to build the epoch tree and the holder calls it to find
/// their own leaf. It must agree element for element with the in-circuit
/// computation in `build_circuit`, and with `witness2.commitment.leaf_commitment`,
/// the independent Python witness. Three implementations, one commitment.
pub fn leaf_commitment(secret_hex: &str, context_id: u64) -> Result<String> {
    let secret = hex_to_hash_elements(secret_hex)?;
    let mut input = secret.to_vec();
    input.push(F::from_canonical_u64(context_id));
    let out = <PoseidonHash as Hasher<F>>::hash_no_pad(&input);
    Ok(hash_elements_to_hex(&out.elements))
}

/// The scoped nullifier, OUT of circuit: `Poseidon(secret || scope || epoch_id)`.
///
/// Same secret as the leaf, so a verifier that accepts the proof knows the
/// nullifier belongs to the member who owns that leaf. Scope is the relying
/// party's own domain separator: change it and the value changes unrecognisably,
/// which is what keeps two relying parties from correlating one person.
pub fn nullifier(secret_hex: &str, scope: u64, epoch_id: u64) -> Result<String> {
    let secret = hex_to_hash_elements(secret_hex)?;
    let mut input = secret.to_vec();
    input.push(F::from_canonical_u64(scope));
    input.push(F::from_canonical_u64(epoch_id));
    let out = <PoseidonHash as Hasher<F>>::hash_no_pad(&input);
    Ok(hash_elements_to_hex(&out.elements))
}

/// Compute the Merkle root over a vector of leaf hashes (each a HashOut).
/// Returns the root as a HashOut and the MerkleTree for proof generation.
pub fn build_merkle_tree(leaves_hex: &[String]) -> Result<MerkleTree<F, PoseidonHash>> {
    if leaves_hex.is_empty() {
        return Err(anyhow!("Cannot build Merkle tree from empty leaf set"));
    }
    if leaves_hex.len() > (1 << tree_depth()) {
        return Err(anyhow!(
            "Too many leaves ({}); circuit tree depth {} caps at {}",
            leaves_hex.len(),
            tree_depth(),
            1 << tree_depth()
        ));
    }
    // Each leaf is a 4-element field array. MerkleTree expects Vec<Vec<F>>.
    let padded = pad_leaves_to_full_depth(leaves_hex);
    let leaves: Vec<Vec<F>> = padded
        .iter()
        .map(|h| {
            let elements = hex_to_hash_elements(h)?;
            Ok(elements.to_vec())
        })
        .collect::<Result<_>>()?;
    // cap_height=0 means a single root hash (no Merkle cap). Standard.
    Ok(MerkleTree::new(leaves, 0))
}

// ---------------------------------------------------------------------------
// P2.5: the epoch tree, maintained sparsely and incrementally.
//
// The obvious implementation of a fixed-depth tree pads the leaf vector to 2^depth and
// hands the whole thing to a Merkle constructor. That is what `build_merkle_tree` does,
// and at the demo depth of 14 it is free. At the national depth of 24 it is not: computing
// a root over a thousand real members took 10.8 seconds and 2.9 GB of resident memory on
// the reference machine, because 16.7 million leaves get materialised whatever the real
// population is. An authority closing epochs on that budget is closing them by the minute
// and by the gigabyte, and the cost is paid entirely on zeros.
//
// The padding is the same value everywhere, so every subtree above the real leaves is an
// all-zero subtree, and an all-zero subtree at level k has ONE hash. Precompute those and
// a root costs O(real leaves + depth) instead of O(2^depth). The tree kept here is the
// real prefix of each level, nothing more.
//
// The root this produces MUST equal the padded construction's root element for element, or
// every epoch already published becomes unverifiable. `parity_with_the_padded_construction`
// asserts it across depths and populations, including the awkward shapes: one leaf, an odd
// count, a count one short of full, and a full tree with no padding at all.
// ---------------------------------------------------------------------------

/// `zero[k]` is the digest of an all-zero subtree of height k: `zero[0]` is the digest of a
/// zero leaf, and each level above is that value compressed with itself.
fn zero_hashes(depth: usize) -> Vec<HashOut<F>> {
    let mut z = Vec::with_capacity(depth + 1);
    // Plonky2 hashes a leaf of at most 4 elements with hash_or_noop, which for exactly 4
    // elements IS the leaf. A zero leaf is therefore four zero field elements.
    z.push(HashOut { elements: [F::ZERO; 4] });
    for k in 1..=depth {
        let below = z[k - 1];
        z.push(<PoseidonHash as Hasher<F>>::two_to_one(below, below));
    }
    z
}

/// A fixed-depth Merkle tree over a sparse population, with the zero padding folded away.
///
/// Holds only the real prefix of every level, so memory is O(real leaves) rather than
/// O(2^depth), and a single-leaf update walks one node per level rather than rebuilding.
pub struct EpochTree {
    depth: usize,
    zero: Vec<HashOut<F>>,
    /// `levels[0]` is the real leaf digests; `levels[depth]` is always exactly the root.
    levels: Vec<Vec<HashOut<F>>>,
}

impl EpochTree {
    /// Build from the real leaves. O(n + depth).
    pub fn from_leaves(leaves_hex: &[String]) -> Result<Self> {
        let depth = tree_depth();
        if leaves_hex.is_empty() {
            return Err(anyhow!("Cannot build Merkle tree from empty leaf set"));
        }
        if leaves_hex.len() > (1usize << depth) {
            return Err(anyhow!(
                "Too many leaves ({}); circuit tree depth {} caps at {}",
                leaves_hex.len(),
                depth,
                1usize << depth
            ));
        }
        let zero = zero_hashes(depth);
        let mut levels: Vec<Vec<HashOut<F>>> = Vec::with_capacity(depth + 1);
        let mut cur: Vec<HashOut<F>> = leaves_hex
            .iter()
            .map(|h| Ok(HashOut { elements: hex_to_hash_elements(h)? }))
            .collect::<Result<_>>()?;
        for k in 0..depth {
            levels.push(cur.clone());
            let mut next = Vec::with_capacity(cur.len().div_ceil(2));
            let mut i = 0;
            while i < cur.len() {
                let left = cur[i];
                // The right child is a real node when one exists and the zero subtree of
                // this height otherwise. That single substitution is the whole optimization.
                let right = if i + 1 < cur.len() { cur[i + 1] } else { zero[k] };
                next.push(<PoseidonHash as Hasher<F>>::two_to_one(left, right));
                i += 2;
            }
            cur = next;
        }
        levels.push(cur);
        Ok(EpochTree { depth, zero, levels })
    }

    /// The epoch root.
    pub fn root(&self) -> HashOut<F> {
        self.levels[self.depth][0]
    }

    /// How many real leaves the tree carries.
    pub fn len(&self) -> usize {
        self.levels[0].len()
    }

    /// Is the tree empty? Never true for a tree built by `from_leaves`, which refuses an
    /// empty set; present because clippy asks for it beside `len`.
    pub fn is_empty(&self) -> bool {
        self.levels[0].is_empty()
    }

    /// The sibling path for one leaf, bottom-up, exactly `depth` entries.
    pub fn proof(&self, index: usize) -> Result<Vec<HashOut<F>>> {
        if index >= self.len() {
            return Err(anyhow!("leaf_index {} out of range (only {} leaves)", index, self.len()));
        }
        let mut path = Vec::with_capacity(self.depth);
        let mut i = index;
        for k in 0..self.depth {
            let sibling = i ^ 1;
            path.push(match self.levels[k].get(sibling) {
                Some(h) => *h,
                None => self.zero[k],
            });
            i >>= 1;
        }
        Ok(path)
    }

    /// Replace one leaf and repair the path to the root. O(depth).
    ///
    /// This is what makes an epoch pipeline incremental: a revocation between epochs changes
    /// one member, and repairing 24 nodes is not the same operation as rebuilding 16.7
    /// million.
    pub fn set_leaf(&mut self, index: usize, leaf_hex: &str) -> Result<()> {
        if index >= self.len() {
            return Err(anyhow!("leaf_index {} out of range (only {} leaves)", index, self.len()));
        }
        self.levels[0][index] = HashOut { elements: hex_to_hash_elements(leaf_hex)? };
        let mut i = index;
        for k in 1..=self.depth {
            let parent = i >> 1;
            let left = self.levels[k - 1][parent << 1];
            let right = match self.levels[k - 1].get((parent << 1) | 1) {
                Some(h) => *h,
                None => self.zero[k - 1],
            };
            self.levels[k][parent] = <PoseidonHash as Hasher<F>>::two_to_one(left, right);
            i = parent;
        }
        Ok(())
    }
}

/// Compute the epoch Merkle root from the same leaf set the prover sees.
/// This is the function `polaris_web/zk.py`'s "compute_root" subcommand
/// shells out to.
pub fn compute_epoch_root(leaves_hex: &[String]) -> Result<String> {
    // Via the sparse tree since v9.357: the padded construction materialised 2^depth leaves
    // whatever the real population was, which at depth 24 was 10.8 seconds and 2.9 GB for a
    // thousand members. build_merkle_tree survives as the thing parity is asserted against.
    Ok(hash_elements_to_hex(&EpochTree::from_leaves(leaves_hex)?.root().elements))
}

/// The circuit's targets, handed back so `prove` can bind a witness to them.
pub struct CircuitTargets {
    /// Private: the holder's secret, 4 field elements.
    pub secret: Vec<plonky2::iop::target::Target>,
    /// Private: the inclusion proof's sibling hashes.
    pub proof: MerkleProofTarget,
    /// Private: the leaf's index, least-significant bit first.
    pub index_bits: Vec<plonky2::iop::target::BoolTarget>,
    /// Public: the epoch Merkle root.
    pub root: HashOutTarget,
    /// Public: the epoch this proof is bound to.
    pub epoch_id: plonky2::iop::target::Target,
    /// Public: the context this proof is bound to. Also opens the leaf.
    pub context_id: plonky2::iop::target::Target,
    /// Public: the verifier's challenge nonce.
    pub nonce: plonky2::iop::target::Target,
    /// Public: the relying party's scope, the nullifier's domain separator.
    pub scope: plonky2::iop::target::Target,
    /// Public: the scoped nullifier, computed in-circuit from `secret`.
    pub nullifier: HashOutTarget,
}

/// Build the circuit: prove "I know a secret S such that
/// Poseidon(S || context_id) is a leaf of the tree with public root R, and the
/// public nullifier N is Poseidon(S || scope || epoch_id) for the SAME S."
///
/// The secret never leaves the prover. The leaf is opened inside the circuit
/// rather than handed in, which is the difference between a nullifier that
/// proves something and one that proves nothing: an opaque leaf lets a prover
/// pair any leaf with any nullifier.
pub fn build_circuit() -> (CircuitBuilder<F, D>, CircuitTargets) {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Private: the holder's secret.
    let secret = builder.add_virtual_targets(HASH_ELEMENTS);

    // Private: the inclusion proof's sibling hashes.
    let proof_target = MerkleProofTarget {
        siblings: (0..tree_depth()).map(|_| builder.add_virtual_hash()).collect(),
    };

    // Private: the leaf's index expressed as bits.
    let index_bits: Vec<_> = (0..tree_depth())
        .map(|_| builder.add_virtual_bool_target_safe())
        .collect();

    // Public: the claimed root, wrapped as a MerkleCapTarget of length 1
    // (cap_height=0 means the cap IS the root).
    let root_target = builder.add_virtual_hash();
    builder.register_public_inputs(&root_target.elements);
    let cap_target = MerkleCapTarget(vec![root_target]);

    // Public: epoch_id, context_id, nonce, scope (one field element each).
    let epoch_id_t = builder.add_virtual_target();
    let context_id_t = builder.add_virtual_target();
    let nonce_t = builder.add_virtual_target();
    let scope_t = builder.add_virtual_target();
    builder.register_public_input(epoch_id_t);
    builder.register_public_input(context_id_t);
    builder.register_public_input(nonce_t);
    builder.register_public_input(scope_t);

    // OPEN THE LEAF. leaf = Poseidon(secret || context_id). Because the circuit
    // computes this rather than accepting it, the secret below is provably the
    // secret behind this member's leaf, and context_id is bound into the
    // commitment so a leaf minted for one context cannot be replayed into
    // another.
    let mut leaf_input = secret.clone();
    leaf_input.push(context_id_t);
    let leaf_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(leaf_input);

    // The core verification: hashing the opened leaf along the siblings, per the
    // index bits, must produce the claimed root.
    builder.verify_merkle_proof_to_cap::<PoseidonHash>(
        leaf_target.elements.to_vec(),
        &index_bits,
        &cap_target,
        &proof_target,
    );

    // THE NULLIFIER, from the SAME secret. Same person, same scope, same epoch
    // gives the same value, so a relying party can refuse a second proof. A
    // different scope gives a value no one can correlate with the first without
    // the secret, so two relying parties cannot link one person.
    let mut nullifier_input = secret.clone();
    nullifier_input.push(scope_t);
    nullifier_input.push(epoch_id_t);
    let nullifier_target = builder.hash_n_to_hash_no_pad::<PoseidonHash>(nullifier_input);
    builder.register_public_inputs(&nullifier_target.elements);

    (
        builder,
        CircuitTargets {
            secret,
            proof: proof_target,
            index_bits,
            root: root_target,
            epoch_id: epoch_id_t,
            context_id: context_id_t,
            nonce: nonce_t,
            scope: scope_t,
            nullifier: nullifier_target,
        },
    )
}

/// Generate a proof. Returns the serialized proof bytes + the public inputs.
pub fn prove(
    witness: &WitnessInput,
    epoch_id: u64,
    context_id: u64,
    nonce: u64,
    scope: u64,
) -> Result<ProofBundle> {
    // Validate the caller-supplied index against the REAL leaf count before
    // using it. build_merkle_tree pads to 2^tree_depth(), so an index past the
    // real leaves but within the padded range slips past tree.prove() and then
    // panics on the all_leaves_hex[leaf_index] slice; an index past the padded
    // range panics inside plonky2. Return the crate's error instead of aborting
    // the process — prove() is a trust boundary the app shells into.
    if witness.leaf_index >= witness.all_leaves_hex.len() {
        return Err(anyhow!(
            "leaf_index {} out of range (only {} leaves)",
            witness.leaf_index,
            witness.all_leaves_hex.len()
        ));
    }
    // The witness must actually open the leaf it claims. Plonky2 would fail to
    // fill the witness anyway, but with an error about an unsatisfied copy
    // constraint deep inside the prover; a holder whose secret does not match
    // the published set deserves to be told exactly that.
    let expected_leaf = leaf_commitment(&witness.secret_hex, context_id)?;
    let claimed_leaf = witness.all_leaves_hex[witness.leaf_index].to_lowercase();
    if expected_leaf != claimed_leaf {
        return Err(anyhow!(
            "the secret does not open leaf {}: Poseidon(secret || context_id) is {} but the \
             published leaf is {}. A leaf from a different context, or a pre-P9.3 SHA3-256 \
             leaf seed, will fail here.",
            witness.leaf_index,
            expected_leaf,
            claimed_leaf
        ));
    }

    let tree = EpochTree::from_leaves(&witness.all_leaves_hex)?;
    let siblings = tree.proof(witness.leaf_index)?;
    let root = tree.root();
    let root_hex = hash_elements_to_hex(&root.elements);
    let nullifier_hex = nullifier(&witness.secret_hex, scope, epoch_id)?;

    let (builder, t) = build_circuit();

    // Plonky2 1.x — the PartialWitness::set_* methods return Result (they error
    // on a double-set of the same target). prove() is a Result-returning trust
    // boundary, so propagate rather than ignore: a silently-dropped set error
    // could leave a target unconstrained. `?` surfaces it as the crate error.
    let mut pw = PartialWitness::<F>::new();
    let secret_elements = hex_to_hash_elements(&witness.secret_hex)?;
    for (i, target) in t.secret.iter().enumerate() {
        pw.set_target(*target, secret_elements[i])?;
    }
    pw.set_hash_target(t.root, root)?;
    pw.set_target(t.epoch_id, F::from_canonical_u64(epoch_id))?;
    pw.set_target(t.context_id, F::from_canonical_u64(context_id))?;
    pw.set_target(t.nonce, F::from_canonical_u64(nonce))?;
    pw.set_target(t.scope, F::from_canonical_u64(scope))?;

    for (i, sibling) in siblings.iter().enumerate() {
        pw.set_hash_target(t.proof.siblings[i], *sibling)?;
    }
    // Set index bits: tree_depth() bits, least significant first.
    for (i, bit_t) in t.index_bits.iter().enumerate() {
        let bit_val = ((witness.leaf_index >> i) & 1) as u64;
        pw.set_bool_target(*bit_t, bit_val == 1)?;
    }

    let circuit = builder.build::<C>();
    let proof = circuit.prove(pw)?;
    let proof_bytes = proof.to_bytes();

    Ok(ProofBundle {
        proof_hex: hex::encode(&proof_bytes),
        public_inputs: PublicInputs {
            epoch_root_hex: root_hex,
            epoch_id,
            context_id,
            nonce,
            scope,
            nullifier_hex,
        },
    })
}

/// Verify a proof. Returns true iff the proof is valid AND the public inputs in
/// the proof match the claimed (epoch_root, epoch_id, context_id, nonce, scope,
/// nullifier).
///
/// The nullifier is checked here like every other public input. A verifier that
/// took the bundle's stated nullifier on trust while verifying only the rest
/// would let a prover relabel their nullifier freely, and the double-proof
/// refusal it is there to support would refuse nothing.
pub fn verify(bundle: &ProofBundle) -> Result<bool> {
    let (builder, _) = build_circuit();
    let circuit = builder.build::<C>();
    let verifier_data: VerifierCircuitData<F, C, D> = circuit.verifier_data();

    let proof_bytes = hex::decode(&bundle.proof_hex)?;
    let proof = ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes, &verifier_data.common)?;

    // Our circuit commits to exactly PUBLIC_INPUT_COUNT public inputs. Plonky2's
    // from_bytes reads the public-input COUNT straight from the (caller-supplied)
    // buffer and does not constrain it to the circuit's count until the
    // cryptographic verify below — so a crafted proof can deserialize Ok with a
    // shorter public_inputs vector, and the indexing below would panic and abort
    // the process. verify() is an attacker-reachable trust boundary
    // (POST /api/zk/verify), so reject cleanly instead of crashing — the same
    // panic-as-DoS class v9.84 closed for prove()'s leaf_index. Returning false
    // is fail-closed: this branch is reached before verifier_data.verify(), so
    // it can never let an invalid proof verify true.
    if proof.public_inputs.len() < PUBLIC_INPUT_COUNT {
        return Ok(false);
    }

    // Check public-input binding before letting Plonky2 verify, so a
    // mismatched public-input shape rejects fast.
    let expected_root = hex_to_hash_elements(&bundle.public_inputs.epoch_root_hex)?;
    let actual_root = &proof.public_inputs[0..4];
    for i in 0..4 {
        if actual_root[i] != expected_root[i] {
            return Ok(false);
        }
    }
    let actual_epoch = proof.public_inputs[4].to_canonical_u64();
    let actual_context = proof.public_inputs[5].to_canonical_u64();
    let actual_nonce = proof.public_inputs[6].to_canonical_u64();
    let actual_scope = proof.public_inputs[7].to_canonical_u64();
    if actual_epoch != bundle.public_inputs.epoch_id
        || actual_context != bundle.public_inputs.context_id
        || actual_nonce != bundle.public_inputs.nonce
        || actual_scope != bundle.public_inputs.scope
    {
        return Ok(false);
    }
    let expected_nullifier = hex_to_hash_elements(&bundle.public_inputs.nullifier_hex)?;
    for i in 0..4 {
        if proof.public_inputs[8 + i] != expected_nullifier[i] {
            return Ok(false);
        }
    }

    // Plonky2 verifies the cryptographic soundness.
    let result = verifier_data.verify(proof);
    Ok(result.is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The context every test epoch is built for. A leaf commits to it, so a
    /// witness and a `prove` call must agree on it or the leaf will not open.
    const TEST_CONTEXT: u64 = 1;
    /// One relying party's scope. Any u64; a deployment derives it from its own
    /// identifier.
    const TEST_SCOPE: u64 = 7;

    /// n distinct holder secrets.
    fn make_secrets(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
                bytes[31] = 0x2a;
                hex::encode(bytes)
            })
            .collect()
    }

    /// The epoch's published leaves: `Poseidon(secret || context_id)` for each
    /// member. Since P9.3 a leaf is a commitment the circuit opens, not an
    /// opaque seed, so a test cannot invent leaves without secrets behind them.
    fn make_leaves(n: usize) -> Vec<String> {
        make_secrets(n)
            .iter()
            .map(|s| leaf_commitment(s, TEST_CONTEXT).unwrap())
            .collect()
    }

    #[test]
    fn honest_prover_passes() {
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let bundle = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();
        assert!(verify(&bundle).unwrap(), "honest prover should pass");
    }

    #[test]
    fn verify_rejects_malformed_proof_without_panicking() {
        // from_bytes reads the public-input count from the buffer, so a crafted
        // proof can deserialize with fewer than the 7 public inputs the circuit
        // commits to. Indexing public_inputs[0..4] used to panic (exit 101) on
        // such input — an unhandled crash at the attacker-reachable verify
        // boundary. An all-zero buffer the size of a real proof exercises it:
        // from_bytes accepts it (pi_len reads as 0 -> empty vector), and the
        // old slice would panic. verify() must now return cleanly, never crash.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let real = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();
        let n = hex::decode(&real.proof_hex).unwrap().len();
        let malformed = ProofBundle {
            proof_hex: hex::encode(vec![0u8; n]),
            public_inputs: real.public_inputs,
        };
        // No panic. A clean result either way: Ok(false) under the guard, or a
        // plain Err if a future plonky2 rejects the buffer in from_bytes. Never
        // an invalid proof verifying true.
        match verify(&malformed) {
            Ok(v) => assert!(!v, "a malformed proof must never verify true"),
            Err(_) => {}
        }
    }

    #[test]
    fn replay_with_different_nonce_fails() {
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let bundle = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();

        // Tamper the public inputs: change nonce. Verifier must reject.
        let mut tampered = bundle;
        tampered.public_inputs.nonce = 100;
        assert!(!verify(&tampered).unwrap(), "tampered nonce should fail");
    }

    #[test]
    fn cross_epoch_proof_fails() {
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let bundle = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();

        // Change epoch_id in public inputs: must reject.
        let mut tampered = bundle;
        tampered.public_inputs.epoch_id = 43;
        assert!(!verify(&tampered).unwrap(), "cross-epoch should fail");
    }

    // ------------------------------------------------------------------
    // v8.80 — additional adversarial tests (ARCH-004 test-depth gap)
    //
    // The first three tests cover the primary identity-preservation
    // properties. The four below cover targeted adversaries:
    //
    //   - tampered Merkle root in public inputs
    //   - wrong context binding (re-binding context_id)
    //   - prover-side replay across different epochs (witness valid
    //     in one epoch must not produce a passing proof for another)
    //   - small-cohort safety (n=1, n=2, edge sizes)
    // ------------------------------------------------------------------

    #[test]
    fn tampered_merkle_root_fails() {
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let bundle = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();

        // Flip a single byte in the committed Merkle root in public inputs.
        // The verifier MUST reject because the proof was generated against
        // the original root.
        let mut tampered = bundle;
        let mut root_bytes = hex::decode(&tampered.public_inputs.epoch_root_hex)
            .expect("root is hex");
        root_bytes[0] ^= 0x01;
        tampered.public_inputs.epoch_root_hex = hex::encode(root_bytes);
        assert!(
            !verify(&tampered).unwrap(),
            "tampered Merkle root must fail verification"
        );
    }

    #[test]
    fn cross_context_proof_fails() {
        // A proof bound to context_id=1 must not verify under context_id=2.
        // This is the schema C9 (context isolation) at the ZK layer.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let bundle = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();

        let mut tampered = bundle;
        tampered.public_inputs.context_id = 2;
        assert!(
            !verify(&tampered).unwrap(),
            "cross-context proof must fail (C9 / context isolation)"
        );
    }

    #[test]
    fn replay_across_epochs_fails() {
        // A prover with a valid witness for epoch 42 must not be able to
        // produce a verifying proof for epoch 43 simply by editing the
        // public inputs — the verifier binds the proof to the public
        // inputs at proof time.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let mut bundle = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();

        // Edit BOTH epoch_id and context_id and nonce simultaneously —
        // a multi-public-input replay attempt. Verifier must still reject.
        bundle.public_inputs.epoch_id = 43;
        bundle.public_inputs.context_id = 2;
        bundle.public_inputs.nonce = 100;
        assert!(
            !verify(&bundle).unwrap(),
            "multi-public-input replay must fail"
        );
    }

    #[test]
    fn small_cohort_n1_passes_with_one_leaf() {
        // Edge case: a 1-leaf Merkle tree. The leaf is its own root.
        // The honest prover must still produce a verifying proof.
        let secrets = make_secrets(1);
        let leaves = make_leaves(1);
        let witness = WitnessInput {
            secret_hex: secrets[0].clone(),
            leaf_index: 0,
            all_leaves_hex: leaves.clone(),
        };
        let bundle = prove(&witness, 42, 1, 99, TEST_SCOPE).unwrap();
        assert!(
            verify(&bundle).unwrap(),
            "honest prover with single-leaf cohort must verify"
        );
    }

    // ------------------------------------------------------------------
    // P9.3 — the scoped nullifier.
    //
    // The nullifier exists so a relying party can refuse the same person a
    // second time in its own scope WITHOUT learning who they are, and without
    // becoming able to compare notes with another relying party. Those are two
    // opposite-facing properties and both are tested here, along with the one
    // that makes either mean anything: the nullifier and the leaf are bound to
    // the same secret, inside the circuit.
    // ------------------------------------------------------------------

    #[test]
    fn one_person_once_per_scope() {
        // The same member proving twice to the SAME relying party produces the
        // same nullifier, even under a fresh nonce. That is what lets a verifier
        // that has recorded the first refuse the second.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let first = prove(&witness, 42, TEST_CONTEXT, 99, TEST_SCOPE).unwrap();
        let second = prove(&witness, 42, TEST_CONTEXT, 1234, TEST_SCOPE).unwrap();
        assert!(verify(&first).unwrap() && verify(&second).unwrap());
        assert_eq!(
            first.public_inputs.nullifier_hex, second.public_inputs.nullifier_hex,
            "one person proving twice in one scope must be recognisable as the same person"
        );
        assert_ne!(
            first.proof_hex, second.proof_hex,
            "the proofs themselves must differ; only the nullifier repeats"
        );
    }

    #[test]
    fn two_verifiers_cannot_link_one_person() {
        // The same member proving to two relying parties with different scopes
        // yields values neither can correlate. This is the privacy half, and it
        // is why the scope is a public input rather than a constant.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let at_a = prove(&witness, 42, TEST_CONTEXT, 99, 1001).unwrap();
        let at_b = prove(&witness, 42, TEST_CONTEXT, 99, 2002).unwrap();
        assert!(verify(&at_a).unwrap() && verify(&at_b).unwrap());
        assert_ne!(
            at_a.public_inputs.nullifier_hex, at_b.public_inputs.nullifier_hex,
            "two relying parties must not see the same value for one person"
        );
    }

    #[test]
    fn distinct_members_get_distinct_nullifiers() {
        // Within one scope, two different people must not collide, or the first
        // to prove would lock the second out.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let mut seen = std::collections::HashSet::new();
        for i in 0..8 {
            let witness = WitnessInput {
                secret_hex: secrets[i].clone(),
                leaf_index: i,
                all_leaves_hex: leaves.clone(),
            };
            let bundle = prove(&witness, 42, TEST_CONTEXT, 99, TEST_SCOPE).unwrap();
            assert!(verify(&bundle).unwrap());
            assert!(
                seen.insert(bundle.public_inputs.nullifier_hex.clone()),
                "member {} collided with an earlier member's nullifier",
                i
            );
        }
    }

    #[test]
    fn a_forged_nullifier_does_not_verify() {
        // The nullifier is a public input like any other. A prover who edits it
        // after the fact must be caught, or the double-proof refusal it supports
        // would refuse nothing: every second visit could carry a fresh value.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let mut bundle = prove(&witness, 42, TEST_CONTEXT, 99, TEST_SCOPE).unwrap();
        bundle.public_inputs.nullifier_hex = "ff".repeat(32);
        assert!(!verify(&bundle).unwrap(), "a forged nullifier must not verify");
    }

    #[test]
    fn a_rescoped_proof_does_not_verify() {
        // Relabelling a proof into another relying party's scope must fail: the
        // scope is bound at proof time, so a proof made for A cannot be replayed
        // at B, which would otherwise defeat B's own double-proof refusal.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let mut bundle = prove(&witness, 42, TEST_CONTEXT, 99, 1001).unwrap();
        bundle.public_inputs.scope = 2002;
        assert!(!verify(&bundle).unwrap(), "a proof must not be re-scoped after the fact");
    }

    #[test]
    fn a_stranger_cannot_open_a_members_leaf() {
        // The whole construction rests on the leaf being a commitment the
        // circuit OPENS. A secret that does not open the claimed leaf must be
        // refused at the prover, not silently proved against an opaque value.
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: "ab".repeat(32),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let err = prove(&witness, 42, TEST_CONTEXT, 99, TEST_SCOPE).unwrap_err();
        assert!(
            err.to_string().contains("does not open leaf"),
            "a stranger's secret must be refused by name, got: {}",
            err
        );
    }

    #[test]
    fn a_leaf_from_another_context_does_not_open() {
        // context_id is inside the commitment, so a member's leaf in context 1
        // cannot be replayed into context 2 even by its rightful owner.
        let secrets = make_secrets(8);
        let leaves = make_leaves(8);
        let witness = WitnessInput {
            secret_hex: secrets[3].clone(),
            leaf_index: 3,
            all_leaves_hex: leaves.clone(),
        };
        let err = prove(&witness, 42, TEST_CONTEXT + 1, 99, TEST_SCOPE).unwrap_err();
        assert!(
            err.to_string().contains("does not open leaf"),
            "a leaf minted for another context must not open, got: {}",
            err
        );
    }

    #[test]
    fn the_out_of_circuit_derivations_agree_with_the_circuit() {
        // leaf_commitment and nullifier are what the issuer, the wallet and the
        // second witness call. If they drifted from the in-circuit computation,
        // the issuer would publish leaves no holder could open.
        let secrets = make_secrets(4);
        let leaves = make_leaves(4);
        let witness = WitnessInput {
            secret_hex: secrets[2].clone(),
            leaf_index: 2,
            all_leaves_hex: leaves.clone(),
        };
        let bundle = prove(&witness, 42, TEST_CONTEXT, 99, TEST_SCOPE).unwrap();
        assert!(verify(&bundle).unwrap());
        assert_eq!(
            bundle.public_inputs.nullifier_hex,
            nullifier(&secrets[2], TEST_SCOPE, 42).unwrap(),
            "the proof's nullifier must equal the out-of-circuit derivation"
        );
        assert_eq!(
            leaves[2],
            leaf_commitment(&secrets[2], TEST_CONTEXT).unwrap(),
            "the published leaf must equal the out-of-circuit commitment"
        );
    }

    // ------------------------------------------------------------------
    // P2.5 — the sparse, incremental epoch tree.
    //
    // The optimization is only allowed to be faster. If its root ever differs from the
    // padded construction's by one element, every epoch already published becomes
    // unverifiable, so parity is asserted first and across the shapes that break naive
    // implementations: one leaf, an odd count, one short of full, and exactly full.
    // ------------------------------------------------------------------

    fn hexes(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| {
                let mut b = [0u8; 32];
                b[0..8].copy_from_slice(&((i as u64) + 1).to_le_bytes());
                b[31] = 0x5a;
                hex::encode(b)
            })
            .collect()
    }

    #[test]
    fn parity_with_the_padded_construction() {
        let cap = 1usize << tree_depth();
        for n in [1usize, 2, 3, 5, 8, 9, 17, 100, cap - 1, cap] {
            let leaves = hexes(n);
            let padded = build_merkle_tree(&leaves).unwrap();
            let sparse = EpochTree::from_leaves(&leaves).unwrap();
            assert_eq!(
                padded.cap.0[0], sparse.root(),
                "sparse root diverged from the padded root at n={}; every published epoch \
                 would become unverifiable", n
            );
        }
    }

    #[test]
    fn parity_of_every_inclusion_path() {
        // A root that matches with paths that do not is worse than a root that does not
        // match, because the failure only surfaces when a holder tries to prove.
        let leaves = hexes(37);
        let padded = build_merkle_tree(&leaves).unwrap();
        let sparse = EpochTree::from_leaves(&leaves).unwrap();
        for i in 0..leaves.len() {
            let a = padded.prove(i);
            let b = sparse.proof(i).unwrap();
            assert_eq!(a.siblings.len(), b.len(), "path length differs at leaf {}", i);
            assert_eq!(a.siblings, b, "sibling path diverged at leaf {}", i);
        }
    }

    #[test]
    fn an_incremental_update_equals_a_rebuild() {
        // The point of set_leaf: repairing one path must land exactly where rebuilding
        // from scratch would. Anything else is a tree that drifts from its own history.
        let mut leaves = hexes(50);
        let mut tree = EpochTree::from_leaves(&leaves).unwrap();
        let replacement = "ab".repeat(32);
        for &i in &[0usize, 1, 7, 24, 49] {
            tree.set_leaf(i, &replacement).unwrap();
            leaves[i] = replacement.clone();
            let rebuilt = EpochTree::from_leaves(&leaves).unwrap();
            assert_eq!(tree.root(), rebuilt.root(), "incremental update diverged at leaf {}", i);
            for j in 0..leaves.len() {
                assert_eq!(tree.proof(j).unwrap(), rebuilt.proof(j).unwrap(),
                           "path {} diverged after updating {}", j, i);
            }
        }
    }

    #[test]
    fn an_updated_leaf_still_proves_and_the_old_one_does_not() {
        // The property a revocation between epochs depends on.
        let leaves = hexes(16);
        let mut tree = EpochTree::from_leaves(&leaves).unwrap();
        let old_root = tree.root();
        let replacement = "cd".repeat(32);
        tree.set_leaf(5, &replacement).unwrap();
        assert_ne!(old_root, tree.root(), "changing a member must change the root");

        let mut updated = leaves.clone();
        updated[5] = replacement;
        let witness = WitnessInput {
            secret_hex: "ef".repeat(32),
            leaf_index: 5,
            all_leaves_hex: updated,
        };
        // The secret does not open that leaf, so prove() refuses by name rather than
        // producing a proof about a leaf nobody can open.
        assert!(prove(&witness, 1, 1, 1, 0).unwrap_err().to_string().contains("does not open leaf"));
    }

    #[test]
    fn the_sparse_tree_refuses_what_the_padded_one_refuses() {
        assert!(EpochTree::from_leaves(&[]).is_err(), "an empty set has no root");
        let too_many = vec!["00".repeat(32); (1usize << tree_depth()) + 1];
        assert!(EpochTree::from_leaves(&too_many).is_err(), "a set past capacity must be refused");
        let t = EpochTree::from_leaves(&hexes(4)).unwrap();
        assert!(t.proof(4).is_err(), "a path for a leaf that does not exist must be refused");
        let mut t = EpochTree::from_leaves(&hexes(4)).unwrap();
        assert!(t.set_leaf(9, &"00".repeat(32)).is_err(), "an out-of-range update must be refused");
    }

    #[test]
    fn zero_subtree_hashes_are_what_the_padding_produces() {
        // If this drifts, everything above is wrong in a way the parity tests would catch
        // only at the depths they happen to cover. Anchor it directly.
        let z = zero_hashes(tree_depth());
        assert_eq!(z[0], HashOut { elements: [F::ZERO; 4] }, "a zero leaf is four zero elements");
        for k in 1..=tree_depth() {
            assert_eq!(z[k], <PoseidonHash as Hasher<F>>::two_to_one(z[k - 1], z[k - 1]));
        }
    }
}

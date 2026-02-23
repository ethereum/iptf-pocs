pub mod chain;
pub mod prover;
pub mod store;
pub mod tee;

use alloy::primitives::{B256, Bytes};

/// Public inputs for the unified transfer circuit (9 fields).
///
/// These are the values that the on-chain verifier checks against the proof.
/// The same structure is used for lock, claim, refund, and standard transfer —
/// mode discrimination happens via the `timeout` + `pk_stealth` + `h_swap` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPublicInputs {
    /// Nullifier of the spent input note
    pub nullifier: B256,
    /// Merkle root for input note inclusion
    pub root: B256,
    /// Commitment of the newly created output note
    pub new_commitment: B256,
    /// Lock: output timeout. Claim/Refund: input timeout. Transfer: 0.
    pub timeout: B256,
    /// Lock: stealth x-coord. Claim: in_owner. Refund/Transfer: 0.
    pub pk_stealth: B256,
    /// Lock: binding commitment for swap_id. Others: 0.
    pub h_swap: B256,
    /// Lock: binding commitment for ephemeral key. Others: 0.
    pub h_r: B256,
    /// Lock: binding commitment for counterparty meta key. Others: 0.
    pub h_meta: B256,
    /// Lock: binding commitment for encrypted salt. Others: 0.
    pub h_enc: B256,
}

/// A proof for the unified transfer circuit
#[derive(Debug, Clone)]
pub struct TransferProof {
    /// Serialized proof in Barretenberg format
    pub proof: Bytes,
    /// Public inputs extracted from the witness
    pub public_inputs: TransferPublicInputs,
}

impl TransferProof {
    /// Create a new `TransferProof` from raw proof bytes and the public inputs.
    pub fn new(proof: Bytes, public_inputs: TransferPublicInputs) -> Self {
        Self {
            proof,
            public_inputs,
        }
    }
}

/// On-chain lock data read from a `SwapNoteLocked` event.
///
/// The TEE reads this to verify binding commitments against off-chain submissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapLockData {
    /// Commitment of the locked note
    pub commitment: B256,
    /// Timeout timestamp
    pub timeout: B256,
    /// Stealth address (owner of the locked note)
    pub pk_stealth: B256,
    /// Binding commitment: H(DOMAIN_BIND_SWAP, swap_id, salt)
    pub h_swap: B256,
    /// Binding commitment: H(DOMAIN_BIND_R, R.x)
    pub h_r: B256,
    /// Binding commitment: H(DOMAIN_BIND_META, pk_meta.x, salt)
    pub h_meta: B256,
    /// Binding commitment: H(DOMAIN_BIND_ENC, encrypted_salt)
    pub h_enc: B256,
}

/// Full witness for the unified transfer circuit (public + private inputs).
///
/// Used by the `Prover` to generate a ZK proof.
#[derive(Debug, Clone)]
pub struct TransferWitness {
    // ── Public inputs (9) ──
    pub nullifier: B256,
    pub root: B256,
    pub new_commitment: B256,
    pub timeout: B256,
    pub pk_stealth: B256,
    pub h_swap: B256,
    pub h_r: B256,
    pub h_meta: B256,
    pub h_enc: B256,

    // ── Private: input note ──
    pub sk_lo: B256,
    pub sk_hi: B256,
    pub in_chain_id: B256,
    pub in_value: u64,
    pub in_asset_id: B256,
    pub in_owner: B256,
    pub in_fallback_owner: B256,
    pub in_timeout: B256,
    pub in_salt: B256,
    pub proof_length: u32,
    pub path_elements: Vec<B256>,
    pub path_indices: Vec<u8>,

    // ── Private: output note ──
    pub out_chain_id: B256,
    pub out_value: u64,
    pub out_asset_id: B256,
    pub out_owner: B256,
    pub out_fallback_owner: B256,
    pub out_timeout: B256,
    pub out_salt: B256,

    // ── Private: lock-mode extras (zeroed in spend mode) ──
    pub swap_id: B256,
    pub r_lo: B256,
    pub r_hi: B256,
    pub pk_meta_x: B256,
    pub pk_meta_y: B256,
    pub encrypted_salt: B256,
}

/// Minimal transaction receipt for PoC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxReceipt {
    pub tx_hash: B256,
    pub success: bool,
}

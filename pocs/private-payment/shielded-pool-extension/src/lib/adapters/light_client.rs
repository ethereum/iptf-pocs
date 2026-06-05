//! Two-level MPT verification of a contract storage slot (the SPEC's `verify_mpt`)
//! plus a [`RootVerifier`] over a trusted state root.
//!
//! `verify_account_storage` checks an `eth_getProof` response against a state
//! root: level 1 proves the account leaf under the state root (binding the
//! account's `storage_hash`); level 2 proves the requested slot under that
//! `storage_hash`. In production the state root comes from a Helios finalized
//! header (consensus-verified); [`TrustedRootVerifier`] instead trusts a supplied
//! root (e.g. an anvil block's `stateRoot`), since Helios needs a beacon chain
//! anvil lacks. The verification is identical regardless of the root's provenance.

use alloy::{
    primitives::{
        keccak256,
        B256,
    },
    rpc::types::EIP1186AccountProofResponse,
};
use alloy_trie::{
    proof::verify_proof,
    Nibbles,
    TrieAccount,
};

use crate::ports::root_verifier::{
    RootVerifier,
    RootVerifierError,
};

/// Verify `proof` (an `eth_getProof` result for one slot) against `state_root`
/// and return the proven storage value.
///
/// Level 1 — the account leaf `rlp(nonce, balance, storage_hash, code_hash)` is
/// proven at `keccak256(address)` under `state_root`. Level 2 — the slot value is
/// proven at `keccak256(slot)` under the account's `storage_hash`. A zero value is
/// proven by *exclusion* (the slot is absent from the storage trie).
pub fn verify_account_storage(
    state_root: B256,
    proof: &EIP1186AccountProofResponse,
) -> Result<B256, RootVerifierError> {
    let account = TrieAccount {
        nonce: proof.nonce,
        balance: proof.balance,
        storage_root: proof.storage_hash,
        code_hash: proof.code_hash,
    };
    verify_proof(
        state_root,
        Nibbles::unpack(keccak256(proof.address.as_slice())),
        Some(alloy_rlp::encode(&account)),
        &proof.account_proof,
    )
    .map_err(|e| RootVerifierError::Account(e.to_string()))?;

    let entry = proof.storage_proof.first().ok_or(RootVerifierError::MissingSlot)?;
    // Ethereum RLP-encodes slot values with leading zeros trimmed; a zero slot is
    // absent from the trie, so it's proven by exclusion (`expected = None`).
    let expected = (!entry.value.is_zero()).then(|| alloy_rlp::encode(&entry.value));
    verify_proof(
        proof.storage_hash,
        Nibbles::unpack(keccak256(entry.key.as_b256().as_slice())),
        expected,
        &entry.proof,
    )
    .map_err(|e| RootVerifierError::Storage(e.to_string()))?;

    Ok(B256::from(entry.value))
}

/// [`RootVerifier`] over a state root the caller already trusts. PoC/dev use:
/// pass an anvil block's `stateRoot`. Production: a `HeliosRootVerifier` would
/// hold the light client's consensus-verified finalized `state_root` and call the
/// same [`verify_account_storage`] — not built here, since Helios requires a
/// beacon chain that anvil does not provide.
pub struct TrustedRootVerifier {
    state_root: B256,
}

impl TrustedRootVerifier {
    pub fn new(state_root: B256) -> Self {
        Self { state_root }
    }
}

impl RootVerifier for TrustedRootVerifier {
    fn verify_storage(&self, proof: &EIP1186AccountProofResponse) -> Result<B256, RootVerifierError> {
        verify_account_storage(self.state_root, proof)
    }
}

//! Root-authenticity port: verify a contract storage slot against a
//! consensus-anchored state root, replacing the trusted-RPC root reads.
//!
//! The wallet reconstructs `commitment_root` / `frozenNullifierRoots[e]` against
//! roots it trusts; this port is what makes those roots trustworthy. The
//! production implementation is a Helios light client (its finalized header's
//! `state_root` is consensus-verified); the PoC ships a `TrustedRootVerifier` that
//! takes a supplied state root (an anvil block's), since Helios needs a beacon
//! chain that anvil lacks. Either way the on-chain verification (the two-level MPT
//! proof) is identical — see `adapters::light_client`.

use alloy::rpc::types::EIP1186AccountProofResponse;

/// Errors from storage-proof verification.
#[derive(Debug, thiserror::Error)]
pub enum RootVerifierError {
    #[error("account proof invalid: {0}")]
    Account(String),
    #[error("storage proof invalid: {0}")]
    Storage(String),
    #[error("proof carries no storage entry for the requested slot")]
    MissingSlot,
}

/// Verifies an `eth_getProof` response against a state root the implementation
/// trusts (consensus-verified in production), returning the proven slot value.
pub trait RootVerifier {
    /// Verify `proof` (an `eth_getProof` result for one slot) and return the
    /// verified storage value.
    fn verify_storage(&self, proof: &EIP1186AccountProofResponse) -> Result<alloy::primitives::B256, RootVerifierError>;
}

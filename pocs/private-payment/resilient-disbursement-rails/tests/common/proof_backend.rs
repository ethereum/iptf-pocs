//! Test-side `ProofBackend` selector. Picks `BBProver` (real proofs) or
//! `MockProofBackend` (empty bytes) based on `RDR_USE_MOCK_PROOFS=1`.
//!
//! The on-chain verifier choice is controlled by the same env var via
//! `AnvilHarness::start(use_mock)`, so the backend in this module and the
//! deployed verifier always agree.

use std::path::PathBuf;

use resilient_disbursement_rails::{
    adapters::{
        bb_prover::BBProver,
        mock_proof::MockProofBackend,
    },
    error::ProofError,
    ports::proof::ProofBackend,
    types::{
        ClaimWitness,
        PoolWithdrawWitness,
    },
};

/// Returns `true` when the `RDR_USE_MOCK_PROOFS=1` env var is set. Tests
/// that strictly require real proofs (cross-card-spend, wrong-recipient)
/// gate on this and skip in mock mode.
pub fn is_mock_mode() -> bool {
    matches!(
        std::env::var("RDR_USE_MOCK_PROOFS").as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE")
    )
}

/// Enum dispatch over the two ProofBackend implementations. Avoids
/// monomorphizing the Relay generics across every test.
pub enum TestBackend {
    Mock(MockProofBackend),
    Real(BBProver),
}

impl TestBackend {
    pub fn from_env() -> Self {
        if is_mock_mode() {
            Self::Mock(MockProofBackend)
        } else {
            let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            Self::Real(BBProver::new(project_root))
        }
    }
}

impl ProofBackend for TestBackend {
    fn generate_claim_proof(
        &self,
        witness: &ClaimWitness,
    ) -> Result<Vec<u8>, ProofError> {
        match self {
            Self::Mock(b) => b.generate_claim_proof(witness),
            Self::Real(b) => b.generate_claim_proof(witness),
        }
    }
    fn generate_pool_withdraw_proof(
        &self,
        witness: &PoolWithdrawWitness,
    ) -> Result<Vec<u8>, ProofError> {
        match self {
            Self::Mock(b) => b.generate_pool_withdraw_proof(witness),
            Self::Real(b) => b.generate_pool_withdraw_proof(witness),
        }
    }
}

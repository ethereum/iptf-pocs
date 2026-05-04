//! Proof-backend port. Two methods only - no batch withdraw.

use crate::{
    error::ProofError,
    types::{
        ClaimWitness,
        PoolWithdrawWitness,
    },
};

/// Generates ZK proofs for the claim and pool-withdraw circuits.
///
/// Implementations: `BBProver` (real, shells to `nargo` + `bb`) and
/// `MockProofBackend` (returns an empty/sentinel byte vector). The
/// `Send + Sync` bound mirrors the reference identity PoC and lets relays
/// hold the prover behind shared references on async runtimes.
pub trait ProofBackend: Send + Sync {
    fn generate_claim_proof(&self, witness: &ClaimWitness)
    -> Result<Vec<u8>, ProofError>;
    fn generate_pool_withdraw_proof(
        &self,
        witness: &PoolWithdrawWitness,
    ) -> Result<Vec<u8>, ProofError>;
}

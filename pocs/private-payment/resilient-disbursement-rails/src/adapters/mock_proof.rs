//! `MockProofBackend`: returns an empty byte vector for both proof methods.
//! Use during development and on-chain mock-verifier tests.

use crate::{
    error::ProofError,
    ports::proof::ProofBackend,
    types::{
        ClaimWitness,
        PoolWithdrawWitness,
    },
};

#[derive(Debug, Clone, Copy, Default)]
pub struct MockProofBackend;

impl ProofBackend for MockProofBackend {
    fn generate_claim_proof(
        &self,
        _witness: &ClaimWitness,
    ) -> Result<Vec<u8>, ProofError> {
        Ok(vec![])
    }
    fn generate_pool_withdraw_proof(
        &self,
        _witness: &PoolWithdrawWitness,
    ) -> Result<Vec<u8>, ProofError> {
        Ok(vec![])
    }
}

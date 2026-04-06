use ark_bn254::{
    Fr,
    G1Affine,
};

use crate::types::{
    DleqProof,
    PartialEvaluation,
};

/// Request sent to MPC nodes for blinded OPRF evaluation.
pub struct BlindEvaluateRequest {
    pub blinded_request: G1Affine,
    pub identity_commitment: Fr,
    pub g_id: G1Affine,
    pub link_proof: Vec<u8>,
}

pub trait MpcNetwork: Send + Sync {
    fn evaluate(&self, request: &BlindEvaluateRequest) -> Vec<PartialEvaluation>;
    fn public_key(&self) -> G1Affine;
    fn threshold(&self) -> usize;
    fn node_public_key(&self, node_index: usize) -> G1Affine;
    /// Produce a DLEQ proof for the aggregate MPC key: log_G(PK) == log_{G_id}(raw_nullifier).
    /// In a real system, MPC nodes collaboratively produce this. The mock computes it directly.
    fn aggregate_dleq_proof(&self, g_id: G1Affine, raw_nullifier: G1Affine) -> DleqProof;
}

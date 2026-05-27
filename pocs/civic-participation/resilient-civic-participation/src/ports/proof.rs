//! Proof-backend port for signer, batch, and resolution SNARKs.

use crate::{
    error::ProofError,
    ports::imt::ImtInsertWitness,
    types::{
        BatchPublicInputs,
        ResolutionPrivateInputs,
        ResolutionPublicInputs,
        SignerPrivateInputs,
        SignerPublicInputs,
        SignerSubmission,
    },
};

/// Per-position batch witness: signer SNARK plus relayer-extracted tuple.
#[derive(Debug, Clone)]
pub struct BatchPositionWitness {
    pub submission: SignerSubmission,
    /// Cached `Fr` form of the public inputs, populated by the relayer.
    pub public_inputs: SignerPublicInputs,
    /// Running-root IMT insertion witness; required by the BB backend.
    pub running_insert: Option<ImtInsertWitness>,
    /// Identity-tag-set IMT insertion witness.
    pub idtag_insert: Option<ImtInsertWitness>,
}

pub trait ProofBackend: Send + Sync {
    fn generate_signer_proof(
        &self,
        public: &SignerPublicInputs,
        private: &SignerPrivateInputs,
    ) -> Result<Vec<u8>, ProofError>;

    fn generate_batch_proof(
        &self,
        public: &BatchPublicInputs,
        positions: &[BatchPositionWitness],
    ) -> Result<Vec<u8>, ProofError>;

    fn generate_resolution_proof(
        &self,
        public: &ResolutionPublicInputs,
        private: &ResolutionPrivateInputs,
    ) -> Result<Vec<u8>, ProofError>;

    /// Registry-side verification (on-chain in production).
    fn verify_signer_proof(
        &self,
        proof: &[u8],
        public: &SignerPublicInputs,
    ) -> Result<(), ProofError>;

    fn verify_batch_proof(
        &self,
        proof: &[u8],
        public: &BatchPublicInputs,
    ) -> Result<(), ProofError>;

    fn verify_resolution_proof(
        &self,
        proof: &[u8],
        public: &ResolutionPublicInputs,
    ) -> Result<(), ProofError>;
}

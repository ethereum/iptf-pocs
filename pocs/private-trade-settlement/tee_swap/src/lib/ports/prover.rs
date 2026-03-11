use std::future::Future;

use super::{TransferProof, TransferWitness};

/// Port for ZK proof generation.
///
/// Implementations:
/// - `BBProver` (shells out to `nargo execute` + `bb prove`)
/// - Mock prover for testing
pub trait Prover: Send + Sync {
    /// Generate a proof for the unified transfer circuit.
    ///
    /// The witness contains all public + private inputs. The returned
    /// `TransferProof` bundles the serialized proof bytes (Barretenberg format)
    /// with the public inputs extracted from the witness.
    fn prove_transfer(
        &self,
        witness: &TransferWitness,
    ) -> impl Future<Output = Result<TransferProof, ProverError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("proof generation failed: {0}")]
    ProofFailed(String),

    #[error("witness generation failed: {0}")]
    WitnessError(String),

    #[error("witness serialization error: {0}")]
    WitnessSerialization(String),

    #[error("prover binary not found: {0}")]
    BinaryNotFound(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("invalid witness: {0}")]
    InvalidWitness(String),
}

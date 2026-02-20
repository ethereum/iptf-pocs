use std::future::Future;

use super::TransferWitness;

/// Port for ZK proof generation.
///
/// Implementations:
/// - `BbProver` (shells out to `nargo execute` + `bb prove`, future)
/// - Mock prover for testing
pub trait Prover: Send + Sync {
    /// Generate a proof for the unified transfer circuit.
    ///
    /// The witness contains all public + private inputs. The returned bytes
    /// are the serialized proof in Barretenberg format, ready for on-chain
    /// verification via `TransferVerifier.sol`.
    fn prove_transfer(
        &self,
        witness: &TransferWitness,
    ) -> impl Future<Output = Result<Vec<u8>, ProverError>> + Send;
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("proof generation failed: {0}")]
    ProofFailed(String),

    #[error("witness serialization error: {0}")]
    WitnessSerialization(String),

    #[error("prover binary not found: {0}")]
    BinaryNotFound(String),
}

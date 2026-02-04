use thiserror::Error;

use crate::domain::{
    proof::{
        DepositProof,
        TransferProof,
        WithdrawProof,
    },
    witness::{
        DepositWitness,
        TransferWitness,
        WithdrawWitness,
    },
};

/// Errors that can occur during proof generation.
#[derive(Debug, Error)]
pub enum ProverError {
    #[error("Circuit compilation failed: {0}")]
    CompilationError(String),

    #[error("Witness generation failed: {0}")]
    WitnessError(String),

    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    #[error("Proof verification failed: {0}")]
    VerificationError(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid witness: {0}")]
    InvalidWitness(String),
}

/// Trait for generating ZK proofs for shielded pool operations.
///
/// Implementations may shell out to external provers (e.g., nargo/bb)
/// or use in-process proving libraries.
pub trait Prover: Send + Sync {
    /// Generate a proof for a deposit operation.
    ///
    /// The deposit circuit proves:
    /// - The commitment is correctly formed from the note fields
    /// - The depositor has a valid attestation in the attestation tree
    fn prove_deposit(
        &self,
        witness: &DepositWitness,
    ) -> impl core::future::Future<Output = Result<DepositProof, ProverError>>;

    /// Generate a proof for a transfer operation.
    ///
    /// The transfer circuit proves:
    /// - Input commitments exist in the commitment tree
    /// - Nullifiers are correctly derived from inputs and spending key
    /// - Output commitments are well-formed
    /// - Value is preserved (input sum == output sum)
    /// - All notes use the same token
    fn prove_transfer(
        &self,
        witness: &TransferWitness,
    ) -> impl core::future::Future<Output = Result<TransferProof, ProverError>>;

    /// Generate a proof for a withdraw operation.
    ///
    /// The withdraw circuit proves:
    /// - The commitment exists in the commitment tree
    /// - The nullifier is correctly derived
    /// - The claimed amount and token match the note
    fn prove_withdraw(
        &self,
        witness: &WithdrawWitness,
    ) -> impl core::future::Future<Output = Result<WithdrawProof, ProverError>>;
}

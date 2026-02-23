use alloy::primitives::{Address, B256};
use std::future::Future;

/// Attestation report from the TEE runtime.
///
/// In production, this would be a TDX/SEV-SNP quote. For the PoC, it's a mock
/// report that is embedded in the RA-TLS certificate's custom X.509 extension.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AttestationReport {
    /// TEE type identifier ("mock", "tdx", "sev-snp")
    pub tee_type: String,
    /// SHA-256 hash of the TLS public key (binds attestation to TLS session)
    pub pubkey_hash: B256,
    /// Timestamp of report generation
    pub timestamp: u64,
}

/// Port for TEE runtime operations (attestation lifecycle).
///
/// Implementations:
/// - `MockTeeRuntime` (for PoC/testing)
/// - Real TDX/SEV-SNP via VirTEE crates (production)
pub trait TeeRuntime: Send + Sync {
    /// Generate an attestation report binding the given TLS public key hash.
    fn generate_attestation(
        &self,
        pubkey_hash: B256,
    ) -> impl Future<Output = Result<AttestationReport, TeeError>> + Send;

    /// Verify an attestation report (for client-side RA-TLS verification).
    fn verify_attestation(
        &self,
        report: &AttestationReport,
    ) -> impl Future<Output = Result<bool, TeeError>> + Send;

    /// Get the TEE's signing key address (for on-chain `onlyTEE` checks).
    fn signer_address(&self) -> Address;
}

#[derive(Debug, thiserror::Error)]
pub enum TeeError {
    #[error("attestation generation failed: {0}")]
    AttestationFailed(String),

    #[error("attestation verification failed: {0}")]
    VerificationFailed(String),

    #[error("TEE runtime not available")]
    Unavailable,
}

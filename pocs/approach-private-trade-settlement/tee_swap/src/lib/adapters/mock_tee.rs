use alloy_primitives::{Address, B256};

use crate::ports::tee::{AttestationReport, TeeError, TeeRuntime};

/// Mock TEE runtime for PoC and testing.
///
/// Generates mock attestation reports with `tee_type = "mock"`.
/// In production, this would be replaced by a real TDX/SEV-SNP runtime
/// using VirTEE crates.
pub struct MockTeeRuntime {
    /// Mock TEE signer address (EOA for on-chain `onlyTEE` checks)
    signer: Address,
}

impl MockTeeRuntime {
    pub fn new(signer: Address) -> Self {
        Self { signer }
    }
}

impl TeeRuntime for MockTeeRuntime {
    async fn generate_attestation(
        &self,
        pubkey_hash: B256,
    ) -> Result<AttestationReport, TeeError> {
        Ok(AttestationReport {
            tee_type: "mock".to_string(),
            pubkey_hash,
            timestamp: 0, // Mock: no real timestamp
        })
    }

    async fn verify_attestation(
        &self,
        report: &AttestationReport,
    ) -> Result<bool, TeeError> {
        // Mock verification: accept any report with tee_type == "mock"
        Ok(report.tee_type == "mock")
    }

    fn signer_address(&self) -> Address {
        self.signer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_attestation_generation() {
        let tee = MockTeeRuntime::new(Address::repeat_byte(0x42));
        let pubkey_hash = B256::repeat_byte(0xAA);

        let report = tee.generate_attestation(pubkey_hash).await.unwrap();

        assert_eq!(report.tee_type, "mock");
        assert_eq!(report.pubkey_hash, pubkey_hash);
    }

    #[tokio::test]
    async fn test_mock_attestation_verification() {
        let tee = MockTeeRuntime::new(Address::repeat_byte(0x42));

        let mock_report = AttestationReport {
            tee_type: "mock".to_string(),
            pubkey_hash: B256::repeat_byte(0xAA),
            timestamp: 0,
        };

        assert!(tee.verify_attestation(&mock_report).await.unwrap());
    }

    #[tokio::test]
    async fn test_mock_rejects_non_mock_report() {
        let tee = MockTeeRuntime::new(Address::repeat_byte(0x42));

        let real_report = AttestationReport {
            tee_type: "tdx".to_string(),
            pubkey_hash: B256::repeat_byte(0xAA),
            timestamp: 0,
        };

        assert!(!tee.verify_attestation(&real_report).await.unwrap());
    }

    #[tokio::test]
    async fn test_signer_address() {
        let signer = Address::repeat_byte(0x42);
        let tee = MockTeeRuntime::new(signer);
        assert_eq!(tee.signer_address(), signer);
    }
}

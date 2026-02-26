//! AWS Nitro Enclave TEE runtime.
//!
//! Implements `TeeRuntime` using the Nitro Security Module (NSM) device `/dev/nsm`.
//! The NSM generates a CBOR COSE_Sign1 attestation document signed by the AWS Nitro
//! hypervisor, binding the TLS public key hash (passed as nonce) to the PCR measurements
//! of the running enclave image.
//!
//! Only compiled when the `nitro` feature is enabled.

use std::time::{SystemTime, UNIX_EPOCH};

use alloy::primitives::{Address, B256};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;

use crate::ports::tee::{AttestationReport, TeeError, TeeRuntime};

pub struct NitroTeeRuntime {
    signer: Address,
}

impl NitroTeeRuntime {
    /// Create a new Nitro TEE runtime with the given signer address.
    ///
    /// The signer must match the address passed to `TeeLock` at deployment time —
    /// it is derived from the TEE private key configured in `server.toml`.
    /// That key (and therefore this address) becomes part of the enclave image
    /// measured into PCR2 when the EIF is built.
    pub fn new(signer: Address) -> Self {
        Self { signer }
    }
}

impl TeeRuntime for NitroTeeRuntime {
    async fn generate_attestation(
        &self,
        pubkey_hash: B256,
    ) -> Result<AttestationReport, TeeError> {
        let nsm_fd = nsm_init();

        let request = Request::Attestation {
            nonce: Some(ByteBuf::from(pubkey_hash.as_slice())),
            user_data: None,
            public_key: None,
        };

        let response = nsm_process_request(nsm_fd, request);
        nsm_exit(nsm_fd);

        match response {
            Response::Attestation { document } => {
                let timestamp = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                Ok(AttestationReport {
                    tee_type: "nitro".to_string(),
                    pubkey_hash,
                    timestamp,
                    raw_document: Some(document.to_vec()),
                })
            }
            _ => Err(TeeError::AttestationFailed(
                "NSM returned unexpected response".to_string(),
            )),
        }
    }

    async fn verify_attestation(
        &self,
        report: &AttestationReport,
    ) -> Result<bool, TeeError> {
        if report.tee_type != "nitro" {
            return Ok(false);
        }
        // PoC: accept any non-empty raw_document.
        // Production: decode CBOR COSE_Sign1, verify signature against AWS root cert,
        // and check PCR0/PCR2 match expected values.
        Ok(report.raw_document.as_ref().map_or(false, |d| !d.is_empty()))
    }

    fn signer_address(&self) -> Address {
        self.signer
    }
}

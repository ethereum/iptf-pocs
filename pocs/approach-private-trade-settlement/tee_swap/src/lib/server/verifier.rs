use std::sync::Arc;

use alloy::primitives::B256;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

use crate::ports::tee::AttestationReport;

/// OID string for the RA-TLS attestation extension.
const ATTESTATION_OID_STR: &str = "1.3.6.1.4.1.99999.1";

/// Client-side RA-TLS certificate verifier.
///
/// During the TLS handshake, this verifier:
/// 1. Parses the server's X.509 certificate
/// 2. Extracts the attestation extension at OID 1.3.6.1.4.1.99999.1
/// 3. Deserializes the `AttestationReport` from JSON
/// 4. Verifies `report.pubkey_hash == SHA-256(cert_tls_public_key)`
/// 5. Accepts if `tee_type == "mock"` (when `allow_mock` is set)
#[derive(Debug)]
pub struct RaTlsVerifier {
    /// If true, accept mock attestation reports (tee_type == "mock").
    pub allow_mock: bool,
    /// Crypto provider for TLS signature verification.
    provider: Arc<CryptoProvider>,
}

impl RaTlsVerifier {
    pub fn new(allow_mock: bool) -> Self {
        Self {
            allow_mock,
            provider: Arc::new(
                rustls::crypto::ring::default_provider(),
            ),
        }
    }
}

impl ServerCertVerifier for RaTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // 1. Parse X.509 certificate
        let (_, cert) = X509Certificate::from_der(end_entity.as_ref()).map_err(|_| {
            Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;

        // 2. Find attestation extension
        let ext = cert
            .extensions()
            .iter()
            .find(|e| e.oid.to_id_string() == ATTESTATION_OID_STR)
            .ok_or_else(|| {
                Error::InvalidCertificate(rustls::CertificateError::Other(
                    rustls::OtherError(Arc::new(VerifierError::MissingExtension)),
                ))
            })?;

        // 3. Deserialize attestation report from extension value (JSON)
        let report: AttestationReport =
            serde_json::from_slice(ext.value).map_err(|e| {
                Error::InvalidCertificate(rustls::CertificateError::Other(
                    rustls::OtherError(Arc::new(VerifierError::InvalidReport(
                        e.to_string(),
                    ))),
                ))
            })?;

        // 4. Verify pubkey_hash matches the certificate's TLS public key
        let spki_raw = cert.public_key().raw;
        let pubkey_hash = Sha256::digest(spki_raw);
        let expected = B256::from_slice(&pubkey_hash);

        if report.pubkey_hash != expected {
            return Err(Error::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                    VerifierError::PubkeyHashMismatch {
                        expected,
                        got: report.pubkey_hash,
                    },
                ))),
            ));
        }

        // 5. Check TEE type
        if report.tee_type == "mock" && self.allow_mock {
            return Ok(ServerCertVerified::assertion());
        }

        // Future: verify real TDX/SEV-SNP quotes here
        Err(Error::InvalidCertificate(
            rustls::CertificateError::Other(rustls::OtherError(Arc::new(
                VerifierError::UnsupportedTeeType(report.tee_type),
            ))),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a `reqwest::Client` configured with the RA-TLS verifier.
///
/// The client will verify the server's TLS certificate by extracting and
/// validating the embedded attestation report during the TLS handshake.
pub fn build_ra_tls_client(allow_mock: bool) -> reqwest::Client {
    let verifier = Arc::new(RaTlsVerifier::new(allow_mock));
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("valid protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    reqwest::Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .expect("failed to build RA-TLS client")
}

#[derive(Debug, thiserror::Error)]
enum VerifierError {
    #[error("missing RA-TLS attestation extension (OID {ATTESTATION_OID_STR})")]
    MissingExtension,

    #[error("invalid attestation report: {0}")]
    InvalidReport(String),

    #[error("pubkey hash mismatch: expected {expected}, got {got}")]
    PubkeyHashMismatch { expected: B256, got: B256 },

    #[error("unsupported TEE type: {0}")]
    UnsupportedTeeType(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::mock_tee::MockTeeRuntime;
    use crate::server::cert::generate_ra_tls_cert;
    use alloy::primitives::Address;
    use rustls::pki_types::ServerName;

    async fn test_cert_der() -> Vec<u8> {
        let tee = MockTeeRuntime::new(Address::repeat_byte(0x42));
        let ra_cert = generate_ra_tls_cert(&tee).await.unwrap();
        ra_cert.cert_der
    }

    #[tokio::test]
    async fn test_verifier_accepts_valid_mock_cert() {
        let cert_der = test_cert_der().await;
        let verifier = RaTlsVerifier::new(true);

        let cert = CertificateDer::from(cert_der);
        let server_name = ServerName::try_from("tee-swap.local").unwrap();

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_verifier_rejects_when_mock_not_allowed() {
        let cert_der = test_cert_der().await;
        let verifier = RaTlsVerifier::new(false); // mock not allowed

        let cert = CertificateDer::from(cert_der);
        let server_name = ServerName::try_from("tee-swap.local").unwrap();

        let result = verifier.verify_server_cert(
            &cert,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_verifier_rejects_cert_without_extension() {
        // Generate a plain certificate without the attestation extension
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["plain.local".to_string()]).unwrap();
        let plain_cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(plain_cert.der().to_vec());

        let verifier = RaTlsVerifier::new(true);
        let server_name = ServerName::try_from("plain.local").unwrap();

        let result = verifier.verify_server_cert(
            &cert_der,
            &[],
            &server_name,
            &[],
            UnixTime::now(),
        );

        assert!(result.is_err());
    }
}

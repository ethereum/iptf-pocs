//! Anonymous transport port: relay -> ethereum seam.
//!
//! Mirrors SPEC IAnonymousTransport: `submit(signedTransaction) -> txHash`.
//! Required property: no single entity simultaneously observes submitter
//! network origin and plaintext transaction. Production deployments route
//! through Tor / Nym; this PoC ships an in-process alloy passthrough
//! adapter (`DirectAnonymousTransport`) so the boundary is visible without
//! adding an actual anonymity network.
//!
//! `signed_tx` is an EIP-2718-encoded transaction envelope. Signing happens
//! upstream (in production, on a rotated relay EOA held offline); the
//! transport sees only opaque bytes.

use std::future::Future;

use thiserror::Error;

use crate::types::Bytes32;

#[derive(Debug, Error)]
pub enum AnonymousTransportError {
    #[error("transport submit failed: {0}")]
    Submit(String),
}

pub trait AnonymousTransport: Send + Sync {
    /// Submit a pre-signed EIP-2718 transaction. Returns the 32-byte tx
    /// hash assigned by the chain.
    fn submit(
        &self,
        signed_tx: &[u8],
    ) -> impl Future<Output = Result<Bytes32, AnonymousTransportError>> + Send;
}

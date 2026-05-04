//! In-process direct anonymous transport adapter.
//!
//! Wraps an alloy `Provider` and forwards raw EIP-2718 bytes via
//! `send_raw_transaction`. Production deployments would route through
//! Tor / Nym; this adapter exists to make the seam visible without adding
//! an actual anonymity network.

use alloy::providers::Provider;

use crate::{
    ports::anon_transport::{
        AnonymousTransport,
        AnonymousTransportError,
    },
    types::Bytes32,
};

pub struct DirectAnonymousTransport<P> {
    provider: P,
}

impl<P> DirectAnonymousTransport<P> {
    pub fn new(provider: P) -> Self {
        Self { provider }
    }
}

impl<P: Provider + Send + Sync> AnonymousTransport for DirectAnonymousTransport<P> {
    async fn submit(&self, signed_tx: &[u8]) -> Result<Bytes32, AnonymousTransportError> {
        let pending = self
            .provider
            .send_raw_transaction(signed_tx)
            .await
            .map_err(|e| AnonymousTransportError::Submit(e.to_string()))?;
        Ok(pending.tx_hash().0)
    }
}

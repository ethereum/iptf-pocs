//! Submission port: companion -> relay seam.
//!
//! Mirrors SPEC ISubmission: `submitVoucher(encryptedVoucher, relayIdentifier)
//! -> deliveryReceipt`. Production deployments back this with a mesh /
//! store-and-forward network; this PoC ships an in-process queue adapter
//! (`DirectSubmission`) so the boundary is visible at every call site.
//!
//! Required SPEC properties (production):
//! - End-to-end IND-CCA2 AEAD with ephemeral sender keying.
//! - Source-fingerprinting resistance via at least two orthogonal mitigations
//!   across physical and network layers.
//! - Eventual delivery.
//! - Relay key rotation at least every 24 hours with secure erase.
//!
//! The trait is push-only: the recipient hands an envelope to the channel
//! and receives a `DeliveryReceipt`. How the relay receives the envelope is
//! adapter-specific (mesh subscription, polling, etc.) and not part of the
//! port surface.

use thiserror::Error;

use crate::types::{
    Bytes32,
    EncryptedVoucher,
};

/// Returned to the recipient after the channel accepts a voucher for
/// eventual delivery. `message_id` is a content hash so the recipient can
/// later detect duplicate delivery and reconcile fan-out across multiple
/// relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryReceipt {
    pub message_id: Bytes32,
    pub accepted_at_unix: u64,
}

#[derive(Debug, Error)]
pub enum SubmissionError {
    #[error("relay id is not in the channel's roster")]
    UnknownRelay,
    #[error("submission channel rejected the envelope: {0}")]
    Rejected(String),
}

/// Companion-side seam. The `Submission` impl owns the channel's state;
/// recipients only see the receipt.
pub trait Submission: Send + Sync {
    fn submit_voucher(
        &self,
        envelope: EncryptedVoucher,
        relay_id: &Bytes32,
    ) -> Result<DeliveryReceipt, SubmissionError>;
}

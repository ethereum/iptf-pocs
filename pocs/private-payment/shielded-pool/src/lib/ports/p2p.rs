use thiserror::Error;

use crate::domain::{
    commitment::Commitment,
    encrypted::{
        EncryptedNote,
        P2pMessage,
    },
    keys::ViewingPubkey,
};

/// Errors that can occur during P2P communication.
#[derive(Debug, Error)]
pub enum P2pError {
    #[error("Recipient not found: {0}")]
    RecipientNotFound(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Send failed: {0}")]
    SendFailed(String),

    #[error("Receive failed: {0}")]
    ReceiveFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),
}

/// Trait for peer-to-peer communication of encrypted notes.
///
/// This abstracts the transport layer for delivering encrypted notes
/// to recipients. In the PoC, this is implemented with in-memory channels.
/// Production implementations might use libp2p, message queues, etc.
pub trait P2p: Send + Sync {
    /// Send an encrypted note to a recipient.
    ///
    /// # Arguments
    /// * `recipient_viewing_pubkey` - The recipient's viewing public key (for routing)
    /// * `encrypted_note` - The encrypted note
    /// * `commitment` - The commitment (for identifying the note on-chain)
    fn send_note(
        &self,
        recipient_viewing_pubkey: &ViewingPubkey,
        encrypted_note: EncryptedNote,
        commitment: Commitment,
    ) -> impl core::future::Future<Output = Result<(), P2pError>>;

    /// Receive a note message (non-blocking).
    ///
    /// # Returns
    /// * `Ok(Some(message))` - A message was available
    /// * `Ok(None)` - No message currently available
    /// * `Err(_)` - An error occurred
    fn receive_note(
        &self,
    ) -> impl core::future::Future<Output = Result<Option<P2pMessage>, P2pError>>;

    /// Receive a note message (blocking).
    ///
    /// Waits until a message is available.
    ///
    /// # Returns
    /// * `Ok(message)` - The received message
    /// * `Err(_)` - An error occurred (e.g., channel closed)
    fn receive_note_blocking(
        &self,
    ) -> impl core::future::Future<Output = Result<P2pMessage, P2pError>>;
}

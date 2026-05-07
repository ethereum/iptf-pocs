use thiserror::Error;

use crate::{
    crypto::{
        aead::AeadError,
        multisig::MultisigError,
    },
    error::CardError,
};

#[derive(Debug, Error)]
pub enum CompanionError {
    #[error("invalid funder signature on round header: {0}")]
    BadFunderSig(MultisigError),
    #[error("invalid funder signature on relay roster: {0}")]
    BadRosterSig(MultisigError),
    #[error("relay roster is stale (older than 48h)")]
    StaleRoster,
    #[error("relay roster is dated in the future relative to the local clock")]
    FutureRoster,
    #[error("smartcard failure: {0}")]
    CardFailure(#[from] CardError),
    #[error("AEAD failure: {0}")]
    AeadFailure(#[from] AeadError),
    #[error("no relays available in roster")]
    NoRelaysAvailable,
    #[error("voucher serialization failure: {0}")]
    Serialization(String),
}

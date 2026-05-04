use thiserror::Error;

#[derive(Debug, Error)]
pub enum FunderError {
    #[error("registry mismatch: cohort root or size differs from header")]
    RegistryMismatch,
    #[error("invalid multisig threshold configuration: {0}")]
    ThresholdConfig(String),
    #[error("multisig propose failed: {0}")]
    MultisigPropose(String),
    #[error("multisig confirm failed: {0}")]
    MultisigConfirm(String),
    #[error("multisig execute failed: {0}")]
    MultisigExecute(String),
}

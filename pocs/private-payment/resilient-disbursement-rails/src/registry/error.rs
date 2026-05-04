use thiserror::Error;

#[derive(Debug, Error)]
pub enum RegistryError {
    #[error("duplicate cardId")]
    DuplicateCard,
    #[error("duplicate M (cards must have unique master pubkeys)")]
    DuplicateM,
    #[error("unknown cardId")]
    UnknownCard,
}

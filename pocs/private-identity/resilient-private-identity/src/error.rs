#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("proof generation failed: {0}")]
    Generation(String),
    #[error("proof verification failed: {0}")]
    Verification(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("proof error: {0}")]
    Proof(#[from] ProofError),
    #[error("MPC error: {0}")]
    Mpc(String),
    #[error("merkle error: {0}")]
    Merkle(String),
}

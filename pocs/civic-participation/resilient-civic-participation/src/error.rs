//! Shared error types; per-actor errors wrap these.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("proof generation failed: {0}")]
    Generation(String),
    #[error("witness serialization failed: {0}")]
    WitnessSerialization(String),
    #[error("proof verification failed: {0}")]
    Verification(String),
}

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("leaf index {0} out of range (size {1})")]
    OutOfRange(usize, usize),
    #[error("empty tree has no proof")]
    EmptyTree,
    #[error("merkle proof construction failed: {0}")]
    ProofFailure(String),
}

#[derive(Debug, Error)]
pub enum ImtError {
    #[error("duplicate insertion: value already present in IMT")]
    DuplicateInsertion,
    #[error("tree depth exhausted (max {0})")]
    CapacityExhausted(usize),
    #[error("low-leaf invariants violated: {0}")]
    LowLeafInvariant(String),
    #[error("merkle: {0}")]
    Merkle(#[from] MerkleError),
}

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("record count {0} exceeds blob capacity {1}")]
    Capacity(usize, usize),
    #[error("malformed blob payload: {0}")]
    Malformed(String),
    #[error("KZG opening verification failed: {0}")]
    InvalidOpening(String),
    #[error("blob not found for batch_versioned_hash")]
    NotFound,
}

#[derive(Debug, Error)]
pub enum PredicateError {
    #[error("predicate exceeds serialized length cap")]
    TooLarge,
    #[error("predicate has {0} tuples; bound is 1..=20")]
    TupleCountOutOfRange(usize),
    #[error("predicate has {0} ops; bound is 1..=20")]
    OpCountOutOfRange(usize),
    #[error("unknown type tag {0:#x}")]
    BadTypeTag(u8),
    #[error("unknown comparator {0:#x}")]
    BadComparator(u8),
    #[error("unknown opcode {0:#x}")]
    BadOpcode(u8),
    #[error("PUSH_TUPLE operand index {0} out of range (tuple_count = {1})")]
    OperandOutOfRange(u8, u8),
    #[error("malformed serialized predicate: {0}")]
    Malformed(String),
    #[error("evaluation stack underflow at op index {0}")]
    StackUnderflow(usize),
    #[error("evaluation produced non-singleton stack (size {0})")]
    NonSingletonResult(usize),
    #[error(
        "missing class-binding clause `attr[class_index] == class_tag` at top-level outside OR"
    )]
    MissingClassBinding,
    #[error("INT64 operand exceeds 64-bit range")]
    Int64OperandOutOfRange,
    #[error("type/comparator mismatch: {0}")]
    TypeMismatch(String),
}

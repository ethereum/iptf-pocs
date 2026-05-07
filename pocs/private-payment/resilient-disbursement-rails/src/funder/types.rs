//! Funder-side types.
//!
//! The legacy `MultisigSignature` struct used a per-index share format that
//! did not match the on-chain `Multisig.sol` k-of-n shape. It has been
//! replaced by `crate::crypto::multisig::MultiSignature`. This module
//! re-exports it so callers in `funder::*` keep a single import path.

pub use crate::crypto::multisig::MultiSignature;

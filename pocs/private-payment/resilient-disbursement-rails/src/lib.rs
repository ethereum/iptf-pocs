//! Resilient Disbursement Rails: Rust crate.
//!
//! Hexagonal layout with per-actor types and per-actor errors plus shared
//! `ProofError` / `PoolError` / `MerkleError` / `CardError`. Mock vs real
//! adapters are wired at construction time. No Cargo features.

pub mod adapters;
pub mod clock;
pub mod companion;
pub mod crypto;
pub mod error;
pub mod funder;
pub mod ports;
pub mod poseidon;
pub mod registry;
pub mod relay;
pub mod smartcard;
pub mod types;

// Domain-tag string constants matching circuits/lib/src/domain.nr.
//
// The Noir circuits use small integer literals (1, 2, 3) for the algebraic
// (Poseidon) domain tags as a PoC simplification. The string constants below
// are still used for SHA-256-based domains (voucher, header, stealth) and as
// the SPEC-canonical names that show up in README divergences.
pub const DOMAIN_LEAF: &[u8] = b"RDR/leaf/v1";
pub const DOMAIN_COMMITMENT: &[u8] = b"RDR/commitment/v1";
pub const DOMAIN_NULLIFIER: &[u8] = b"RDR/null/v1";
pub const DOMAIN_VOUCHER: &[u8] = b"RDR/voucher/v1";
pub const DOMAIN_HEADER: &[u8] = b"RDR/header/v1";
pub const DOMAIN_STEALTH: &[u8] = b"RDR/stealth/v1";
pub const DOMAIN_ROSTER: &[u8] = b"RDR/roster/v1";

// Algebraic domain-tag values used inside Poseidon hashes. Match
// `circuits/lib/src/domain.nr` byte-for-byte.
pub const LEAF_DOMAIN_TAG: u64 = 1;
pub const COMMITMENT_DOMAIN_TAG: u64 = 2;
pub const NULL_DOMAIN_TAG: u64 = 3;

// Cohort tree depth (matches circuits/claim main and SPEC Cohort Tree).
pub const COHORT_DEPTH: usize = 20;

// Pool sub-tree max depth (matches circuits/withdraw main and SPEC).
pub const POOL_DEPTH: usize = 32;

// Voucher signed-message preimage byte length (matches SPEC Voucher).
pub const VOUCHER_PREIMAGE_LEN: usize = 308;

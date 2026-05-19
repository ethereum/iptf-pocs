pub mod domain;
pub mod hasher;
pub mod sponge;
pub mod merkle;
pub mod imt;
pub mod fsrt;
pub mod predicate;
pub mod blob;
pub mod cmp;

// Capacity constants matching `src/lib.rs`. Single source of truth across
// Rust + Noir; if these change here, the Rust crate's analogues must too.
pub global FSRT_DEPTH: u32 = 24;
pub global IMT_DEPTH: u32 = 24;
pub global ATTR_COUNT: u32 = 4;
// SPEC value is 100 but the PoC's recursive-verification cap shrinks
// this to 6 to keep the batch circuit compile time tractable. Listed
// in SPEC.md section Limitations. Matches Rust `BATCH_SIZE_MAX`.
pub global BATCH_SIZE_MAX: u32 = 6;
pub global PREDICATE_TUPLE_MAX: u32 = 20;
pub global PREDICATE_OP_MAX: u32 = 20;
pub global PREDICATE_SCALAR_COUNT: u32 = 34;
pub global RECORDS_PER_BLOB: u32 = 1000;
pub global RI_DEPTH: u32 = 32;

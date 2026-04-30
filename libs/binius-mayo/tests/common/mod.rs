//! Test-only support modules: NIST KAT parser and pure-Rust MAYO-2 oracle.
//!
//! This module is included via `mod common;` from each integration test
//! crate; Cargo treats `tests/common/mod.rs` as a private module of the
//! test binary that includes it (it is not compiled as a separate test).

#![deny(unsafe_code)]
#![allow(dead_code)]

pub mod kat;
pub mod oracle;

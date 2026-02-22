//! RISC Zero guest method binaries
//!
//! This crate provides the compiled guest ELF binaries and their image IDs.
//! The binaries are embedded at compile time by the build.rs script.

include!(concat!(env!("OUT_DIR"), "/methods.rs"));

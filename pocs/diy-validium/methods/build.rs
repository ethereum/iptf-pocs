//! Build script for RISC Zero guest programs
//!
//! This compiles the guest programs into ELF binaries that can be executed
//! in the RISC Zero zkVM. The resulting binaries and their image IDs are
//! made available to the host program via the `methods` crate.

fn main() {
    risc0_build::embed_methods();
}

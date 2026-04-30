//! Binius64 circuit library for verifying MAYO-2 post-quantum signatures
//! against a hidden public key and a committed message.
//!
//! # API at a glance
//!
//! Most consumers only need the high-level [`Prover`] / [`Verifier`] pair
//! plus the [`compute_c`] / [`compute_pk_id`] helpers exposed below.
//! [`Mayo2Verify`] is the circuit-builder primitive used internally; reach
//! for it only if you need to embed the MAYO-2 verifier inside a larger
//! Binius64 circuit.

#![deny(unsafe_code)]
#![warn(unreachable_pub)]

mod api;
mod gf16;
mod params;
mod quadratic;
mod shake256;
mod util;
mod verify;
mod whipping;

pub use api::{
    Commitment, DOMAIN_TAG_C, DOMAIN_TAG_LEN, DOMAIN_TAG_PK, Error, PkId, Proof, ProofBundle,
    Prover, Result, SignedMessage, Verifier, compute_c, compute_c_from_digest, compute_commitments,
    compute_pk_id,
};
pub use verify::Mayo2Verify;

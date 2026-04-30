//! Integration tests for the top-level `Mayo2Verify` SNARK.
//!
//! These tests build the full circuit, populate it with a NIST KAT vector
//! (lifted to a 32-byte digest via SHAKE-256), and check that the constraint
//! system accepts a valid witness and rejects a tampered one.

#![deny(unsafe_code)]

mod common;

use binius_core::verify::verify_constraints;
use binius_frontend::CircuitBuilder;
use binius_mayo::Mayo2Verify;

use common::{kat, oracle};

const KAT_PATH: &str = "tests/kat/mayo2.rsp";

/// Lift a KAT entry to the form `Mayo2Verify` expects:
/// `m = SHAKE-256(msg, 32)`, the same 32-byte digest the MAYO-2 signature
/// authenticates internally.
fn kat_to_circuit_inputs(
    e: &kat::KatEntry,
) -> (
    [u8; 32],
    Vec<[u8; 64]>,
    Vec<[u8; 64]>,
    Vec<[u8; 64]>,
    [u8; 186],
) {
    let cpk: &[u8; 4912] = e.pk.as_slice().try_into().expect("pk size");
    let sig: [u8; 186] = e.signature().try_into().expect("sig size");
    let expanded = oracle::expand_pk(cpk);
    let m_vec = oracle::shake256(e.message(), 32);
    let m: [u8; 32] = m_vec.as_slice().try_into().unwrap();
    (m, expanded.p1, expanded.p2, expanded.p3, sig)
}

#[test]
fn verify_first_kat_in_circuit() {
    // Given: the first KAT entry, lifted to a 32-byte digest.
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");
    let entry = &entries[0];
    let (m, p1, p2, p3, sig) = kat_to_circuit_inputs(entry);

    // When: we build the full Mayo2Verify circuit once.
    let build_start = std::time::Instant::now();
    let builder = CircuitBuilder::new();
    let v = Mayo2Verify::new(&builder);
    let circuit = builder.build();
    let build_elapsed = build_start.elapsed();
    let n_and = circuit.constraint_system().n_and_constraints();
    eprintln!(
        "Mayo2Verify built in {:.2?}; total AND constraint count = {}",
        build_elapsed, n_and
    );

    // And: populate the witness for this single KAT.
    let pop_start = std::time::Instant::now();
    let mut w = circuit.new_witness_filler();
    v.populate(&mut w, &m, &p1, &p2, &p3, &sig);

    // Then: the circuit accepts the witness and verify_constraints succeeds.
    circuit
        .populate_wire_witness(&mut w)
        .expect("populate_wire_witness should accept a valid witness");
    let pop_elapsed = pop_start.elapsed();
    eprintln!(
        "populate (build + fill, KAT count={}) took {:.2?}",
        entry.count, pop_elapsed
    );

    verify_constraints(circuit.constraint_system(), &w.into_value_vec())
        .expect("circuit must accept a valid witness");
    eprintln!("verified KAT count={} in circuit", entry.count);
}

#[test]
fn tampered_signature_rejected() {
    // Given: the first KAT entry with a single bit flipped in the signature.
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");
    let entry = &entries[0];
    let (m, p1, p2, p3, mut sig) = kat_to_circuit_inputs(entry);
    sig[0] ^= 1;

    // When: we build and populate.
    let builder = CircuitBuilder::new();
    let v = Mayo2Verify::new(&builder);
    let circuit = builder.build();
    let mut w = circuit.new_witness_filler();
    v.populate(&mut w, &m, &p1, &p2, &p3, &sig);

    // Then: at least one of `populate_wire_witness` or `verify_constraints`
    // must reject. (Both are acceptable rejection sites depending on which
    // bxor/and constraint along the chain is violated first.)
    let pop = circuit.populate_wire_witness(&mut w);
    if pop.is_ok() {
        let r = verify_constraints(circuit.constraint_system(), &w.into_value_vec());
        assert!(r.is_err(), "tampered signature should be rejected");
    }
}

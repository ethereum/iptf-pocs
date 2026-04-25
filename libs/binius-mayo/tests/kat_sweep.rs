//! KAT-sweep integration tests for `Mayo2Verify`.
//!
//! These tests build the full circuit ONCE and re-use it across many KAT
//! vectors, exercising both the happy path (positive sweep over the first 10
//! NIST KATs) and three negative paths where a single byte / bit of the
//! witness is tampered with after the public inputs have been derived.
//!
//! The verifier follows Approach E: `m` is the 32-byte MAYO digest, not the
//! raw KAT message. We compute `m = SHAKE-256(msg, 32)` off-circuit using the
//! pure-Rust oracle helper before populating the witness.

#![deny(unsafe_code)]

mod common;

use binius_core::verify::verify_constraints;
use binius_frontend::CircuitBuilder;
use binius_mayo::Mayo2Verify;

use common::{kat, oracle};

const KAT_PATH: &str = "tests/kat/mayo2.rsp";

#[test]
fn kats() {
    // Given: every KAT entry in the response file.
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");

    // When: build the circuit ONCE and reuse it for every entry.
    let builder = CircuitBuilder::new();
    let v = Mayo2Verify::new(&builder);
    let circuit = builder.build();

    let mut total_pop_ms = 0u128;
    let mut total_check_ms = 0u128;
    let n = entries.len() as u128;

    for entry in entries.iter() {
        let cpk: &[u8; 4912] = entry.pk.as_slice().try_into().expect("pk size");
        let sig: &[u8; 186] = entry.signature().try_into().expect("sig size");
        let msg = entry.message();

        let expanded = oracle::expand_pk(cpk);
        let m_vec = oracle::shake256(msg, 32);
        let m: [u8; 32] = m_vec.as_slice().try_into().expect("digest size");

        let t_pop = std::time::Instant::now();
        let mut w = circuit.new_witness_filler();
        v.populate(&mut w, &m, &expanded.p1, &expanded.p2, &expanded.p3, sig);
        circuit.populate_wire_witness(&mut w).unwrap_or_else(|e| {
            panic!(
                "populate_wire_witness for KAT count={} failed: {e:?}",
                entry.count
            )
        });
        total_pop_ms += t_pop.elapsed().as_millis();

        let t_chk = std::time::Instant::now();
        verify_constraints(circuit.constraint_system(), &w.into_value_vec()).unwrap_or_else(|e| {
            panic!("KAT count={} failed verify_constraints: {e:?}", entry.count)
        });
        total_check_ms += t_chk.elapsed().as_millis();
    }

    eprintln!(
        "{} KATs verified -- populate: {} ms total ({} ms avg), verify_constraints: {} ms total ({} ms avg)",
        n,
        total_pop_ms,
        total_pop_ms / n,
        total_check_ms,
        total_check_ms / n,
    );
}

/// Tampering with the off-circuit message digest must break the algebraic
/// equality `y == t` even though the public inputs (`c`, `pk_id`) still come
/// out consistent with the (tampered) witness.
///
/// Given: the first KAT, with one bit flipped in the digest `m`.
/// When : we build, populate, and check.
/// Then : either `populate_wire_witness` or `verify_constraints` rejects.
#[test]
fn tampered_message_rejects() {
    // Given: load the first KAT and tamper with `m`.
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");
    let entry = &entries[0];
    let cpk: &[u8; 4912] = entry.pk.as_slice().try_into().expect("pk size");
    let sig: &[u8; 186] = entry.signature().try_into().expect("sig size");

    let expanded = oracle::expand_pk(cpk);
    let m_vec = oracle::shake256(entry.message(), 32);
    let mut m: [u8; 32] = m_vec.as_slice().try_into().expect("digest size");
    m[0] ^= 1; // flip a bit of the digest

    // When: build and populate.
    let builder = CircuitBuilder::new();
    let v = Mayo2Verify::new(&builder);
    let circuit = builder.build();
    let mut w = circuit.new_witness_filler();
    v.populate(&mut w, &m, &expanded.p1, &expanded.p2, &expanded.p3, sig);

    // Then: at least one of the two checks must reject.
    let pop = circuit.populate_wire_witness(&mut w);
    if pop.is_ok() {
        let r = verify_constraints(circuit.constraint_system(), &w.into_value_vec());
        assert!(r.is_err(), "tampered message digest should reject");
    }
}

/// Tampering with the expanded public key (a single nibble bit in `p1[0]`)
/// must break the SPS-vs-target equality.
///
/// Given: the first KAT, with one bit flipped in `expanded.p1[0][0]`.
/// When : we build, populate, and check.
/// Then : either `populate_wire_witness` or `verify_constraints` rejects.
#[test]
fn tampered_pk_rejects() {
    // Given: load the first KAT and tamper with `expanded.p1[0][0]`.
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");
    let entry = &entries[0];
    let cpk: &[u8; 4912] = entry.pk.as_slice().try_into().expect("pk size");
    let sig: &[u8; 186] = entry.signature().try_into().expect("sig size");

    let mut expanded = oracle::expand_pk(cpk);
    let m_vec = oracle::shake256(entry.message(), 32);
    let m: [u8; 32] = m_vec.as_slice().try_into().expect("digest size");
    // Flip a low-nibble bit of p1[0][0]; nibbles are GF(16) elements.
    expanded.p1[0][0] ^= 0x01;

    // When: build and populate.
    let builder = CircuitBuilder::new();
    let v = Mayo2Verify::new(&builder);
    let circuit = builder.build();
    let mut w = circuit.new_witness_filler();
    v.populate(&mut w, &m, &expanded.p1, &expanded.p2, &expanded.p3, sig);

    // Then: at least one of the two checks must reject.
    let pop = circuit.populate_wire_witness(&mut w);
    if pop.is_ok() {
        let r = verify_constraints(circuit.constraint_system(), &w.into_value_vec());
        assert!(r.is_err(), "tampered pk should reject");
    }
}

/// Tampering with a salt byte changes the SHAKE-derived target `t` and the
/// nibble-derivation of `s`, so the algebraic equality must break.
///
/// Given: the first KAT, with `sig[170]` (a salt byte) flipped.
/// When : we build, populate, and check.
/// Then : either `populate_wire_witness` or `verify_constraints` rejects.
#[test]
fn wrong_salt_rejects() {
    // Given: load the first KAT and tamper with the salt.
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");
    let entry = &entries[0];
    let cpk: &[u8; 4912] = entry.pk.as_slice().try_into().expect("pk size");
    let mut sig: [u8; 186] = entry.signature().try_into().expect("sig size");

    let expanded = oracle::expand_pk(cpk);
    let m_vec = oracle::shake256(entry.message(), 32);
    let m: [u8; 32] = m_vec.as_slice().try_into().expect("digest size");
    // Salt occupies sig[162..186]; flip a bit inside that range.
    sig[170] ^= 1;

    // When: build and populate.
    let builder = CircuitBuilder::new();
    let v = Mayo2Verify::new(&builder);
    let circuit = builder.build();
    let mut w = circuit.new_witness_filler();
    v.populate(&mut w, &m, &expanded.p1, &expanded.p2, &expanded.p3, &sig);

    // Then: at least one of the two checks must reject.
    let pop = circuit.populate_wire_witness(&mut w);
    if pop.is_ok() {
        let r = verify_constraints(circuit.constraint_system(), &w.into_value_vec());
        assert!(r.is_err(), "tampered salt should reject");
    }
}

/// Sanity test: `populate` must be infallible (no panics) on valid inputs.
///
/// Given: the first three KAT entries.
/// When : we populate the witness for each.
/// Then : `populate` returns without panicking. (We do not run
///        `verify_constraints` here -- that path is exercised by
///        `sweep_first_10_kats`.)
#[test]
fn populate_does_not_panic_on_valid_inputs() {
    // Given: load the first three KATs.
    let entries = kat::load_rsp(KAT_PATH);
    assert!(
        entries.len() >= 3,
        "expected >=3 KAT entries, got {}",
        entries.len()
    );

    // When: build the circuit ONCE.
    let builder = CircuitBuilder::new();
    let v = Mayo2Verify::new(&builder);
    let circuit = builder.build();

    // Then: each `populate` call must not panic.
    for entry in entries.iter().take(3) {
        let cpk: &[u8; 4912] = entry.pk.as_slice().try_into().expect("pk size");
        let sig: &[u8; 186] = entry.signature().try_into().expect("sig size");
        let expanded = oracle::expand_pk(cpk);
        let m_vec = oracle::shake256(entry.message(), 32);
        let m: [u8; 32] = m_vec.as_slice().try_into().expect("digest size");

        let mut w = circuit.new_witness_filler();
        v.populate(&mut w, &m, &expanded.p1, &expanded.p2, &expanded.p3, sig);
        // Drop `w` without running populate_wire_witness -- this test is
        // only about `populate` itself.
        drop(w);
    }
}

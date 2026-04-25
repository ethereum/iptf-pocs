//! Integration tests for the pure-Rust MAYO-2 oracle verifier.
//!
//! Runs the oracle against the vendored NIST KAT vectors and the
//! standard tampered-input rejection checks.

#![deny(unsafe_code)]

mod common;

use common::oracle::{CPK_BYTES, SIG_BYTES};
use common::{kat, oracle};

const KAT_PATH: &str = "tests/kat/mayo2.rsp";

#[test]
fn verify_all_kats() {
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");

    let start = std::time::Instant::now();
    for e in &entries {
        let pk: &[u8; CPK_BYTES] =
            e.pk.as_slice()
                .try_into()
                .unwrap_or_else(|_| panic!("pk must be {CPK_BYTES} bytes (count={})", e.count));
        let sig_slice = e.signature();
        let sig: &[u8; SIG_BYTES] = sig_slice
            .try_into()
            .unwrap_or_else(|_| panic!("sig must be {SIG_BYTES} bytes (count={})", e.count));
        let msg = e.message();
        assert!(oracle::verify(pk, msg, sig), "KAT count={} failed", e.count);
    }
    let elapsed = start.elapsed();
    eprintln!(
        "verified {} KAT entries in {:.2?} ({:.1?} avg)",
        entries.len(),
        elapsed,
        elapsed / (entries.len() as u32)
    );
}

#[test]
fn tamper_signature_rejects() {
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");

    let e = &entries[0];
    let pk: &[u8; CPK_BYTES] = e.pk.as_slice().try_into().expect("pk size");
    let mut sig: [u8; SIG_BYTES] = e.signature().try_into().expect("sig size");
    sig[5] ^= 1;
    let msg = e.message();
    assert!(!oracle::verify(pk, msg, &sig), "tampered sig accepted");
}

#[test]
fn tamper_message_rejects() {
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");

    let e = &entries[0];
    let pk: &[u8; CPK_BYTES] = e.pk.as_slice().try_into().expect("pk size");
    let sig: &[u8; SIG_BYTES] = e.signature().try_into().expect("sig size");
    // Mutate the first byte of the message.
    let mut msg = e.message().to_vec();
    if msg.is_empty() {
        msg.push(0x42);
    } else {
        msg[0] ^= 1;
    }
    assert!(
        !oracle::verify(pk, &msg, sig),
        "tampered msg accepted (count={})",
        e.count
    );
}

#[test]
fn tamper_salt_rejects() {
    let entries = kat::load_rsp(KAT_PATH);
    assert!(!entries.is_empty(), "no KAT entries parsed");

    let e = &entries[0];
    let pk: &[u8; CPK_BYTES] = e.pk.as_slice().try_into().expect("pk size");
    let mut sig: [u8; SIG_BYTES] = e.signature().try_into().expect("sig size");
    // Salt occupies the last SALT_BYTES (= 24) bytes of the signature.
    sig[SIG_BYTES - 1] ^= 0x80;
    let msg = e.message();
    assert!(!oracle::verify(pk, msg, &sig), "tampered salt accepted");
}

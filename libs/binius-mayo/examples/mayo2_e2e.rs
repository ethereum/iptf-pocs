//! End-to-end MAYO-2 prove + verify example using the high-level API.
//!
//! Loads the first NIST KAT entry, compiles a `Prover` and `Verifier`,
//! produces a `ProofBundle`, then verifies it. Prints timings.
//!
//! Run with: `cargo run --example mayo2_e2e --release`.

#![deny(unsafe_code)]

use std::{fs, path::Path, time::Instant};

use binius_mayo::{Prover, SignedMessage, Verifier, compute_commitments};

const SIG_BYTES: usize = 186;
const CPK_BYTES: usize = 4912;

/// Tiny KAT loader for the first stanza in `tests/kat/mayo2.rsp`.
fn load_first_kat(path: &Path) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path)?;
    let mut pk: Option<Vec<u8>> = None;
    let mut sm: Option<Vec<u8>> = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() && pk.is_some() && sm.is_some() {
            break;
        }
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            match k.trim() {
                "pk" if pk.is_none() => pk = Some(hex::decode(v.trim())?),
                "sm" if sm.is_none() => sm = Some(hex::decode(v.trim())?),
                _ => {}
            }
        }
    }
    Ok((pk.ok_or("missing pk")?, sm.ok_or("missing sm")?))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (pk_bytes, sm_bytes) = load_first_kat(Path::new("tests/kat/mayo2.rsp"))?;
    let cpk: &[u8; CPK_BYTES] = pk_bytes.as_slice().try_into()?;
    let sig: &[u8; SIG_BYTES] = sm_bytes[..SIG_BYTES].try_into()?;
    let payload: &[u8] = &sm_bytes[SIG_BYTES..];

    let t = Instant::now();
    let prover = Prover::compile()?;
    println!("prover compile:  {:.2?}", t.elapsed());

    let t = Instant::now();
    let verifier = Verifier::compile()?;
    println!("verifier compile:{:.2?}", t.elapsed());

    let signed = SignedMessage { payload, cpk, sig };

    let t = Instant::now();
    let bundle = prover.prove(&signed)?;
    println!(
        "prove:           {:.2?} ({} byte proof)",
        t.elapsed(),
        bundle.proof.len()
    );

    // Application-level check: re-derive (c, pk_id) and compare.
    let (c_local, pk_id_local) = compute_commitments(payload, cpk);
    assert_eq!(bundle.c, c_local, "commitment mismatch");
    assert_eq!(bundle.pk_id, pk_id_local, "pk_id mismatch");

    let t = Instant::now();
    verifier.verify(&bundle)?;
    println!("verify:          {:.2?}", t.elapsed());

    println!("OK");
    Ok(())
}

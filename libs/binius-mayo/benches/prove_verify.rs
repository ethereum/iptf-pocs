//! Criterion benchmarks for the high-level `Prover::prove` and
//! `Verifier::verify` paths, using the NIST KAT vectors as inputs.
//!
//! Run with: `cargo bench --bench prove_verify`

#![deny(unsafe_code)]

use std::{
    fs,
    path::Path,
    time::{Duration, Instant},
};

use binius_mayo::{ProofBundle, Prover, SignedMessage, Verifier};
use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};

const KAT_PATH: &str = "tests/kat/mayo2.rsp";
const SIG_BYTES: usize = 186;
const CPK_BYTES: usize = 4912;
const N_KATS: usize = 10;

#[derive(Clone)]
struct KatInput {
    cpk: [u8; CPK_BYTES],
    sig: [u8; SIG_BYTES],
    msg: Vec<u8>,
}

fn load_kats(path: &Path, n: usize) -> Vec<KatInput> {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));

    let mut out: Vec<KatInput> = Vec::with_capacity(n);
    let mut pk: Option<Vec<u8>> = None;
    let mut sm: Option<Vec<u8>> = None;

    let flush = |pk: &mut Option<Vec<u8>>, sm: &mut Option<Vec<u8>>, out: &mut Vec<KatInput>| {
        if let (Some(pkb), Some(smb)) = (pk.take(), sm.take()) {
            let cpk: [u8; CPK_BYTES] = pkb.as_slice().try_into().expect("cpk size");
            let sig: [u8; SIG_BYTES] = smb[..SIG_BYTES].try_into().expect("sig size");
            let msg = smb[SIG_BYTES..].to_vec();
            out.push(KatInput { cpk, sig, msg });
        }
    };

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            flush(&mut pk, &mut sm, &mut out);
            if out.len() >= n {
                return out;
            }
            continue;
        }
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            match k.trim() {
                "pk" => pk = hex::decode(v.trim()).ok(),
                "sm" => sm = hex::decode(v.trim()).ok(),
                _ => {}
            }
        }
    }
    flush(&mut pk, &mut sm, &mut out);
    out
}

fn bench_prove(c: &mut Criterion) {
    let kats = load_kats(Path::new(KAT_PATH), N_KATS);
    assert!(!kats.is_empty(), "no KATs loaded");
    let prover = Prover::compile().expect("prover compile");

    let signed: Vec<SignedMessage<'_>> = kats
        .iter()
        .map(|kat| SignedMessage {
            payload: &kat.msg,
            cpk: &kat.cpk,
            sig: &kat.sig,
        })
        .collect();

    let mut group = c.benchmark_group("prove");
    group.sample_size(10);
    group.throughput(Throughput::Elements(1));
    group.bench_function("kats", |b| {
        let mut i = 0usize;
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let s = &signed[i % signed.len()];
                i += 1;
                let start = Instant::now();
                let bundle = prover.prove(black_box(s)).expect("prove");
                total += start.elapsed();
                black_box(bundle);
            }
            total
        });
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let kats = load_kats(Path::new(KAT_PATH), N_KATS);
    assert!(!kats.is_empty(), "no KATs loaded");
    let prover = Prover::compile().expect("prover compile");
    let verifier = Verifier::compile().expect("verifier compile");

    let bundles: Vec<ProofBundle> = kats
        .iter()
        .map(|kat| {
            let signed = SignedMessage {
                payload: &kat.msg,
                cpk: &kat.cpk,
                sig: &kat.sig,
            };
            prover.prove(&signed).expect("prove")
        })
        .collect();

    let mut group = c.benchmark_group("verify");
    group.sample_size(50);
    group.throughput(Throughput::Elements(1));
    group.bench_function("kats", |b| {
        let mut i = 0usize;
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let bundle = &bundles[i % bundles.len()];
                i += 1;
                let start = Instant::now();
                verifier.verify(black_box(bundle)).expect("verify");
                total += start.elapsed();
            }
            total
        });
    });
    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);

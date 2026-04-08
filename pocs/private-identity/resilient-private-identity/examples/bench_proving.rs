//! Benchmark for resilient private identity proof generation.
//!
//! Runs 100 iterations of link, enrollment, and membership proof generation
//! and reports min/mean/median/max total time per operation.
//!
//! Prerequisites: `nargo` and `bb` on PATH, compiled circuits in `circuits/`.
//!
//! ```bash
//! cargo run --example bench_proving --release
//! ```

use std::path::PathBuf;
use std::time::{Duration, Instant};

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_std::UniformRand;
use sha2::{Digest, Sha256};

use resilient_private_identity::{
    adapters::{
        bb_prover::BBProver,
        lean_imt_merkle::LeanImtMerkleStore,
        mock_mpc::MockMpcNetwork,
        mock_proof::MockProofBackend,
    },
    domain::voprf::{aggregate, blind, hash_to_curve, unblind, verify_dleq},
    ports::{
        merkle::MerkleStore,
        mpc::{BlindEvaluateRequest, MpcNetwork},
        proof::ProofBackend,
    },
    poseidon::{hash_attr, hash_leaf, hash_link},
    types::{Predicate, SvdwWitnesses},
};

const ITERATIONS: usize = 100;

fn stats(durations: &[Duration]) -> (Duration, Duration, Duration, Duration) {
    let mut sorted: Vec<Duration> = durations.to_vec();
    sorted.sort();
    let min = sorted[0];
    let max = sorted[sorted.len() - 1];
    let mean = sorted.iter().sum::<Duration>() / sorted.len() as u32;
    let median = if sorted.len() % 2 == 0 {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2
    } else {
        sorted[sorted.len() / 2]
    };
    (min, mean, median, max)
}

fn fmt_duration(d: Duration) -> String {
    let ms = d.as_millis();
    if ms >= 1000 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}ms", ms)
    }
}

fn main() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let prover = BBProver::new(project_root);

    let mut rng = ark_std::rand::thread_rng();

    // --- Common identity parameters ---
    let user_id = "email:alice@example.com";
    let attrs = [
        Fr::from(1u64),     // ageOver18
        Fr::from(840u64),   // nationality
        Fr::from(0u64),     // reserved
        Fr::from(20178u64), // enrollmentDay
    ];
    let version: u32 = 1;

    // Derive user_id_hash and hash-to-curve point (deterministic per user_id)
    let hash = Sha256::digest(user_id.as_bytes());
    let user_id_hash = Fr::from_be_bytes_mod_order(&hash);
    let svdw = hash_to_curve(user_id_hash);
    let g_id = svdw.point;
    let svdw_witnesses = SvdwWitnesses {
        index: svdw.index,
        w: svdw.w,
        inv_w2: svdw.inv_w2,
        non_qr_witnesses: svdw.non_qr_witnesses,
    };

    // --- Setup vOPRF outputs via mock MPC (needed for enrollment proof) ---
    let mpc = MockMpcNetwork::new(4, 7, MockProofBackend);
    let mpc_public_key = mpc.public_key();

    let r_setup = Fr::rand(&mut rng);
    let blinded_request_setup = blind(g_id, r_setup);

    let request = BlindEvaluateRequest {
        blinded_request: blinded_request_setup,
        identity_commitment: hash_link(user_id_hash, Fr::rand(&mut rng)),
        g_id,
        link_proof: vec![0xCA, 0xFE], // MockProofBackend accepts any non-empty proof
    };
    let evaluations = mpc.evaluate(&request);

    let threshold = mpc.threshold();
    let mut valid_evals = Vec::new();
    for eval in &evaluations {
        let node_pk = mpc.node_public_key(eval.node_index);
        if verify_dleq(node_pk, blinded_request_setup, eval.partial, &eval.proof) {
            valid_evals.push(eval.clone());
        }
    }
    assert!(
        valid_evals.len() >= threshold,
        "Not enough valid MPC responses: got {}, need {threshold}",
        valid_evals.len()
    );

    let partials: Vec<(usize, ark_bn254::G1Affine)> = valid_evals[..threshold]
        .iter()
        .map(|e| (e.node_index, e.partial))
        .collect();
    let aggregated = aggregate(&partials);
    let raw_nullifier = unblind(aggregated, r_setup);
    let chaum_pedersen_proof = mpc.aggregate_dleq_proof(g_id, raw_nullifier);

    // --- Setup Merkle tree with one enrolled leaf (needed for membership proof) ---
    let identity_secret = Fr::rand(&mut rng);
    let version_fr = Fr::from(version as u64);
    let attr_hash = hash_attr(version_fr, &attrs);
    let leaf = hash_leaf(identity_secret, attr_hash);

    let mut merkle_store = LeanImtMerkleStore::new();
    let leaf_index = merkle_store.insert(leaf);
    let merkle_path = merkle_store.get_proof(leaf_index);
    let root = merkle_store.root().expect("tree has root after insert");

    println!("=== Resilient Private Identity Proving Benchmarks ({ITERATIONS} iterations) ===\n");

    // === Link Proof Benchmark ===
    println!("Running link proof benchmarks...");
    let mut link_times = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let salt = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);
        let identity_commitment = hash_link(user_id_hash, salt);
        let blinded_request = blind(g_id, r);

        let start = Instant::now();
        prover
            .generate_link_proof(
                user_id_hash,
                salt,
                r,
                g_id,
                identity_commitment,
                blinded_request,
                &svdw_witnesses,
            )
            .expect("link proof failed");
        link_times.push(start.elapsed());

        if (i + 1) % 10 == 0 {
            eprintln!("  link proof {}/{ITERATIONS}", i + 1);
        }
    }

    // === Enrollment Proof Benchmark ===
    println!("Running enrollment proof benchmarks...");
    let mut enrollment_times = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let start = Instant::now();
        prover
            .generate_enrollment_proof(
                identity_secret,
                &attrs,
                version,
                g_id,
                raw_nullifier,
                mpc_public_key,
                &chaum_pedersen_proof,
            )
            .expect("enrollment proof failed");
        enrollment_times.push(start.elapsed());

        if (i + 1) % 10 == 0 {
            eprintln!("  enrollment proof {}/{ITERATIONS}", i + 1);
        }
    }

    // === Membership Proof Benchmark ===
    println!("Running membership proof benchmarks...");
    let mut membership_times = Vec::with_capacity(ITERATIONS);
    let predicate = Predicate {
        predicate_type: 1,     // boolean check
        attr_index: 0,         // ageOver18
        value: Fr::from(0u64), // unused for boolean predicate
    };
    for i in 0..ITERATIONS {
        let external_nullifier = Fr::from((i + 1) as u64);

        let start = Instant::now();
        prover
            .generate_membership_proof(
                identity_secret,
                &attrs,
                version,
                &merkle_path,
                root,
                external_nullifier,
                &predicate,
            )
            .expect("membership proof failed");
        membership_times.push(start.elapsed());

        if (i + 1) % 10 == 0 {
            eprintln!("  membership proof {}/{ITERATIONS}", i + 1);
        }
    }

    // === Results ===
    println!("\n| Operation | Min | Mean | Median | Max |");
    println!("|---|---|---|---|---|");

    for (name, times) in [
        ("Link Proof", &link_times),
        ("Enrollment Proof", &enrollment_times),
        ("Membership Proof", &membership_times),
    ] {
        let (min, mean, median, max) = stats(times);
        println!(
            "| {} | {} | {} | {} | {} |",
            name,
            fmt_duration(min),
            fmt_duration(mean),
            fmt_duration(median),
            fmt_duration(max),
        );
    }
}

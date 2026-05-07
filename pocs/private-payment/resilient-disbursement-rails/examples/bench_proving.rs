//! Benchmark for resilient-disbursement-rails proof generation.
//!
//! Times claim and pool-withdraw proof generation through the real
//! `BBProver` adapter (shells to `nargo` + `bb`). Mirrors the reference
//! identity PoC's bench shape.
//!
//! Prerequisites: `nargo` and `bb` on PATH, compiled circuits in
//! `circuits/`. Run with:
//!
//! ```bash
//! cargo run --example bench_proving --release
//! ```

use std::{
    path::PathBuf,
    time::{
        Duration,
        Instant,
    },
};

use ark_bn254::Fr;
use ark_ff::PrimeField;

use resilient_disbursement_rails::{
    adapters::{
        bb_prover::BBProver,
        lean_imt_merkle::LeanImtMerkleStore,
        software_smartcard::SoftwareSmartcard,
    },
    crypto::stealth::destination_from_derived_pubkey,
    funder::Funder,
    ports::{
        merkle::MerkleStore,
        proof::ProofBackend,
        smartcard::Smartcard,
    },
    poseidon::{
        fr_from_be_bytes,
        hash_claim_nullifier,
        hash_derived_pubkey_packed,
        hash_m_packed,
        hash_pool_commitment,
        pack_chain_id,
        pack_round_id,
    },
    smartcard::apdu::{
        decode_export_key_response,
        decode_sign_voucher_response,
        encode_export_key,
        encode_generate_key,
        encode_sign_voucher,
        serialize_round_header,
    },
    types::{
        Address,
        Bytes32,
        ClaimWitness,
        CohortMerklePath,
        PoolMerklePath,
        PoolWithdrawWitness,
        U256Be,
        VoucherContext,
    },
};

const ITERATIONS: usize = 5;

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
        format!("{ms}ms")
    }
}

fn pad_address(a: &Address) -> Bytes32 {
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(a);
    padded
}

fn main() {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let prover = BBProver::new(project_root);

    let token: Address = [0xccu8; 20];
    let claim_contract: Address = [0xeeu8; 20];
    let chain_id = U256Be::from_u64(11_155_111);
    let amount = U256Be::from_u64(1_000_000);
    let round_id: Bytes32 = [0x42; 32];
    let cohort_size: u64 = 1;
    let close_time: u64 = 1_000_000;

    let mut card = SoftwareSmartcard::new(None, false);
    let _ = card.transmit(&encode_generate_key()).unwrap();
    let m_pub = decode_export_key_response(&card.transmit(&encode_export_key()).unwrap())
        .unwrap();

    let funder = Funder::new(vec![], claim_contract, [0xff; 20]);
    let header = funder.build_round_header(
        round_id,
        1,
        [0xab; 32], // dummy cohort_root; we recompute below
        amount,
        cohort_size,
        token,
        close_time,
        chain_id,
    );
    let commitments = funder
        .compute_round_commitments(&header, &[m_pub])
        .expect("compute commitments");

    let mut cohort_tree = LeanImtMerkleStore::new();
    let m_x_hi = fr_from_be_bytes(&m_pub.x[..16]);
    let m_x_lo = fr_from_be_bytes(&m_pub.x[16..32]);
    let m_y_hi = fr_from_be_bytes(&m_pub.y[..16]);
    let m_y_lo = fr_from_be_bytes(&m_pub.y[16..32]);
    let m_packed = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
    cohort_tree.insert(m_packed);
    let cohort_root_fr = cohort_tree.root().expect("cohort root");
    let cohort_path = cohort_tree.get_proof(0).unwrap();

    let commitment_fr = fr_from_be_bytes(&commitments[0]);
    let mut pool_tree = LeanImtMerkleStore::new();
    pool_tree.insert(commitment_fr);
    let pool_root_fr = pool_tree.root().expect("pool root");
    let pool_path = pool_tree.get_proof(0).unwrap();

    // Convert generic MerklePath -> domain CohortMerklePath / PoolMerklePath.
    let cohort_path_domain = CohortMerklePath {
        siblings: cohort_path
            .siblings
            .iter()
            .map(fr_to_be_bytes_local)
            .collect(),
        indices: cohort_path.indices.clone(),
    };
    let pool_path_domain = PoolMerklePath {
        siblings: pool_path
            .siblings
            .iter()
            .map(fr_to_be_bytes_local)
            .collect(),
        indices: pool_path.indices.clone(),
    };

    let ctx = VoucherContext {
        round_id,
        cohort_root: fr_to_be_bytes_local(&cohort_root_fr),
        claim_contract,
        per_recipient_amount: amount,
        chain_id,
    };
    // Header used by the bench mirrors `funder.build_round_header`'s output
    // but with the recomputed cohort_root.
    let header_for_apdu = {
        let mut h = header.clone();
        h.cohort_root = fr_to_be_bytes_local(&cohort_root_fr);
        h
    };
    let serialized = serialize_round_header(&header_for_apdu);
    let resp = card
        .transmit(&encode_sign_voucher([0u8; 32], &serialized, &ctx))
        .expect("SIGN_VOUCHER");
    let (m_pub2, derived_pub, signature) = decode_sign_voucher_response(&resp).unwrap();
    assert_eq!(m_pub, m_pub2);

    let destination = destination_from_derived_pubkey(&derived_pub);

    let r_packed = pack_round_id(
        fr_from_be_bytes(&round_id[..16]),
        fr_from_be_bytes(&round_id[16..32]),
    );
    let c_packed = pack_chain_id(
        fr_from_be_bytes(&chain_id.as_bytes()[..16]),
        fr_from_be_bytes(&chain_id.as_bytes()[16..32]),
    );
    let cc_fr = fr_from_be_bytes(&pad_address(&claim_contract));
    let derived_pubkey_x_hi = fr_from_be_bytes(&derived_pub.x[..16]);
    let derived_pubkey_x_lo = fr_from_be_bytes(&derived_pub.x[16..32]);
    let derived_pubkey_y_hi = fr_from_be_bytes(&derived_pub.y[..16]);
    let derived_pubkey_y_lo = fr_from_be_bytes(&derived_pub.y[16..32]);
    let derived_pubkey_packed = hash_derived_pubkey_packed(
        derived_pubkey_x_hi,
        derived_pubkey_x_lo,
        derived_pubkey_y_hi,
        derived_pubkey_y_lo,
    );
    let nullifier =
        hash_claim_nullifier(m_packed, derived_pubkey_packed, r_packed, cc_fr, c_packed);
    let token_fr = fr_from_be_bytes(&pad_address(&token));
    let amount_fr = Fr::from_be_bytes_mod_order(amount.as_bytes());
    // Sanity: recompute the commitment and assert tree leaf agrees.
    let recomputed_commitment =
        hash_pool_commitment(token_fr, amount_fr, m_packed, r_packed);
    assert_eq!(recomputed_commitment, commitment_fr);

    let relay_submitter: Address = [0x44u8; 20];
    let destination_fr = fr_from_be_bytes(&pad_address(&destination));

    let claim_witness = ClaimWitness {
        round_id_hi: fr_from_be_bytes(&round_id[..16]),
        round_id_lo: fr_from_be_bytes(&round_id[16..32]),
        cohort_root: cohort_root_fr,
        chain_id_hi: fr_from_be_bytes(&chain_id.as_bytes()[..16]),
        chain_id_lo: fr_from_be_bytes(&chain_id.as_bytes()[16..32]),
        destination: destination_fr,
        amount: amount_fr,
        nullifier,
        claim_contract_address: cc_fr,
        relay_submitter: fr_from_be_bytes(&pad_address(&relay_submitter)),
        derived_pubkey_x_hi,
        derived_pubkey_x_lo,
        derived_pubkey_y_hi,
        derived_pubkey_y_lo,
        m_x_hi,
        m_x_lo,
        m_y_hi,
        m_y_lo,
        signature_r: signature.r,
        signature_s: signature.s,
        merkle_path: cohort_path_domain,
    };
    let pool_witness = PoolWithdrawWitness {
        pool_root: pool_root_fr,
        claim_nullifier: nullifier,
        token: token_fr,
        amount: amount_fr,
        recipient: destination_fr,
        m_x_hi,
        m_x_lo,
        m_y_hi,
        m_y_lo,
        derived_pubkey_x_hi,
        derived_pubkey_x_lo,
        derived_pubkey_y_hi,
        derived_pubkey_y_lo,
        round_id_hi: claim_witness.round_id_hi,
        round_id_lo: claim_witness.round_id_lo,
        chain_id_hi: claim_witness.chain_id_hi,
        chain_id_lo: claim_witness.chain_id_lo,
        claim_contract: cc_fr,
        merkle_path: pool_path_domain,
    };

    println!(
        "=== Resilient Disbursement Rails Proving Benchmarks ({ITERATIONS} iterations) ==="
    );

    let mut claim_times = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let start = Instant::now();
        prover
            .generate_claim_proof(&claim_witness)
            .expect("claim proof");
        claim_times.push(start.elapsed());
        eprintln!("  claim proof {}/{ITERATIONS}", i + 1);
    }

    let mut pool_times = Vec::with_capacity(ITERATIONS);
    for i in 0..ITERATIONS {
        let start = Instant::now();
        prover
            .generate_pool_withdraw_proof(&pool_witness)
            .expect("pool-withdraw proof");
        pool_times.push(start.elapsed());
        eprintln!("  pool-withdraw proof {}/{ITERATIONS}", i + 1);
    }

    println!("\n| Operation | Min | Mean | Median | Max |");
    println!("|---|---|---|---|---|");
    for (name, times) in [
        ("Claim Proof", &claim_times),
        ("Pool-Withdraw Proof", &pool_times),
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

fn fr_to_be_bytes_local(fr: &Fr) -> Bytes32 {
    use ark_ff::BigInteger;
    let bigint = fr.into_bigint();
    let le = bigint.to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

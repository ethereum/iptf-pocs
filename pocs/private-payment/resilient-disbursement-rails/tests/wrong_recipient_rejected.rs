//! Scenario 8: wrong recipient rejected.
//!
//! The relay constructs a pool-withdraw proof with `recipient` set to the
//! relay's own EOA instead of the claim circuit's `destination`. The
//! claim contract's cross-proof binding asserts
//! `poolPublicInputs.recipient == destination`; mismatch => revert with
//! `BadPoolBinding`. Funds do not move.
//!
//! NOTE: this test is genuinely meaningful only with REAL proofs. In
//! mock-mode the on-chain mock verifier accepts any bytes; the
//! cross-proof public-input check still runs and catches the mismatch,
//! so the test is still useful, but it does not validate the circuit's
//! recipient-binding constraint. Both modes are exercised; gating only
//! affects what's asserted about the proof generator.

mod common;

use alloy::primitives::{
    Bytes,
    U256,
};
use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use common::*;
use resilient_disbursement_rails::{
    ports::proof::ProofBackend,
    poseidon::fr_from_be_bytes,
    types::{
        PoolWithdrawWitness,
        U256Be,
    },
};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::TestBackend;

#[tokio::test(flavor = "multi_thread")]
async fn wrong_recipient_rejected() {
    let backend = TestBackend::from_env();
    let use_mock = matches!(&backend, TestBackend::Mock(_));

    let harness = AnvilHarness::start(use_mock);
    let dep = harness.deploy_all();

    let cohort_size: u64 = 1;
    let (mut cards, m_pubs, pre_keys) = make_cohort(cohort_size as usize);

    let (_reg, cohort_root_be, cohort_root_fr) = build_cohort_tree(&m_pubs);
    publish_cohort_on_chain(&harness.provider, dep.registry, cohort_root_fr, &m_pubs)
        .await;

    let per_recipient = U256Be::from_u64(1_000_000);
    let close_time: u64 = 2_000_000_000;
    let chain_id_be = U256Be::from_u64(harness.chain_id);
    let round_id = round_id_from_u64(0xf06);

    let (header, commitments, funder_sig) = publish_round(
        &harness,
        &dep,
        1,
        cohort_root_be,
        cohort_size,
        per_recipient,
        close_time,
        chain_id_be,
        round_id,
        &m_pubs,
    )
    .await;

    let funder = build_funder_with_multisig(&dep, &harness);
    let relay_secret = relay_secret_from_seed([0xf6u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    let relay_addr = ANVIL_OWNER_PKS[0]
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .unwrap()
        .address();

    // Build a legitimate bundle, then swap in the relay's own EOA as the
    // pool-withdraw `recipient`.
    let mut bundle = build_claim_for_card(
        &backend,
        &mut cards[0],
        pre_keys[0],
        1,
        &m_pubs,
        0,
        0,
        &commitments,
        &header,
        &funder_sig,
        &signed_roster,
        &relay_secret,
        relay_addr,
        &funder_owners,
        FUNDER_THRESHOLD,
    );

    // Substitute pool's recipient field for the relay's own EOA in the
    // public inputs and re-prove.
    let mut bad_pool_witness: PoolWithdrawWitness = bundle.pool_witness.clone();
    let attacker_recipient = relay_addr;
    let attacker_recipient_fr = {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(attacker_recipient.as_slice());
        fr_from_be_bytes(&padded)
    };
    bad_pool_witness.recipient = attacker_recipient_fr;

    let bad_pool_proof_res = backend.generate_pool_withdraw_proof(&bad_pool_witness);

    // In real mode the prover may reject; in mock mode it succeeds.
    let bad_pool_proof = match bad_pool_proof_res {
        Ok(p) => p,
        Err(_) => {
            // Real mode rejected at proof gen - that's also a valid
            // failure mode. Verify funds didn't move and exit.
            let bal = IShieldedPool::new(dep.pool, &harness.provider)
                .balance(dep.claim_contract)
                .call()
                .await
                .unwrap();
            assert_eq!(bal, u256_be_to_alloy(&per_recipient));
            return;
        }
    };

    // Patch the bundle's pool_proof and pool_public_inputs[RECIPIENT].
    bundle.pool_proof = bad_pool_proof;
    bundle.pool_public_inputs[4] = {
        // Convert Fr to U256 (matches fr_to_u256 inline).
        let bigint = bad_pool_witness.recipient.into_bigint();
        let le = bigint.to_bytes_le();
        U256::from_le_slice(&le)
    };

    // Submit. Claim contract asserts pool.recipient == destination;
    // attacker_recipient != destination, so revert with BadPoolBinding.
    let owner = harness.owner_provider(0);
    let cc = IClaimContract::new(dep.claim_contract, &owner);
    let outcome = cc
        .claim(
            Bytes::from(bundle.claim_proof.clone()),
            bundle.claim_public_inputs,
            Bytes::from(bundle.pool_proof.clone()),
            bundle.pool_public_inputs,
        )
        .send()
        .await;
    match outcome {
        Err(_) => { /* ok */ }
        Ok(tx) => {
            let r = tx.get_receipt().await.unwrap();
            assert!(!r.status(), "wrong-recipient claim must revert");
        }
    }

    let bal = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(bal, u256_be_to_alloy(&per_recipient));

    let _ = use_mock;
    let _ = Fr::from(0u64); // keep ark_bn254 import live in mock paths
}

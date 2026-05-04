//! Scenario 6: proof-stealing rejected.
//!
//! Cohort 1. Card claims via Relay A (owner 0). Capture the calldata
//! (proof + public inputs). Replay the same calldata from Relay B's EOA
//! (owner 1). The claim contract asserts `claimPublicInputs.relaySubmitter
//! == msg.sender`; B's EOA differs from A's, so the contract reverts with
//! `BadRelaySubmitter`. Funds go to relay A's claim, never to B's replay.

mod common;

use alloy::primitives::{
    Bytes,
    U256,
};
use common::*;
use resilient_disbursement_rails::types::U256Be;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::TestBackend;

#[tokio::test(flavor = "multi_thread")]
async fn proof_stealing_rejected() {
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
    let round_id = round_id_from_u64(0xe04);

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
    let relay_secret = relay_secret_from_seed([0xe4u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    // Build a bundle that pins relay A (owner 0) as the relaySubmitter.
    let relay_a = ANVIL_OWNER_PKS[0]
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .unwrap()
        .address();
    let bundle = build_claim_for_card(
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
        relay_a,
        &funder_owners,
        FUNDER_THRESHOLD,
    );

    // Replay from relay B (owner 1) using the same bundle. The claim
    // contract asserts relaySubmitter == msg.sender; A != B, so revert.
    let owner_b = harness.owner_provider(1);
    let cc = IClaimContract::new(dep.claim_contract, &owner_b);
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
        Err(_) => { /* ok: alloy bubbled the revert */ }
        Ok(tx) => {
            let r = tx.get_receipt().await.unwrap();
            assert!(!r.status(), "stolen proof must revert");
        }
    }

    // Verify funds did not move: pool balance unchanged.
    let bal = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(
        bal,
        u256_be_to_alloy(&per_recipient) * U256::from(cohort_size)
    );
}

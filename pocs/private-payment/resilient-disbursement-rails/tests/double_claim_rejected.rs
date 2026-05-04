//! Scenario 3: double-claim rejected.
//!
//! Cohort 2. Card[0] claims successfully, then attempts a second claim
//! for the same `(card, round, claimContract, chainId)` tuple. Because
//! the claim_nullifier is deterministic in those four values, the second
//! claim's nullifier collides with the first; the contract reverts on
//! `NullifierConsumed`.

mod common;

use common::*;
use resilient_disbursement_rails::types::U256Be;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::TestBackend;

#[tokio::test(flavor = "multi_thread")]
async fn double_claim_rejected() {
    let backend = TestBackend::from_env();
    let use_mock = matches!(&backend, TestBackend::Mock(_));

    let harness = AnvilHarness::start(use_mock);
    let dep = harness.deploy_all();

    let cohort_size: u64 = 2;
    let (mut cards, m_pubs, pre_keys) = make_cohort(cohort_size as usize);

    let (_reg, cohort_root_be, cohort_root_fr) = build_cohort_tree(&m_pubs);
    publish_cohort_on_chain(&harness.provider, dep.registry, cohort_root_fr, &m_pubs)
        .await;

    let per_recipient = U256Be::from_u64(1_000_000);
    // Close-time is a unix timestamp; pick a date well past 2026 so the
    // round stays open for the duration of the test.
    let close_time: u64 = 2_000_000_000;
    let chain_id_be = U256Be::from_u64(harness.chain_id);
    let round_id = round_id_from_u64(0xc02);

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
    let relay_secret = relay_secret_from_seed([0xc2u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    // Card 0 claims successfully through relay (owner 0).
    let relay_addr0 = ANVIL_OWNER_PKS[0]
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .unwrap()
        .address();

    let bundle1 = build_claim_for_card(
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
        relay_addr0,
        &funder_owners,
        FUNDER_THRESHOLD,
    );
    let r1 = submit_claim_from_owner(&harness, &dep, &bundle1, 0)
        .await
        .expect("first claim send");
    assert!(r1.status());

    // Build a second bundle for the same card / round / contract / chain
    // (relay can be a different EOA; doesn't matter, the nullifier is
    // determined by card+round+contract+chainId).
    let relay_addr1 = ANVIL_OWNER_PKS[1]
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .unwrap()
        .address();
    let bundle2 = build_claim_for_card(
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
        relay_addr1,
        &funder_owners,
        FUNDER_THRESHOLD,
    );

    // Same nullifier as bundle1.
    assert_eq!(bundle1.claim_nullifier, bundle2.claim_nullifier);

    let outcome = submit_claim_from_owner(&harness, &dep, &bundle2, 1).await;
    match outcome {
        Err(_) => { /* ok: tx reverted */ }
        Ok(receipt) => assert!(
            !receipt.status(),
            "second claim should revert (nullifier consumed)"
        ),
    }

    // Pool balance now has the unclaimed leaf for card 1.
    let bal = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(bal, u256_be_to_alloy(&per_recipient));
}

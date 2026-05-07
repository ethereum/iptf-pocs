//! Scenario 1: golden path. Cohort 4, single round, all 4 cards claim.
//!
//! Asserts:
//! - Each `claim()` tx succeeds.
//! - MockERC20 balance of each `destination` == `perRecipientAmount`.
//! - `pool.balance(claimContract)` == 0 after all four claims.
//! - `nullifierConsumed[claim_nullifier]` is true on both the claim
//!   contract and the pool.

mod common;

use alloy::primitives::U256;
use common::*;

use resilient_disbursement_rails::types::U256Be;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::TestBackend;

#[tokio::test(flavor = "multi_thread")]
async fn golden_path() {
    let backend = TestBackend::from_env();
    let use_mock = matches!(&backend, TestBackend::Mock(_));
    println!("[1/7] starting anvil + deploying contracts (use_mock={use_mock})");

    // 1. Anvil + deploy.
    let harness = AnvilHarness::start(use_mock);
    let dep = harness.deploy_all();
    println!("deployment: {dep:?}");

    // 2. Cohort of 4 cards.
    let cohort_size: u64 = 4;
    println!("[2/7] generating cohort of {cohort_size} cards");
    let (mut cards, m_pubs, pre_keys) = make_cohort(cohort_size as usize);

    // 3. Build cohort tree off-chain + push to on-chain Registry.
    println!("[3/7] building cohort tree and publishing to Registry");
    let (_reg, cohort_root_be, cohort_root_fr) = build_cohort_tree(&m_pubs);
    let cohort_version =
        publish_cohort_on_chain(&harness.provider, dep.registry, cohort_root_fr, &m_pubs)
            .await;
    assert_eq!(cohort_version, 1);
    println!("    cohort_version={cohort_version}");

    // 4. Publish a round with 4 commitments.
    println!("[4/7] publishing round with {cohort_size} commitments");
    let per_recipient: U256Be = U256Be::from_u64(1_000_000);
    let chain_id_be: U256Be = U256Be::from_u64(harness.chain_id);
    // Close-time is a unix timestamp; pick a date well past 2026 so the
    // round stays open for the duration of the test.
    let close_time: u64 = 2_000_000_000;
    let round_id = round_id_from_u64(0xa55);

    let (header, commitments, funder_sig) = publish_round(
        &harness,
        &dep,
        cohort_version,
        cohort_root_be,
        cohort_size,
        per_recipient,
        close_time,
        chain_id_be,
        round_id,
        &m_pubs,
    )
    .await;

    // Sanity: factory deposited 4 commitments.
    let pool_size = IShieldedPool::new(dep.pool, &harness.provider)
        .subTreeSize(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(pool_size, U256::from(cohort_size));

    let pool_balance_before = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(
        pool_balance_before,
        u256_be_to_alloy(&per_recipient) * U256::from(cohort_size)
    );
    println!("    pool_balance_before={pool_balance_before} pool_size={pool_size}");

    // 5. Build a fresh-roster Companion world: one funder, one relay.
    println!("[5/7] building funder multisig and signed relay roster");
    let funder = build_funder_with_multisig(&dep, &harness);
    let relay_secret = relay_secret_from_seed([0xa1u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    // 6. For each card, drive Companion -> Relay -> claim().
    // Use a different anvil owner as the relay submitter per-card to
    // exercise the relay_submitter == msg.sender binding.
    println!("[6/7] driving Companion -> Relay -> claim() for each card");
    for (i, card) in cards.iter_mut().enumerate() {
        // Owner indices [0..7]; relay_submitter for card i = owner[i].
        let relay_idx = i % 7;
        let relay_addr: alloy::primitives::Address = ANVIL_OWNER_PKS[relay_idx]
            .parse::<alloy::signers::local::PrivateKeySigner>()
            .unwrap()
            .address();
        println!("    card {i}: relay_idx={relay_idx} relay_addr={relay_addr}");

        let bundle = build_claim_for_card(
            &backend,
            card,
            pre_keys[i],
            cohort_version,
            &m_pubs,
            i as u64,
            i as u64,
            &commitments,
            &header,
            &funder_sig,
            &signed_roster,
            &relay_secret,
            relay_addr,
            &funder_owners,
            FUNDER_THRESHOLD,
        );

        let receipt = submit_claim_from_owner(&harness, &dep, &bundle, relay_idx)
            .await
            .expect("claim submission");
        assert!(receipt.status(), "claim() reverted for card {i}");
        println!(
            "    card {i}: claim tx={:?} gas_used={}",
            receipt.transaction_hash, receipt.gas_used,
        );

        // Destination received perRecipient.
        let dest_balance = IMockERC20::new(dep.mock_token, &harness.provider)
            .balanceOf(bundle.destination)
            .call()
            .await
            .unwrap();
        assert_eq!(
            dest_balance,
            u256_be_to_alloy(&per_recipient),
            "card {i} destination did not receive funds"
        );
        println!(
            "    card {i}: destination={} received={}",
            bundle.destination, dest_balance,
        );

        // claim_nullifier is now consumed (both claim contract and pool).
        let consumed_cc = IClaimContract::new(dep.claim_contract, &harness.provider)
            .nullifierConsumed(bundle.claim_nullifier)
            .call()
            .await
            .unwrap();
        assert!(consumed_cc);
        let consumed_pool = IShieldedPool::new(dep.pool, &harness.provider)
            .spentClaimNullifiers(bundle.claim_nullifier)
            .call()
            .await
            .unwrap();
        assert!(consumed_pool);
    }

    // 7. Pool balance for the claim contract is zero after all four claims.
    println!("[7/7] verifying final pool state");
    let pool_balance_after = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(pool_balance_after, U256::ZERO);
    println!("    pool_balance_after={pool_balance_after}");

    let claimed = IShieldedPool::new(dep.pool, &harness.provider)
        .roundClaimed(dep.claim_contract, U256::from_be_slice(&header.round_id))
        .call()
        .await
        .unwrap();
    assert_eq!(
        claimed,
        u256_be_to_alloy(&per_recipient) * U256::from(cohort_size)
    );
    println!("    round_claimed={claimed}");
    println!("golden_path: OK");
}

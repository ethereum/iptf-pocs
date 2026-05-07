//! Scenario 2: partial claim + residual recovery.
//!
//! Cohort 4. Three cards claim, one does not.
//! - After three claims, pool retains `1 * perRecipientAmount` for this
//!   round.
//! - Funder calls `funderUnshieldResidual(roundId)` while the timelock
//!   has not yet expired: the call reverts (`RoundOpen`).
//! - Fast-forward EVM time past `closeTime + RESIDUAL_TIMELOCK_SECONDS`
//!   (30 days) via `evm_increaseTime`. The funder then drives
//!   `Funder::recover_residual` which proposes/confirms/executes the
//!   `Multisig` call to `claimContract.funderUnshieldResidual`. The
//!   residual transfers to the funder's residual destination, the round
//!   is marked paid, and a second residual call must revert.

mod common;

use alloy::{
    primitives::U256,
    providers::Provider,
    sol,
};
use common::*;
use resilient_disbursement_rails::types::U256Be;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::TestBackend;

sol! {
    #[sol(rpc)]
    interface IClaimContractResidual {
        function funderUnshieldResidual(uint256 roundId) external;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn partial_claim_residual() {
    let backend = TestBackend::from_env();
    let use_mock = matches!(&backend, TestBackend::Mock(_));

    let harness = AnvilHarness::start(use_mock);
    let dep = harness.deploy_all();

    let cohort_size: u64 = 4;
    let (mut cards, m_pubs, pre_keys) = make_cohort(cohort_size as usize);

    let (_reg, cohort_root_be, cohort_root_fr) = build_cohort_tree(&m_pubs);
    publish_cohort_on_chain(&harness.provider, dep.registry, cohort_root_fr, &m_pubs)
        .await;

    let per_recipient = U256Be::from_u64(1_000_000);
    // Close-time: 10 minutes from now so the round stays open during the
    // three claims (and the early-revert assertion) on the wall-clock,
    // but `evm_increaseTime` later jumps the chain past `closeTime +
    // 30 days` to satisfy the residual timelock.
    let close_time: u64 = harness_now_unix() + 600;
    let chain_id_be = U256Be::from_u64(harness.chain_id);
    let round_id = round_id_from_u64(0xb01);

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
    let relay_secret = relay_secret_from_seed([0xb1u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    // Three out of four claim.
    for i in 0..3 {
        let relay_idx = i % 7;
        let relay_addr = ANVIL_OWNER_PKS[relay_idx]
            .parse::<alloy::signers::local::PrivateKeySigner>()
            .unwrap()
            .address();

        let bundle = build_claim_for_card(
            &backend,
            &mut cards[i],
            pre_keys[i],
            1,
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
        let r = submit_claim_from_owner(&harness, &dep, &bundle, relay_idx)
            .await
            .expect("claim send");
        assert!(r.status());
    }

    // Pool retains exactly 1 * perRecipientAmount.
    let bal = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(bal, u256_be_to_alloy(&per_recipient));

    // Build the funderUnshieldResidual calldata for the early-revert
    // assertion (still under the timelock).
    let owner0 = harness.owner_provider(0);
    let cc = IClaimContractResidual::new(dep.claim_contract, &owner0);
    let calldata = cc
        .funderUnshieldResidual(U256::from_be_slice(&round_id))
        .calldata()
        .clone();

    // Verify timelock-gating: calling residual before
    // `closeTime + RESIDUAL_TIMELOCK_SECONDS` reverts.
    let early_outcome = multisig_propose_confirm_try_execute(
        &harness,
        dep.multisig,
        dep.claim_contract,
        calldata.clone(),
    )
    .await;
    match early_outcome {
        Err(_) => { /* ok: revert bubbled up */ }
        Ok(receipt) => assert!(
            !receipt.status(),
            "early residual recovery should revert (RoundOpen)"
        ),
    }
    let bal_unchanged = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(bal_unchanged, u256_be_to_alloy(&per_recipient));

    // Advance EVM time past `close_time + 30 days + slack`. anvil's
    // `evm_increaseTime` advances from the CURRENT block timestamp, which
    // may already lag wall-clock now, so we compute the delta needed to
    // overshoot the threshold and then mine a block.
    let target = close_time + 30 * 86_400 + 60;
    let block = harness
        .provider
        .get_block_by_number(alloy::eips::BlockNumberOrTag::Latest)
        .await
        .unwrap()
        .unwrap();
    let now_ts = block.header.timestamp;
    let advance_secs: u64 = target.saturating_sub(now_ts).max(60);
    let _: serde_json::Value = harness
        .provider
        .raw_request("evm_increaseTime".into(), vec![advance_secs])
        .await
        .expect("evm_increaseTime");
    let _: serde_json::Value = harness
        .provider
        .raw_request("evm_mine".into(), ())
        .await
        .expect("evm_mine");

    // Drive the production-shaped residual recovery via Funder.
    // Rebuild fresh DynProviders for the funder rather than reusing the
    // harness owners. The harness owners' nonce-filler state was mutated
    // by many txns earlier (publishRound, claims, the early-revert
    // assertion); fresh providers eliminate any chance of a stale cached
    // nonce after `evm_increaseTime` perturbs anvil's clock.
    let signer_providers: Vec<alloy::providers::DynProvider> = ANVIL_OWNER_PKS
        .iter()
        .take(FUNDER_THRESHOLD)
        .map(|pk| {
            let signer: alloy::signers::local::PrivateKeySigner = pk.parse().unwrap();
            let wallet = alloy::network::EthereumWallet::from(signer);
            alloy::providers::ProviderBuilder::new()
                .wallet(wallet)
                .connect_http(harness.endpoint.parse().unwrap())
                .erased()
        })
        .collect();
    let _tx_hash = funder
        .recover_residual(U256::from_be_slice(&round_id), &signer_providers)
        .await
        .expect("Funder::recover_residual");

    // Funder residual destination = deployer EOA (configured in Deploy.s.sol).
    let dest_balance = IMockERC20::new(dep.mock_token, &harness.provider)
        .balanceOf(harness.deployer_addr)
        .call()
        .await
        .unwrap();
    assert!(
        dest_balance >= u256_be_to_alloy(&per_recipient),
        "residual destination did not receive at least one perRecipientAmount, got {dest_balance}"
    );

    let bal_after = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(bal_after, U256::ZERO);

    // residualPaid[roundId] must now be true.
    let paid = IClaimContract::new(dep.claim_contract, &harness.provider)
        .residualPaid(U256::from_be_slice(&round_id))
        .call()
        .await
        .unwrap();
    assert!(paid, "residualPaid mapping should be true after recovery");

    // Second residual call must revert (ResidualAlreadyPaid).
    let second_attempt = funder
        .recover_residual(U256::from_be_slice(&round_id), &signer_providers)
        .await;
    match second_attempt {
        Err(_) => { /* expected */ }
        Ok(_) => panic!("second residual recovery should fail"),
    }
}

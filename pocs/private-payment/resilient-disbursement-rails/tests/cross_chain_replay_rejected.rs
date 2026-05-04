//! Scenario 5: cross-chain replay rejected.
//!
//! Approach (documented divergence): rather than two parallel anvils with
//! different chain ids (alloy's node_bindings can spawn arbitrary chain
//! ids but managing two simultaneous instances reliably in tests is
//! finicky), we exercise the contract-level chain-id bindings on a
//! single chain by submitting a claim whose `claimPublicInputs.chainId_*`
//! limbs encode a different chain id than the one anvil reports as
//! `block.chainid`.
//!
//! The claim contract enforces:
//!   - `claimPublicInputs.chainId == block.chainid`
//!   - `claimPublicInputs.chainId == header.chainId`
//!
//! With a doctored bundle whose chainId_lo encodes 31338 (one off from
//! the active 31337) we expect a revert with `BadChainId`.
//!
//! The factory's `header.chainId == block.chainid` guard is exercised
//! independently by the existing `forge test` Phase-3 suite; this file
//! exercises the claim-time guard.

mod common;

use alloy::primitives::{
    Bytes,
    U256,
};
use ark_bn254::Fr;
use common::*;
use resilient_disbursement_rails::types::U256Be;
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::TestBackend;

#[tokio::test(flavor = "multi_thread")]
async fn cross_chain_replay_rejected() {
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
    let round_id = round_id_from_u64(0xb05);

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
    let relay_secret = relay_secret_from_seed([0xb5u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    let relay_addr = ANVIL_OWNER_PKS[0]
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
        relay_addr,
        &funder_owners,
        FUNDER_THRESHOLD,
    );

    // Doctor the chain-id public inputs to a different chain id (31338).
    let mut claim_pi = bundle.claim_public_inputs;
    claim_pi[3] = U256::from(0u64); // CHAIN_ID_HI
    claim_pi[4] = U256::from(31338u64); // CHAIN_ID_LO

    let owner = harness.owner_provider(0);
    let cc = IClaimContract::new(dep.claim_contract, &owner);
    let outcome = cc
        .claim(
            Bytes::from(bundle.claim_proof.clone()),
            claim_pi,
            Bytes::from(bundle.pool_proof.clone()),
            bundle.pool_public_inputs,
        )
        .send()
        .await;
    match outcome {
        Err(_) => { /* ok: alloy bubbled the revert */ }
        Ok(tx) => {
            let r = tx.get_receipt().await.unwrap();
            assert!(!r.status(), "cross-chain replay must revert");
        }
    }

    // Funds didn't move.
    let bal = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(
        bal,
        u256_be_to_alloy(&per_recipient) * U256::from(cohort_size)
    );

    let _ = Fr::from(0u64);
}

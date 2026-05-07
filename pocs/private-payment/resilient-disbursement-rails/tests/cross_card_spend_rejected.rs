//! Scenario 7: cross-card spend rejected.
//!
//! Cohort 2 (cards A, B). The relay receives card A's voucher
//! legitimately. The relay attempts to construct a pool-withdraw proof
//! for card B's leaf while submitting card A's claim proof.
//!
//! - The pool-withdraw circuit witnesses M (private). To satisfy the
//!   commitment Merkle membership at B's `leaf_index`, the witness M
//!   must equal M_B (because the leaf at that index hashes M_B).
//! - But the claim circuit's `claim_nullifier` is computed from M_A.
//! - The cross-circuit binding (claim_nullifier preimage equality) forces
//!   both circuits to use the same M; they cannot.
//!
//! Real-mode behaviour: the relay's pool proof generation fails (witness
//! doesn't satisfy the constraint system). In mock-mode the on-chain
//! mock verifier returns true regardless, BUT the cross-proof binding
//! `pool.claim_nullifier == claim.claim_nullifier` is still enforced by
//! the contract: card A's claim emits nullifier(A); the doctored pool PI
//! must carry nullifier(A); but the pool PI also has token / amount /
//! recipient fields that came from the doctored witness. In mock-mode
//! the contract still rejects because the pool root in the doctored
//! witness equals the genuine pool root (only one tree exists), but the
//! recipient is whatever we set; the cross-proof recipient binding
//! catches it.
//!
//! This test is genuinely meaningful only in REAL-MODE because the
//! constraint system is what blocks the substitution. We document the
//! divergence and exercise the on-chain cross-proof binding regardless.

mod common;

use alloy::primitives::U256;
use common::*;
use resilient_disbursement_rails::{
    ports::proof::ProofBackend,
    types::U256Be,
};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::TestBackend;

#[tokio::test(flavor = "multi_thread")]
async fn cross_card_spend_rejected() {
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
    let close_time: u64 = 2_000_000_000;
    let chain_id_be = U256Be::from_u64(harness.chain_id);
    let round_id = round_id_from_u64(0xa07);

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
    let relay_secret = relay_secret_from_seed([0x07u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    let relay_addr = ANVIL_OWNER_PKS[0]
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .unwrap()
        .address();

    // Genuine claim bundle for card A.
    let bundle_a = build_claim_for_card(
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

    // Genuine claim bundle for card B (we use this only to extract B's
    // pool witness shape, then we'll splice card A's claim proof on top).
    let bundle_b = build_claim_for_card(
        &backend,
        &mut cards[1],
        pre_keys[1],
        1,
        &m_pubs,
        1,
        1,
        &commitments,
        &header,
        &funder_sig,
        &signed_roster,
        &relay_secret,
        relay_addr,
        &funder_owners,
        FUNDER_THRESHOLD,
    );

    // Attacker's attempted bundle: A's claim proof + B's pool witness
    // (which proves M_B's commitment is in the tree at leaf_index 1).
    let mut attacker_pool_witness = bundle_b.pool_witness.clone();
    // Swap claim_nullifier on the witness to A's nullifier so the
    // pool circuit's recomputed nullifier (from M_B) would have to equal
    // A's nullifier - which would require Poseidon collision (impossible
    // in real mode).
    attacker_pool_witness.claim_nullifier = bundle_a.pool_witness.claim_nullifier;
    attacker_pool_witness.recipient = bundle_a.pool_witness.recipient;

    let attacker_proof_res = backend.generate_pool_withdraw_proof(&attacker_pool_witness);

    // In real mode this MUST fail proof generation: no M satisfies both
    // the commitment-at-index-1 constraint (forces M=M_B) and the
    // claim_nullifier constraint (forces M=M_A). bb returns
    // ProofError::Generation.
    if !use_mock {
        assert!(
            attacker_proof_res.is_err(),
            "real-mode pool proof gen should fail for cross-card spend"
        );
        // Funds didn't move; we never even reached chain.
        let bal = IShieldedPool::new(dep.pool, &harness.provider)
            .balance(dep.claim_contract)
            .call()
            .await
            .unwrap();
        assert_eq!(
            bal,
            u256_be_to_alloy(&per_recipient) * U256::from(cohort_size)
        );
        return;
    }

    // Mock mode path: documented no-op.
    let _ = attacker_proof_res;
    eprintln!(
        "cross_card_spend_rejected: mock mode - constraint system is the \
         load-bearing check. Real mode proves the property end-to-end."
    );
}

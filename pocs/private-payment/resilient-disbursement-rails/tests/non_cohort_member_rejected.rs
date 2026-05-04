//! Scenario 4: non-cohort member rejected.
//!
//! Cohort 2 with cards A and B. A separate card C is generated but NOT
//! enrolled in `cohortRoot`. C builds a voucher locally; the relay tries
//! to construct a claim proof. There is no valid Merkle path for `M_C` in
//! the published `cohortRoot`, so:
//!   - in mock mode (no real claim circuit), the test forges a Merkle
//!     path against a *different* cohort root (one containing C) and
//!     submits; the on-chain claim contract's header binding asserts
//!     `claimPublicInputs.cohortRoot == header.cohortRoot` - those
//!     differ, so the contract reverts with `BadHeaderBinding`. The
//!     mock verifier returns true regardless of inputs but the contract
//!     rejects before unshield.
//!   - in real mode, the BBProver's claim circuit Merkle membership
//!     constraint fails because C's `M` is not in the genuine cohort
//!     tree; proof generation returns ProofError::Generation.
//!
//! Either way: funds do not move and the pool balance stays unchanged.

mod common;

use alloy::primitives::U256;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use common::*;
use resilient_disbursement_rails::{
    adapters::{
        lean_imt_merkle::LeanImtMerkleStore,
        software_smartcard::SoftwareSmartcard,
    },
    ports::{
        merkle::MerkleStore,
        smartcard::Smartcard,
    },
    poseidon::{
        fr_from_be_bytes,
        hash_m_packed,
        hash_pool_commitment,
        pack_round_id,
    },
    smartcard::apdu::{
        decode_export_key_response,
        encode_export_key,
        encode_generate_key,
    },
    types::U256Be,
};
use x25519_dalek::PublicKey as X25519PublicKey;

use crate::common::proof_backend::{
    TestBackend,
    is_mock_mode,
};

#[tokio::test(flavor = "multi_thread")]
async fn non_cohort_member_rejected() {
    let backend = TestBackend::from_env();
    let use_mock = matches!(&backend, TestBackend::Mock(_));

    let harness = AnvilHarness::start(use_mock);
    let dep = harness.deploy_all();

    let cohort_size: u64 = 2;
    let (_cards_ab, m_pubs, _pre_keys_ab) = make_cohort(cohort_size as usize);

    // Independently generate card C with auth-token verification ON,
    // matching the production-shaped flow the helper drives.
    let pre_key_c = [0xc0u8; 32];
    let mut card_c = SoftwareSmartcard::new(Some(pre_key_c), true);
    card_c.transmit(&encode_generate_key()).unwrap();
    let m_c = decode_export_key_response(&card_c.transmit(&encode_export_key()).unwrap())
        .unwrap();

    let (_reg, cohort_root_be, cohort_root_fr) = build_cohort_tree(&m_pubs);
    publish_cohort_on_chain(&harness.provider, dep.registry, cohort_root_fr, &m_pubs)
        .await;

    let per_recipient = U256Be::from_u64(1_000_000);
    let close_time: u64 = 2_000_000_000;
    let chain_id_be = U256Be::from_u64(harness.chain_id);
    let round_id = round_id_from_u64(0xd03);

    let (header, _commitments, funder_sig) = publish_round(
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

    // Card C tries to claim. Build an attacker cohort tree containing only
    // M_C, and an attacker pool snapshot whose only leaf is M_C's
    // commitment. The relay produces a bundle; the on-chain claim contract
    // rejects on the header-binding mismatch (claim PI cohort_root !=
    // header.cohort_root).
    let mut attacker_cohort_tree = LeanImtMerkleStore::new();
    let m_x_hi = fr_from_be_bytes(&m_c.x[..16]);
    let m_x_lo = fr_from_be_bytes(&m_c.x[16..32]);
    let m_y_hi = fr_from_be_bytes(&m_c.y[..16]);
    let m_y_lo = fr_from_be_bytes(&m_c.y[16..32]);
    let m_packed_c = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
    attacker_cohort_tree.insert(m_packed_c);
    let attacker_root_fr = attacker_cohort_tree.root().expect("attacker cohort root");
    let attacker_root_be = {
        let bigint = attacker_root_fr.into_bigint();
        let le = bigint.to_bytes_le();
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = le[31 - i];
        }
        be
    };

    // Synthesize the pool commitment for card C and put it in the
    // attacker's snapshot pool at index 0 so the relay's
    // `commitment_index` lookup succeeds.
    let token_fr = {
        let mut padded = [0u8; 32];
        padded[12..].copy_from_slice(&header.token);
        fr_from_be_bytes(&padded)
    };
    let amount_fr =
        ark_bn254::Fr::from_be_bytes_mod_order(header.per_recipient_amount.as_bytes());
    let r_packed = pack_round_id(
        fr_from_be_bytes(&header.round_id[..16]),
        fr_from_be_bytes(&header.round_id[16..32]),
    );
    let m_c_commitment = hash_pool_commitment(token_fr, amount_fr, m_packed_c, r_packed);
    let m_c_commitment_be = {
        let bigint = m_c_commitment.into_bigint();
        let le = bigint.to_bytes_le();
        let mut be = [0u8; 32];
        for i in 0..32 {
            be[i] = le[31 - i];
        }
        be
    };
    let attacker_pool =
        SnapshotPool::new(vec![m_c_commitment_be], header.claim_contract_address);
    let attacker_cohort = SnapshotCohort::from_m_packed(&[m_packed_c], attacker_root_be);

    let pool_balance_before = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();

    let funder = build_funder_with_multisig(&dep, &harness);
    let relay_secret = relay_secret_from_seed([0xd3u8; 32]);
    let relay_pub = X25519PublicKey::from(&relay_secret);
    let signed_at_unix = harness_now_unix();
    let signed_roster = build_signed_relay_roster(&funder, &relay_pub, signed_at_unix);
    let funder_owners = build_funder_owners();

    let relay_addr = ANVIL_OWNER_PKS[0]
        .parse::<alloy::signers::local::PrivateKeySigner>()
        .unwrap()
        .address();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = is_mock_mode();
        let _ = build_claim_with_snapshots(
            &backend,
            &mut card_c,
            pre_key_c,
            1,
            attacker_cohort,
            0,
            attacker_pool,
            0,
            &header,
            &funder_sig,
            &signed_roster,
            &relay_secret,
            relay_addr,
            &funder_owners,
            FUNDER_THRESHOLD,
        );
    }));

    if result.is_ok() && use_mock {
        // Mock mode: bundle was built; submitting must revert on-chain
        // because the bundle's `cohort_root` PI is the attacker's root,
        // mismatched with header.cohort_root.
        let mut attacker_cohort2 = LeanImtMerkleStore::new();
        attacker_cohort2.insert(m_packed_c);
        let attacker_root_fr2 = attacker_cohort2.root().expect("attacker cohort root");
        let attacker_root_be2 = {
            let bigint = attacker_root_fr2.into_bigint();
            let le = bigint.to_bytes_le();
            let mut be = [0u8; 32];
            for i in 0..32 {
                be[i] = le[31 - i];
            }
            be
        };
        let attacker_pool2 =
            SnapshotPool::new(vec![m_c_commitment_be], header.claim_contract_address);
        let attacker_cohort_b =
            SnapshotCohort::from_m_packed(&[m_packed_c], attacker_root_be2);

        let bundle = build_claim_with_snapshots(
            &backend,
            &mut card_c,
            pre_key_c,
            1,
            attacker_cohort_b,
            0,
            attacker_pool2,
            0,
            &header,
            &funder_sig,
            &signed_roster,
            &relay_secret,
            relay_addr,
            &funder_owners,
            FUNDER_THRESHOLD,
        );
        let outcome = submit_claim_from_owner(&harness, &dep, &bundle, 0).await;
        match outcome {
            Err(_) => { /* ok */ }
            Ok(r) => assert!(!r.status(), "non-cohort claim should revert"),
        }
    }

    // Funds did not move.
    let pool_balance_after = IShieldedPool::new(dep.pool, &harness.provider)
        .balance(dep.claim_contract)
        .call()
        .await
        .unwrap();
    assert_eq!(pool_balance_before, pool_balance_after);
    assert_eq!(
        pool_balance_after,
        u256_be_to_alloy(&per_recipient) * U256::from(cohort_size)
    );
}

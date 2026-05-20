//! Cross-batch duplicate-nullifier resubmission must be rejected by the registry.

mod common;

use common::*;
use resilient_civic_participation::{
    adapters::mock_proof::MockProofBackend,
    relayer::{
        Relayer,
        core::RelayerPetitionState,
        types::PetitionView,
    },
    types::U256Be,
};

#[test]
fn duplicate_nullifier_across_batches_rejected() {
    let mut harness = Harness::new();

    let class_tag = 826u16;
    let mut signer = enroll_signer(&mut harness, 30, class_tag, [0xa1u8; 32]);
    advance_past_ri_age_window(&mut harness);

    let predicate = class_only_predicate(ATTR_CLASS as u8, class_tag);
    let predicate_encoded = predicate.encode().unwrap();
    let mut salt = [0u8; 32];
    salt[31] = 0x77;
    let fixture = register_petition(
        &mut harness,
        [0xc0; 20],
        predicate,
        salt,
        vec![class_tag],
        vec![1],
        ATTR_CLASS as u8,
        U256Be::from_u64(1_000_000),
        100,
    );

    let s1 = signer_sign(&mut signer, &fixture.view, salt, &predicate_encoded);
    let mut state = RelayerPetitionState::new();
    let _ = publish_one_batch(
        &mut harness,
        &fixture.view,
        [0xa1; 20],
        &mut state,
        vec![s1],
    );

    // Resubmit the same signer; the relayer's IMT insert detects the duplicate.
    let view_after = harness
        .registry
        .state_view(&fixture.event.petition_id)
        .unwrap();
    let s2 = signer_sign(&mut signer, &view_after, salt, &predicate_encoded);
    let mut relayer = Relayer::new([0xa1; 20], MockProofBackend, harness.blob.clone());
    let pv = PetitionView {
        petition_id: view_after.petition_id,
        r_root: view_after.r_root,
        predicate_hash: view_after.predicate_hash,
        class_index: view_after.class_index,
        class_set: view_after.class_set.clone(),
        slot: view_after.slot,
        running_root: view_after.running_root,
        identity_tag_set_root: view_after.identity_tag_set_root,
        leaf_count: view_after.leaf_count,
        signer_vk_hash: [0u8; 32],
    };
    let result = relayer.build_batch(&pv, &mut state, vec![s2]);
    assert!(
        result.is_err(),
        "expected duplicate-nullifier batch to be rejected by the relayer's IMT insert"
    );
}

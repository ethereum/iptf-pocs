//! Regression tests for the dispute-window upper bound and the
//! `mark_unresolved` grace period; the Rust state machine must mirror
//! `PetitionRegistry.sol` so that `mark_unresolved` cannot tombstone
//! a petition in the same block where a valid `resolve` first becomes
//! callable.

mod common;

use common::*;
use resilient_civic_participation::{
    MARK_UNRESOLVED_GRACE_BLOCKS,
    RESOLUTION_DEADLINE_BLOCKS,
    registry::error::RegistryError,
    types::{
        Dispute,
        U256Be,
        ViolationType,
    },
};

const SIGNING_WINDOW: u64 = 100;

fn register_for_lifecycle(harness: &mut Harness) -> (RegisteredFixture, u64) {
    let class_tag = 826u16;
    let _signer = enroll_signer(harness, 30, class_tag, [0xa1u8; 32]);
    advance_past_ri_age_window(harness);
    let predicate = class_only_predicate(ATTR_CLASS as u8, class_tag);
    let mut salt = [0u8; 32];
    salt[31] = 0x42;
    let close_at_block = harness.block() + SIGNING_WINDOW;
    let fixture = register_petition(
        harness,
        [0xc0; 20],
        predicate,
        salt,
        vec![class_tag],
        vec![1],
        ATTR_CLASS as u8,
        U256Be::from_u64(1_000_000),
        SIGNING_WINDOW,
    );
    (fixture, close_at_block)
}

#[test]
fn dispute_rejected_once_resolution_opens() {
    let mut harness = Harness::new();
    let (fixture, close_at_block) = register_for_lifecycle(&mut harness);

    // Jump to the first block where resolve is callable; dispute MUST be closed.
    let now_at = harness.block();
    harness.advance_blocks(close_at_block + RESOLUTION_DEADLINE_BLOCKS - now_at);

    let dispute = Dispute {
        petition_id: fixture.event.petition_id,
        batch_index: 0,
        violation_type: ViolationType::ClassTagOutOfSet,
        position_i: 0,
        position_j: None,
        openings: vec![],
    };
    let err = harness
        .registry
        .dispute(dispute)
        .expect_err("dispute past resolution-open must fail");
    assert!(
        matches!(err, RegistryError::DisputeWindowClosed),
        "expected DisputeWindowClosed, got {err:?}"
    );
}

#[test]
fn mark_unresolved_requires_grace_after_resolution_deadline() {
    let mut harness = Harness::new();
    let (fixture, close_at_block) = register_for_lifecycle(&mut harness);
    let petition_id = fixture.event.petition_id;
    let caller = [0xbe; 20];

    // At `close_at_block + RESOLUTION_DEADLINE_BLOCKS` (resolve opens):
    // mark_unresolved MUST still be blocked.
    let now_at = harness.block();
    harness.advance_blocks(close_at_block + RESOLUTION_DEADLINE_BLOCKS - now_at);
    let err = harness
        .registry
        .mark_unresolved(&petition_id, caller, 0)
        .expect_err("mark_unresolved at resolve-open block must fail");
    assert!(matches!(err, RegistryError::BadState(_, _)));

    // One block before the grace expires; still blocked.
    harness.advance_blocks(MARK_UNRESOLVED_GRACE_BLOCKS - 1);
    let err = harness
        .registry
        .mark_unresolved(&petition_id, caller, 0)
        .expect_err("mark_unresolved one block before grace must fail");
    assert!(matches!(err, RegistryError::BadState(_, _)));

    // Grace expires; mark_unresolved succeeds.
    harness.advance_blocks(1);
    harness
        .registry
        .mark_unresolved(&petition_id, caller, 0)
        .expect("mark_unresolved at grace boundary must succeed");
}

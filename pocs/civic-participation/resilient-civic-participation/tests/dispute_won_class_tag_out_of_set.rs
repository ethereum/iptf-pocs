//! End-to-end dispute path against anvil with the mock SNARK verifier.
//!
//! Flow: register -> forge a 6-record batch where one record carries an
//! out-of-set class_tag -> publish via blob tx -> advance into
//! DisputeWindow -> Disputant builds an `0x01 ClassTagOutOfSet` envelope
//! -> submit on chain -> assert `BatchRepudiated` rolls running state
//! back to the empty IMT.
//!
//! The mock batch verifier accepts any proof bytes (it is deploy-gated
//! by `USE_MOCK_VERIFIER=true`), which lets the test publish a forged
//! batch the real SNARK + relayer would otherwise reject. The dispute
//! path is fully real: KZG openings are verified on chain, the
//! violation predicate is executed in Solidity, and rollback updates
//! the on-chain state.

mod anvil_harness;

use std::{
    path::PathBuf,
    time::Instant,
};

use alloy::{
    primitives::{
        FixedBytes,
        U256,
    },
    providers::Provider,
    sol,
};
use ark_bn254::Fr;

use anvil_harness::AnvilDeployment;
use resilient_civic_participation::{
    BATCH_SIZE_MAX,
    adapters::{
        blob_4844::EIP4844BlobCarrier,
        chain_registry::{
            ChainPetitionRegistry,
            IPetitionRegistry,
        },
    },
    blob::{
        FE_PER_RECORD,
        canonical_eval_points,
        record_to_bls_fields,
    },
    disputant::{
        Disputant,
        types::DisputeContext,
    },
    imt::IndexedMerkleTree,
    ports::{
        blob::BlobCarrier,
        imt::ImtStore,
    },
    poseidon::{
        derive_petition_id,
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_leaf,
        hash_predicate,
    },
    predicate::{
        Op,
        PredicateDef,
        Tuple,
        canonical_scalars,
    },
    types::{
        BatchPublicInputs,
        BatchSubmission,
        Bytes32,
        ClassTag,
        Comparator,
        KzgOpening,
        OpCode,
        RecordEntry,
        TypeTag,
        ViolationType,
    },
};

sol! {
    #[sol(rpc)]
    interface IMockERC20 {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
    }
}

/// `attr[class_index] == class_a OR attr[class_index] == class_b`. Matches
/// the predicate shape the golden path uses; sums to two class operands so
/// the contract's class-binding taint walks through `Or`.
fn two_class_predicate(
    class_index: u8,
    class_a: ClassTag,
    class_b: ClassTag,
) -> PredicateDef {
    let mut operand_a = [0u8; 32];
    operand_a[30..].copy_from_slice(&class_a.to_be_bytes());
    let mut operand_b = [0u8; 32];
    operand_b[30..].copy_from_slice(&class_b.to_be_bytes());
    PredicateDef {
        tuples: vec![
            Tuple {
                claim_index: class_index,
                operand: operand_a,
                type_tag: TypeTag::Int64,
                comparator: Comparator::Eq,
            },
            Tuple {
                claim_index: class_index,
                operand: operand_b,
                type_tag: TypeTag::Int64,
                comparator: Comparator::Eq,
            },
        ],
        ops: vec![
            Op {
                code: OpCode::PushTuple,
                operand: 0,
            },
            Op {
                code: OpCode::PushTuple,
                operand: 1,
            },
            Op {
                code: OpCode::Or,
                operand: 0,
            },
        ],
    }
}

/// Synthesize a record with caller-chosen seed and class_tag. Bypasses
/// `Signer`/`Relayer` (both refuse out-of-set tags), which is what lets
/// the test stage a batch the on-chain dispute path can repudiate.
fn forged_record(seed: u64, class_tag: ClassTag) -> RecordEntry {
    let mut nullifier = [0u8; 32];
    nullifier[24..].copy_from_slice(&seed.to_be_bytes());
    nullifier[0] = 0; // keep within BN254 Fr range.
    let mut identity_tag = [0u8; 32];
    identity_tag[24..].copy_from_slice(&(seed.wrapping_add(0xfeed)).to_be_bytes());
    identity_tag[0] = 0;
    RecordEntry {
        nullifier,
        identity_tag,
        class_tag,
    }
}

/// Build a `BatchSubmission` with arbitrary records, bypassing the
/// relayer's class_tag check. Records are sorted by canonical leaf
/// order before publish; IMTs are inserted in the same order.
#[allow(clippy::too_many_arguments)]
fn build_forged_batch(
    petition_id: Bytes32,
    r_root: Bytes32,
    predicate_hash: Bytes32,
    class_index: u8,
    slot: u32,
    empty_imt_root: Bytes32,
    signer_vk_hash: Bytes32,
    mut records: Vec<RecordEntry>,
    blob_carrier: &mut EIP4844BlobCarrier,
) -> BatchSubmission {
    assert_eq!(
        records.len(),
        BATCH_SIZE_MAX,
        "on-chain `_preflightBatch` enforces batchSize == BATCH_SIZE_MAX",
    );

    records.sort_by_cached_key(|r| {
        let leaf =
            hash_leaf(fr_from_be_bytes(&r.nullifier), Fr::from(r.class_tag as u64));
        fr_to_be_bytes(&leaf)
    });

    let mut running_imt = IndexedMerkleTree::new();
    let mut id_imt = IndexedMerkleTree::new();
    for r in &records {
        let leaf =
            hash_leaf(fr_from_be_bytes(&r.nullifier), Fr::from(r.class_tag as u64));
        running_imt.insert(&fr_to_be_bytes(&leaf)).unwrap();
        id_imt.insert(&r.identity_tag).unwrap();
    }
    let new_running_root = running_imt.root();
    let new_id_root = id_imt.root();

    let batch_versioned_hash = blob_carrier.publish(&records).unwrap();

    let fe_per_batch = BATCH_SIZE_MAX * FE_PER_RECORD;
    let mut bls_fields: Vec<Fr> = Vec::with_capacity(fe_per_batch);
    bls_fields.extend(records.iter().flat_map(record_to_bls_fields));
    bls_fields.resize(fe_per_batch, Fr::from(0u64));

    let public_inputs = BatchPublicInputs {
        petition_id: fr_from_be_bytes(&petition_id),
        r_root: fr_from_be_bytes(&r_root),
        predicate_hash: fr_from_be_bytes(&predicate_hash),
        class_index: Fr::from(class_index as u64),
        slot: Fr::from(slot as u64),
        batch_size: Fr::from(records.len() as u64),
        prior_running_root: fr_from_be_bytes(&empty_imt_root),
        new_running_root: fr_from_be_bytes(&new_running_root),
        prior_identity_tag_set_root: fr_from_be_bytes(&empty_imt_root),
        new_identity_tag_set_root: fr_from_be_bytes(&new_id_root),
        prior_leaf_count: Fr::from(0u64),
        new_leaf_count: Fr::from(records.len() as u64),
        batch_versioned_hash: fr_from_be_bytes(&batch_versioned_hash),
        bls_fields,
        signer_vk_hash: fr_from_be_bytes(&signer_vk_hash),
    };

    BatchSubmission {
        public_inputs,
        records,
        proof_bytes: Vec::new(),
    }
}

/// Pack a dispute envelope into the contract's `(openingsBlob,
/// proofsBlob)` layout. `openings` MUST be sorted by
/// `field_element_index`, with `positionI`'s four field elements first
/// followed by `positionJ`'s four (only the first four are used for
/// `ClassTagOutOfSet`).
fn pack_dispute_openings(openings: &[KzgOpening]) -> (Vec<u8>, Vec<u8>) {
    let mut openings_blob = Vec::with_capacity(openings.len() * 32);
    let mut proofs_blob = Vec::with_capacity(openings.len() * 48);
    for o in openings {
        openings_blob.extend_from_slice(&o.claimed_value);
        proofs_blob.extend_from_slice(&o.proof_bytes[..48]);
    }
    (openings_blob, proofs_blob)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dispute_won_class_tag_out_of_set_anvil_real() {
    let test_start = Instant::now();

    eprintln!("=== [1/10] Deploy anvil + contracts (mock verifier) ===");
    let dep = AnvilDeployment::start_and_deploy(true);
    eprintln!("  anvil endpoint:    {}", dep.endpoint);
    eprintln!("  petition registry: {:#x}", dep.petition_registry);
    eprintln!("  bounty token:      {:#x}", dep.bounty_token);

    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let chain = ChainPetitionRegistry::new(dep.provider.clone(), dep.petition_registry);

    let bounty = U256::from(1_000_000u64);
    eprintln!("=== [2/10] Fund and approve bounty ({} units) ===", bounty);
    IMockERC20::new(dep.bounty_token, &dep.provider)
        .mint(dep.deployer_addr, bounty)
        .send()
        .await
        .expect("mint")
        .get_receipt()
        .await
        .unwrap();
    IMockERC20::new(dep.bounty_token, &dep.provider)
        .approve(dep.petition_registry, bounty)
        .send()
        .await
        .expect("approve")
        .get_receipt()
        .await
        .unwrap();

    let class_a: ClassTag = 100;
    let class_b: ClassTag = 200;
    let out_of_set_tag: ClassTag = 999;
    let class_index = 2u8;
    let class_set = vec![class_a, class_b];

    eprintln!("=== [3/10] Build predicate and derive petition id ===");
    let pred = two_class_predicate(class_index, class_a, class_b);
    let pred_encoded = pred.encode().expect("encode predicate");
    let canonical = canonical_scalars(&pred_encoded).unwrap();
    // Top byte zero so the Fr roundtrip `fr_to_be_bytes(fr_from_be_bytes(x))`
    // is the identity. Otherwise the contract's stored bytes32 fields
    // disagree with the publish path's reduced-then-re-encoded fields.
    let mut salt = [0x77u8; 32];
    salt[0] = 0;
    let mut r_root = [0xabu8; 32];
    r_root[0] = 0;
    let predicate_hash_pre_id_fr =
        hash_predicate(&canonical, Fr::from(0u64), fr_from_be_bytes(&salt));
    let predicate_hash_pre_id = fr_to_be_bytes(&predicate_hash_pre_id_fr);

    let current_block = dep.provider.get_block_number().await.unwrap();
    let close_at_block = current_block + 30;

    let petition_id = derive_petition_id(
        31337,
        &dep.petition_registry.into(),
        &dep.deployer_addr.into(),
        0,
        &predicate_hash_pre_id,
        close_at_block,
    );
    let predicate_hash_fr = hash_predicate(
        &canonical,
        fr_from_be_bytes(&petition_id),
        fr_from_be_bytes(&salt),
    );
    let predicate_hash = fr_to_be_bytes(&predicate_hash_fr);

    eprintln!("=== [4/10] Register petition ===");
    let params = IPetitionRegistry::PetitionParams {
        rRoot: FixedBytes(r_root),
        predicateDef: pred_encoded.clone().into(),
        salt: FixedBytes(salt),
        classSet: class_set.clone(),
        classThresholds: vec![1u64, 1u64],
        classIndex: class_index,
        closeAtBlock: close_at_block,
        bounty,
    };
    let returned_id = chain.register(params).await.expect("register on chain");
    assert_eq!(returned_id, petition_id);
    eprintln!("  registered 0x{}", hex::encode(petition_id));

    eprintln!("=== [5/10] Forge a 6-record batch with one out-of-set tag ===");
    let empty_imt_root = {
        let imt = IndexedMerkleTree::new();
        fr_to_be_bytes(&imt.root_fr())
    };
    let signer_vk_hash_bytes = std::fs::read(
        project_root
            .join("circuits")
            .join("signer")
            .join("target")
            .join("vk_hash"),
    )
    .expect("read signer vk_hash");
    let mut signer_vk_hash: Bytes32 = [0u8; 32];
    signer_vk_hash.copy_from_slice(&signer_vk_hash_bytes);

    let mut records = vec![
        forged_record(1, class_a),
        forged_record(2, class_b),
        forged_record(3, class_a),
        forged_record(4, class_b),
        forged_record(5, class_a),
        forged_record(6, out_of_set_tag),
    ];
    // Pre-shuffle so canonical leaf sort is exercised, not preserved by accident.
    records.swap(0, 5);
    records.swap(1, 4);

    let mut blob_carrier = EIP4844BlobCarrier::new();
    let batch = build_forged_batch(
        petition_id,
        r_root,
        predicate_hash,
        class_index,
        0,
        empty_imt_root,
        signer_vk_hash,
        records,
        &mut blob_carrier,
    );
    let bad_position = batch
        .records
        .iter()
        .position(|r| r.class_tag == out_of_set_tag)
        .expect("out-of-set record must be present after sort")
        as u32;
    eprintln!(
        "  out-of-set record landed at position {} (post canonical sort)",
        bad_position
    );

    eprintln!("=== [6/10] Publish forged batch via blob tx ===");
    let bvh = fr_to_be_bytes(&batch.public_inputs.batch_versioned_hash);
    let sidecar = blob_carrier.make_sidecar(&bvh).expect("make_sidecar");
    let eval_points = canonical_eval_points();
    let (commitment, proofs_concat, _ys) = blob_carrier
        .commitment_and_per_point_proofs(&bvh, &eval_points)
        .expect("commitment_and_per_point_proofs");
    let publish_start = Instant::now();
    chain
        .publish_batch(
            batch.public_inputs.clone(),
            batch.proof_bytes,
            commitment.to_vec(),
            proofs_concat,
            sidecar,
        )
        .await
        .expect("publishBatch with mock verifier");
    eprintln!("  publishBatch confirmed in {:?}", publish_start.elapsed());
    assert_eq!(
        chain.get_batch_count(petition_id).await.unwrap(),
        1,
        "exactly one batch must be published"
    );

    eprintln!("=== [7/10] Advance chain into DisputeWindow ===");
    let target = close_at_block + 600 + 1;
    let now = dep.provider.get_block_number().await.unwrap();
    let to_mine = target.saturating_sub(now);
    dep.provider
        .raw_request::<_, ()>("anvil_mine".into(), (format!("0x{:x}", to_mine),))
        .await
        .expect("anvil_mine");

    eprintln!("=== [8/10] Disputant builds ClassTagOutOfSet envelope ===");
    let disputant = Disputant::new(blob_carrier.clone());
    let dispute_ctx = DisputeContext {
        petition_id,
        batch_versioned_hash: bvh,
        batch_index: 0,
        class_set: class_set.clone(),
    };
    let dispute = disputant
        .build_class_tag_out_of_set(&dispute_ctx, bad_position)
        .expect("build dispute");
    assert_eq!(dispute.violation_type, ViolationType::ClassTagOutOfSet);
    assert_eq!(dispute.openings.len(), 4);

    eprintln!("=== [9/10] Submit dispute on chain ===");
    let (openings_blob, proofs_blob) = pack_dispute_openings(&dispute.openings);
    let dispute_start = Instant::now();
    let event = chain
        .dispute(
            petition_id,
            dispute.batch_index,
            dispute.position_i,
            dispute.position_j.unwrap_or(0),
            dispute.violation_type as u8,
            commitment.to_vec(),
            openings_blob,
            proofs_blob,
        )
        .await
        .expect("dispute on chain");
    eprintln!("  dispute confirmed in {:?}", dispute_start.elapsed());

    eprintln!("=== [10/10] Verify rollback to empty IMT ===");
    assert_eq!(event.petitionId, FixedBytes(petition_id));
    assert_eq!(event.batchIndex, 0);
    assert_eq!(
        event.newRunningRoot,
        FixedBytes(empty_imt_root),
        "running root must roll back to empty IMT (no active predecessor)",
    );
    assert_eq!(
        event.newIdentityTagSetRoot,
        FixedBytes(empty_imt_root),
        "identity-tag set root must roll back to empty IMT",
    );
    assert_eq!(event.newLeafCount, 0, "leaf count must roll back to 0");
    // The repudiated batch stays in storage (`getBatchCount` is unaffected);
    // only its `state` flips to Repudiated.
    assert_eq!(
        chain.get_batch_count(petition_id).await.unwrap(),
        1,
        "repudiation does not pop the batch array",
    );

    eprintln!(
        "=== Dispute-won path complete in {:?} ===",
        test_start.elapsed()
    );
}

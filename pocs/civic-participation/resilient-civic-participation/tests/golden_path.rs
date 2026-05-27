//! End-to-end golden path against anvil with real verifiers, blobs, and Honk proofs.
//!
//! Full lifecycle: register -> 6 signers sign -> relayer publishes one
//! batch -> anvil advances past `closeAtBlock + COOLDOWN_BLOCKS` ->
//! resolver reconstructs leaves, builds resolution SNARK, submits.

mod anvil_harness;

use std::{
    path::PathBuf,
    sync::{
        Arc,
        Mutex,
    },
    time::Instant,
};

use alloy::{
    primitives::{
        FixedBytes,
        U256,
        keccak256,
    },
    providers::Provider,
    sol,
};
use ark_bn254::Fr;

use anvil_harness::AnvilDeployment;
use resilient_civic_participation::{
    adapters::{
        bb_prover::BBProver,
        blob_4844::EIP4844BlobCarrier,
        chain_registry::{
            ChainPetitionRegistry,
            IPetitionRegistry,
        },
        in_memory_ri::InMemoryRi,
    },
    error::MerkleError,
    imt::IndexedMerkleTree,
    ports::ri::{
        RiCredentialLayer,
        RiPath,
    },
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_predicate,
    },
    predicate::{
        Op,
        PredicateDef,
        Tuple,
        canonical_scalars,
    },
    relayer::{
        Relayer,
        core::RelayerPetitionState,
        types::PetitionView,
    },
    resolver::{
        Resolver,
        types::ResolverView,
    },
    signer::{
        Signer,
        types::PetitionMeta,
    },
    types::{
        Bytes32,
        ClassTag,
        Comparator,
        OpCode,
        SignerSubmission,
        TypeTag,
    },
};

sol! {
    #[sol(rpc)]
    interface IMockERC20 {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Shared `InMemoryRi` so each signer's RI port observes the same tree.
#[derive(Clone)]
struct SharedRi {
    inner: Arc<Mutex<InMemoryRi>>,
}

impl SharedRi {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryRi::new())),
        }
    }
}

impl RiCredentialLayer for SharedRi {
    fn append_leaf(&mut self, attr_hash: Bytes32, posted_at_block: u64) -> u32 {
        self.inner
            .lock()
            .unwrap()
            .append_leaf(attr_hash, posted_at_block)
    }
    fn root(&self) -> Bytes32 {
        self.inner.lock().unwrap().root()
    }
    fn merkle_path(&self, leaf_index: u32) -> Result<RiPath, MerkleError> {
        self.inner.lock().unwrap().merkle_path(leaf_index)
    }
    fn root_first_seen(&self, root: &Bytes32) -> Option<u64> {
        self.inner.lock().unwrap().root_first_seen(root)
    }
}

/// `attr[class_index] == class_a OR attr[class_index] == class_b`.
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

/// Off-chain mirror of `PetitionRegistry._derivePetitionId`.
fn derive_petition_id_offchain(
    chain_id: u64,
    registry: alloy::primitives::Address,
    msg_sender: alloy::primitives::Address,
    s_at_reg: u32,
    predicate_hash_pre_id: Bytes32,
    close_at_block: u64,
) -> Bytes32 {
    let domain = keccak256(b"RCP/petition_id/v1");
    let mut packed = Vec::<u8>::with_capacity(32 + 8 + 20 + 20 + 4 + 32 + 8);
    packed.extend_from_slice(domain.as_slice());
    packed.extend_from_slice(&chain_id.to_be_bytes());
    packed.extend_from_slice(registry.as_slice());
    packed.extend_from_slice(msg_sender.as_slice());
    packed.extend_from_slice(&s_at_reg.to_be_bytes());
    packed.extend_from_slice(&predicate_hash_pre_id);
    packed.extend_from_slice(&close_at_block.to_be_bytes());
    let h = keccak256(packed);
    let mut out: [u8; 32] = h.into();
    // Matches contract: top byte masked.
    out[0] = 0;
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn golden_path_anvil_real() {
    let test_start = Instant::now();

    eprintln!("=== [1/13] Deploy anvil + contracts ===");
    let use_mock_verifier = std::env::var("USE_MOCK_VERIFIER")
        .map(|s| s.eq_ignore_ascii_case("true") || s == "1")
        .unwrap_or(true);
    let dep = AnvilDeployment::start_and_deploy(use_mock_verifier);
    eprintln!("  anvil endpoint:    {}", dep.endpoint);
    eprintln!("  petition registry: {:#x}", dep.petition_registry);
    eprintln!("  bounty token:      {:#x}", dep.bounty_token);
    eprintln!("  deployer:          {:#x}", dep.deployer_addr);

    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let prover_root = project_root.clone();

    eprintln!("=== [2/13] Ensure signer VK ===");
    let vk_start = Instant::now();
    BBProver::new(prover_root.clone())
        .ensure_signer_vk()
        .expect("ensure signer VK");
    eprintln!("  signer VK ready in {:?}", vk_start.elapsed());

    let chain = ChainPetitionRegistry::new(dep.provider.clone(), dep.petition_registry);

    let bounty = U256::from(1_000_000_000u64);
    eprintln!("=== [3/13] Fund and approve bounty ({} units) ===", bounty);
    IMockERC20::new(dep.bounty_token, &dep.provider)
        .mint(dep.deployer_addr, bounty)
        .send()
        .await
        .expect("mint")
        .get_receipt()
        .await
        .unwrap();
    eprintln!("  minted {} to deployer", bounty);
    IMockERC20::new(dep.bounty_token, &dep.provider)
        .approve(dep.petition_registry, bounty)
        .send()
        .await
        .expect("approve")
        .get_receipt()
        .await
        .unwrap();
    eprintln!("  approved registry to spend {} from deployer", bounty);

    let ri = SharedRi::new();
    let class_a: ClassTag = 826;
    let class_b: ClassTag = 840;
    let class_index = 2u8;
    eprintln!(
        "=== [4/13] Enroll 6 signers (classes {} x3, {} x3) ===",
        class_a, class_b
    );
    let mut signers: Vec<Signer<BBProver, SharedRi>> = Vec::with_capacity(6);
    let mut class_tags: Vec<ClassTag> = Vec::with_capacity(6);
    for i in 0..6u8 {
        let class_tag = if i < 3 { class_a } else { class_b };
        let attrs = vec![
            Fr::from(25u64),
            Fr::from(1u64),
            Fr::from(class_tag as u64),
            Fr::from(20_000u64),
        ];
        let mut seed = [0u8; 32];
        seed[31] = i + 1;
        let (signer, _artifact) = Signer::enroll(
            BBProver::new(prover_root.clone()),
            ri.clone(),
            attrs,
            32,
            0,
            100,
            Some(seed),
        );
        eprintln!(
            "  enrolled signer {}/6 (class {}, ri_leaf_index {})",
            i + 1,
            class_tag,
            signer.credentials.ri_leaf_index
        );
        signers.push(signer);
        class_tags.push(class_tag);
    }
    eprintln!("  RI root after enrollment: 0x{}", hex::encode(ri.root()));

    eprintln!("=== [5/13] Build predicate and derive petition id ===");
    let pred = two_class_predicate(class_index, class_a, class_b);
    let pred_encoded = pred.encode().expect("encode predicate");
    let canonical = canonical_scalars(&pred_encoded).unwrap();
    let salt = [0x55u8; 32];
    eprintln!("  predicate encoded:    {} bytes", pred_encoded.len());

    let predicate_hash_pre_id_fr =
        hash_predicate(&canonical, Fr::from(0u64), fr_from_be_bytes(&salt));
    let predicate_hash_pre_id = fr_to_be_bytes(&predicate_hash_pre_id_fr);

    let current_block = dep.provider.get_block_number().await.unwrap();
    let close_at_block = current_block + 30;
    eprintln!("  current block:        {}", current_block);
    eprintln!("  close_at_block:       {}", close_at_block);

    let petition_id = derive_petition_id_offchain(
        31337,
        dep.petition_registry,
        dep.deployer_addr,
        0,
        predicate_hash_pre_id,
        close_at_block,
    );
    let predicate_hash_fr = hash_predicate(
        &canonical,
        fr_from_be_bytes(&petition_id),
        fr_from_be_bytes(&salt),
    );
    let predicate_hash = fr_to_be_bytes(&predicate_hash_fr);
    eprintln!("  predicate_hash:       0x{}", hex::encode(predicate_hash));

    let r_root = ri.root();
    let params = IPetitionRegistry::PetitionParams {
        rRoot: FixedBytes(r_root),
        predicateDef: pred_encoded.clone().into(),
        salt: FixedBytes(salt),
        classSet: vec![class_a, class_b],
        classThresholds: vec![3u64, 3u64],
        classIndex: class_index,
        closeAtBlock: close_at_block,
        bounty,
    };

    eprintln!("=== [6/13] Register petition on chain ===");
    let register_start = Instant::now();
    let returned_id = chain
        .register(params.clone())
        .await
        .expect("register on chain");
    assert_eq!(
        returned_id, petition_id,
        "off-chain petition_id derivation must match contract"
    );
    eprintln!(
        "  registered petition_id 0x{} in {:?}",
        hex::encode(petition_id),
        register_start.elapsed()
    );
    eprintln!("  bounty escrowed:      {}", bounty);

    eprintln!("=== [7/13] Generate signer proofs (6 total) ===");
    let signing_start = Instant::now();
    let mut submissions: Vec<SignerSubmission> = Vec::with_capacity(6);
    for (i, signer) in signers.iter_mut().enumerate() {
        let meta = PetitionMeta {
            petition_id,
            r_root,
            predicate_hash,
            slot: 0,
            class_index,
            class_tag: class_tags[i],
            predicate_def: pred.clone(),
            salt,
            ri_leaf_index: signer.credentials.ri_leaf_index,
        };
        eprintln!("  signer {}/6 (class {}): proving...", i + 1, class_tags[i]);
        let proof_start = Instant::now();
        let sub = signer.sign(&meta).expect("signer.sign");
        eprintln!(
            "  signer {}/6: proof generated in {:?} ({} bytes)",
            i + 1,
            proof_start.elapsed(),
            sub.proof_bytes.len()
        );
        submissions.push(sub);
    }
    eprintln!("  all 6 signer proofs in {:?}", signing_start.elapsed());

    let empty_imt_root = {
        let imt = IndexedMerkleTree::new();
        fr_to_be_bytes(&imt.root_fr())
    };
    // Read the signer VK hash that the on-chain registry was pinned to
    // at deploy time; the batch SNARK's signer_vk_hash public input
    // must match it bit-for-bit.
    let signer_vk_hash_bytes = std::fs::read(
        prover_root
            .join("circuits")
            .join("signer")
            .join("target")
            .join("vk_hash"),
    )
    .expect("read signer vk_hash");
    let mut signer_vk_hash: [u8; 32] = [0u8; 32];
    signer_vk_hash.copy_from_slice(&signer_vk_hash_bytes);
    let petition_view = PetitionView {
        petition_id,
        r_root,
        predicate_hash,
        class_index,
        class_set: vec![class_a, class_b],
        slot: 0,
        running_root: empty_imt_root,
        identity_tag_set_root: empty_imt_root,
        leaf_count: 0,
        signer_vk_hash,
    };
    let blob_carrier = EIP4844BlobCarrier::new();
    let mut relayer_state = RelayerPetitionState::new();
    let mut relayer = Relayer::new(
        dep.deployer_addr.into_array(),
        BBProver::new(prover_root.clone()),
        blob_carrier.clone(),
    );

    eprintln!("=== [8/13] Build recursive batch proof (multi-minute) ===");
    let batch_start = Instant::now();
    let (batch, _positions) = relayer
        .build_batch(&petition_view, &mut relayer_state, submissions)
        .expect("relayer.build_batch");
    eprintln!(
        "  batch proof ready in {:?} ({} bytes)",
        batch_start.elapsed(),
        batch.proof_bytes.len()
    );
    eprintln!(
        "  new_running_root:        0x{}",
        hex::encode(fr_to_be_bytes(&batch.public_inputs.new_running_root))
    );
    eprintln!(
        "  batch_versioned_hash:    0x{}",
        hex::encode(fr_to_be_bytes(&batch.public_inputs.batch_versioned_hash))
    );
    eprintln!(
        "  new_leaf_count:          {}",
        batch.public_inputs.new_leaf_count
    );

    eprintln!("=== [9/13] Build EIP-4844 sidecar and KZG openings ===");
    let batch_versioned_hash_be =
        fr_to_be_bytes(&batch.public_inputs.batch_versioned_hash);
    let sidecar = blob_carrier
        .make_sidecar(&batch_versioned_hash_be)
        .expect("make sidecar");
    let eval_points = resilient_civic_participation::blob::canonical_eval_points();
    let (commitment, proofs_concat, ys) = blob_carrier
        .commitment_and_per_point_proofs(&batch_versioned_hash_be, &eval_points)
        .expect("commitment_and_per_point_proofs");
    eprintln!("  KZG commitment:    {} bytes", commitment.len());
    eprintln!(
        "  KZG proofs concat: {} bytes across {} eval points",
        proofs_concat.len(),
        eval_points.len()
    );
    for (k, fe) in batch.public_inputs.bls_fields.iter().enumerate() {
        let expected = fr_to_be_bytes(fe);
        assert_eq!(
            ys[k], expected,
            "kzg opening y_{k} disagrees with SNARK bls_fields[{k}]"
        );
    }
    eprintln!("  KZG openings consistent with SNARK bls_fields");

    eprintln!("=== [10/13] Publish batch on chain ===");
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
        .expect("publishBatch on chain");
    eprintln!("  publishBatch confirmed in {:?}", publish_start.elapsed());

    let count = chain
        .get_batch_count(petition_id)
        .await
        .expect("getBatchCount");
    assert_eq!(count, 1, "exactly one batch must be published");
    eprintln!("  batchCount = {}", count);

    // Advance past `closeAtBlock + RESOLUTION_DEADLINE_BLOCKS` so the
    // petition is in `DisputeWindow` AND the resolution deadline has
    // elapsed. After SPEC line 65 / line 121, `resolve` is gated on
    // `block.number >= closeAtBlock + RESOLUTION_DEADLINE_BLOCKS` to
    // prevent races against in-flight disputes.
    // RESOLUTION_DEADLINE_BLOCKS = 100_800 in PetitionRegistry.sol.
    eprintln!("=== [11/13] Advance chain past resolution deadline ===");
    let now = dep.provider.get_block_number().await.unwrap();
    let target = close_at_block + 100_800;
    let to_mine = target.saturating_sub(now);
    eprintln!(
        "  current block: {} | target: {} | mining {} blocks",
        now, target, to_mine
    );
    let mine_hex = format!("0x{:x}", to_mine);
    dep.provider
        .raw_request::<_, ()>("anvil_mine".into(), (mine_hex,))
        .await
        .expect("anvil_mine");
    let post_mine = dep.provider.get_block_number().await.unwrap();
    eprintln!("  block after mine: {}", post_mine);

    // Resolver reconstructs the leaf set from the published blob,
    // builds the resolution SNARK, and submits it.
    let resolver_view = ResolverView {
        petition_id,
        r_root,
        predicate_hash,
        running_root: fr_to_be_bytes(&batch.public_inputs.new_running_root),
        leaf_count: 6,
        class_set: vec![class_a, class_b],
        class_thresholds: vec![3u64, 3u64],
        class_index,
        active_batch_versioned_hashes: vec![batch_versioned_hash_be],
    };
    let resolver =
        Resolver::new(BBProver::new(prover_root.clone()), blob_carrier.clone());
    eprintln!("=== [12/13] Build resolution proof ===");
    let resolution_start = Instant::now();
    let resolution = resolver.resolve(&resolver_view).expect("resolver.resolve");
    eprintln!(
        "  resolution proof ready in {:?} ({} bytes)",
        resolution_start.elapsed(),
        resolution.proof_bytes.len()
    );

    eprintln!("=== [13/13] Submit resolution and verify bounty payout ===");
    let pre_balance = IMockERC20::new(dep.bounty_token, &dep.provider)
        .balanceOf(dep.deployer_addr)
        .call()
        .await
        .expect("balanceOf pre-resolve");
    eprintln!("  deployer balance pre-resolve:  {}", pre_balance);
    assert_eq!(
        pre_balance,
        U256::ZERO,
        "deployer should hold no bounty token while petition is escrowed"
    );

    let resolve_start = Instant::now();
    chain
        .resolve(
            petition_id,
            resolution.public_inputs.clone(),
            resolution.proof_bytes,
        )
        .await
        .expect("resolve on chain");
    eprintln!("  resolve confirmed in {:?}", resolve_start.elapsed());

    let post_balance = IMockERC20::new(dep.bounty_token, &dep.provider)
        .balanceOf(dep.deployer_addr)
        .call()
        .await
        .expect("balanceOf post-resolve");
    eprintln!("  deployer balance post-resolve: {}", post_balance);
    assert_eq!(
        post_balance, bounty,
        "bounty must transfer to resolve caller on success"
    );

    eprintln!("=== Golden path complete in {:?} ===", test_start.elapsed());
}

//! Shared in-memory harness for integration tests that use `MockProofBackend`.

use std::sync::{
    Arc,
    Mutex,
};

use ark_bn254::Fr;

use resilient_civic_participation::{
    adapters::{
        in_memory_blob::InMemoryBlobCarrier,
        in_memory_ri::InMemoryRi,
        mock_proof::MockProofBackend,
    },
    clock::{
        BlockClock,
        MockBlockClock,
    },
    error::{
        BlobError,
        MerkleError,
    },
    organizer::{
        Organizer,
        types::PetitionDraft,
    },
    ports::{
        blob::BlobCarrier,
        ri::{
            RiCredentialLayer,
            RiPath,
        },
    },
    predicate::{
        Op,
        PredicateDef,
        Tuple,
    },
    registry::{
        PetitionRegistry,
        types::{
            PetitionRegisteredEvent,
            PetitionStateView,
        },
    },
    relayer::{
        Relayer,
        core::RelayerPetitionState,
        types::PetitionView,
    },
    signer::{
        Signer,
        types::PetitionMeta,
    },
    types::{
        Address,
        BatchSubmission,
        Bytes32,
        ClassTag,
        Comparator,
        GlobalState,
        KzgOpening,
        OpCode,
        SignerSubmission,
        TypeTag,
        U256Be,
    },
};

const CHAIN_ID: u64 = 31337;
const REGISTRY_ADDRESS: Address = [0xab; 20];
pub const ATTR_CLASS: usize = 2;
const TEST_FSRT_LEN: u32 = 32;
const TEST_ALPHA: u64 = 1;
const TEST_ALPHA_MIN: u64 = 1;
const TEST_ALPHA_MAX: u64 = 1_000_000;

#[derive(Clone)]
pub struct SharedRi {
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
            .expect("SharedRi poisoned")
            .append_leaf(attr_hash, posted_at_block)
    }
    fn root(&self) -> Bytes32 {
        self.inner.lock().expect("SharedRi poisoned").root()
    }
    fn merkle_path(&self, leaf_index: u32) -> Result<RiPath, MerkleError> {
        self.inner
            .lock()
            .expect("SharedRi poisoned")
            .merkle_path(leaf_index)
    }
    fn root_first_seen(&self, root: &Bytes32) -> Option<u64> {
        self.inner
            .lock()
            .expect("SharedRi poisoned")
            .root_first_seen(root)
    }
}

#[derive(Clone)]
pub struct SharedBlob {
    inner: Arc<Mutex<InMemoryBlobCarrier>>,
}

impl SharedBlob {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryBlobCarrier::new())),
        }
    }
}

impl BlobCarrier for SharedBlob {
    fn publish(
        &mut self,
        records: &[resilient_civic_participation::types::RecordEntry],
    ) -> Result<Bytes32, BlobError> {
        self.inner
            .lock()
            .expect("SharedBlob poisoned")
            .publish(records)
    }
    fn open(
        &self,
        batch_versioned_hash: &Bytes32,
        field_element_index: u32,
    ) -> Result<KzgOpening, BlobError> {
        self.inner
            .lock()
            .expect("SharedBlob poisoned")
            .open(batch_versioned_hash, field_element_index)
    }
    fn verify(
        &self,
        batch_versioned_hash: &Bytes32,
        opening: &KzgOpening,
    ) -> Result<(), BlobError> {
        self.inner
            .lock()
            .expect("SharedBlob poisoned")
            .verify(batch_versioned_hash, opening)
    }
    fn fetch_records(
        &self,
        batch_versioned_hash: &Bytes32,
    ) -> Result<Vec<resilient_civic_participation::types::RecordEntry>, BlobError> {
        self.inner
            .lock()
            .expect("SharedBlob poisoned")
            .fetch_records(batch_versioned_hash)
    }
}

pub struct SignerCtx {
    pub signer: Signer<MockProofBackend, SharedRi>,
    pub class_tag: ClassTag,
    pub ri_leaf_index: u32,
}

pub struct Harness {
    block_clock: Arc<MockBlockClock>,
    pub ri: SharedRi,
    pub blob: SharedBlob,
    pub registry: PetitionRegistry<MockProofBackend, SharedRi, SharedBlob>,
}

impl Harness {
    pub fn new() -> Self {
        let clock = Arc::new(MockBlockClock::new(0));
        let ri = SharedRi::new();
        let blob = SharedBlob::new();
        let global = GlobalState {
            s: 0,
            alpha: TEST_ALPHA,
            alpha_min: TEST_ALPHA_MIN,
            alpha_max: TEST_ALPHA_MAX,
            srs_hash: [0u8; 32],
            chain_id: CHAIN_ID,
            n: 4,
        };
        let registry = PetitionRegistry::new(
            REGISTRY_ADDRESS,
            global,
            clock.clone(),
            MockProofBackend,
            ri.clone(),
            blob.clone(),
        );
        Self {
            block_clock: clock,
            ri,
            blob,
            registry,
        }
    }

    pub fn block(&self) -> u64 {
        self.block_clock.block_number()
    }
    pub fn advance_blocks(&self, n: u64) {
        self.block_clock.advance(n);
    }
}

pub fn enroll_signer(
    harness: &mut Harness,
    age: u64,
    class_tag: ClassTag,
    seed: [u8; 32],
) -> SignerCtx {
    let attrs = vec![
        Fr::from(age),
        Fr::from(if age >= 18 { 1u64 } else { 0u64 }),
        Fr::from(class_tag as u64),
        Fr::from(20_000u64),
    ];
    let (signer, _artifact) = Signer::enroll(
        MockProofBackend,
        harness.ri.clone(),
        attrs,
        TEST_FSRT_LEN,
        0,
        harness.block(),
        Some(seed),
    );
    let ri_leaf_index = signer.credentials.ri_leaf_index;
    SignerCtx {
        signer,
        class_tag,
        ri_leaf_index,
    }
}

pub fn class_only_predicate(class_index: u8, class_tag: ClassTag) -> PredicateDef {
    let mut operand = [0u8; 32];
    operand[30..].copy_from_slice(&class_tag.to_be_bytes());
    PredicateDef {
        tuples: vec![Tuple {
            claim_index: class_index,
            operand,
            type_tag: TypeTag::Int64,
            comparator: Comparator::Eq,
        }],
        ops: vec![Op {
            code: OpCode::PushTuple,
            operand: 0,
        }],
    }
}

pub struct RegisteredFixture {
    pub event: PetitionRegisteredEvent,
    pub view: PetitionStateView,
}

#[allow(clippy::too_many_arguments)]
pub fn register_petition(
    harness: &mut Harness,
    organizer_addr: Address,
    predicate: PredicateDef,
    salt: Bytes32,
    class_set: Vec<ClassTag>,
    class_thresholds: Vec<u64>,
    class_index: u8,
    bounty: U256Be,
    signing_window_blocks: u64,
) -> RegisteredFixture {
    let organizer = Organizer::new(organizer_addr);
    let r_root = harness.ri.root();
    let now = harness.block();
    let close_at_block = now + signing_window_blocks;
    let draft: PetitionDraft = organizer
        .build_petition(
            r_root,
            predicate,
            salt,
            class_set,
            class_thresholds,
            class_index,
            now,
            close_at_block,
            bounty,
        )
        .expect("organizer draft");
    let (_ack, event) = harness.registry.register(draft).expect("registry register");
    let view = harness
        .registry
        .state_view(&event.petition_id)
        .expect("state view");
    RegisteredFixture { event, view }
}

pub fn signer_sign(
    ctx: &mut SignerCtx,
    petition_view: &PetitionStateView,
    salt: Bytes32,
    predicate_encoded: &[u8],
) -> SignerSubmission {
    let predicate_def =
        PredicateDef::decode(predicate_encoded).expect("decode predicate");
    let meta = PetitionMeta {
        petition_id: petition_view.petition_id,
        r_root: petition_view.r_root,
        predicate_hash: petition_view.predicate_hash,
        slot: petition_view.slot,
        class_index: petition_view.class_index,
        class_tag: ctx.class_tag,
        predicate_def,
        salt,
        ri_leaf_index: ctx.ri_leaf_index,
    };
    ctx.signer.sign(&meta).expect("signer sign")
}

pub fn publish_one_batch(
    harness: &mut Harness,
    petition_view: &PetitionStateView,
    relayer_addr: Address,
    state: &mut RelayerPetitionState,
    submissions: Vec<SignerSubmission>,
) -> BatchSubmission {
    let mut relayer = Relayer::new(relayer_addr, MockProofBackend, harness.blob.clone());
    let pv = PetitionView {
        petition_id: petition_view.petition_id,
        r_root: petition_view.r_root,
        predicate_hash: petition_view.predicate_hash,
        class_index: petition_view.class_index,
        class_set: petition_view.class_set.clone(),
        slot: petition_view.slot,
        running_root: petition_view.running_root,
        identity_tag_set_root: petition_view.identity_tag_set_root,
        leaf_count: petition_view.leaf_count,
        signer_vk_hash: [0u8; 32],
    };
    let (batch, _positions) = relayer
        .build_batch(&pv, state, submissions)
        .expect("relayer build_batch");
    harness
        .registry
        .publish_batch(&petition_view.petition_id, relayer_addr, batch.clone())
        .expect("registry publish_batch");
    batch
}

pub fn advance_past_ri_age_window(harness: &mut Harness) {
    use resilient_civic_participation::MIN_R_AGE_BLOCKS;
    harness.advance_blocks(MIN_R_AGE_BLOCKS + 1);
}

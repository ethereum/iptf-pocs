//! Petition Registry state machine (Rust mirror of the Solidity contract).

use std::{
    collections::HashMap,
    sync::Arc,
};

use ark_bn254::Fr;
use ark_ff::Zero;

use crate::{
    BATCH_SIZE_MAX,
    COOLDOWN_BLOCKS,
    FSRT_SLOT_COUNT,
    MARK_UNRESOLVED_GRACE_BLOCKS,
    MIN_R_AGE_BLOCKS,
    RESOLUTION_DEADLINE_BLOCKS,
    blob::compute_batch_versioned_hash,
    clock::BlockClock,
    disputant::leaf_ordering_violated,
    error::ProofError,
    imt::IndexedMerkleTree,
    organizer::types::PetitionDraft,
    ports::{
        blob::BlobCarrier,
        imt::ImtStore,
        proof::ProofBackend,
        ri::RiCredentialLayer,
    },
    poseidon::{
        derive_petition_id,
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_leaf,
        hash_predicate,
    },
    predicate::canonical_scalars,
    registry::{
        error::{
            BatchPriorMismatch,
            RegistryError,
        },
        types::{
            AlphaUpdatedEvent,
            BatchPublishedEvent,
            BatchRepudiatedEvent,
            BountyPaidEvent,
            BountyRefundedEvent,
            PetitionRegisteredEvent,
            PetitionResolvedEvent,
            PetitionStateView,
            PetitionUnresolvedEvent,
            RegisteredPetition,
            TOMBSTONE_MARKER,
        },
    },
    types::{
        Address,
        BatchRecord,
        BatchState,
        BatchSubmission,
        Bytes32,
        Dispute,
        GlobalState,
        PetitionId,
        PetitionRecord,
        PetitionState,
        ResolutionSubmission,
        U256Be,
        ViolationType,
    },
};

/// Per-batch on-chain state; payload lives on the blob carrier.
#[derive(Debug, Clone)]
struct InternalBatch {
    record: BatchRecord,
}

/// Per-petition cached state; IMTs are recomputed on insert so the mock backend cannot mask a bad relayer.
struct PetitionEntry {
    record: PetitionRecord,
    batches: Vec<InternalBatch>,
    running_imt: IndexedMerkleTree,
    identity_tag_imt: IndexedMerkleTree,
}

pub struct PetitionRegistry<P, R, B>
where
    P: ProofBackend,
    R: RiCredentialLayer,
    B: BlobCarrier,
{
    pub address: Address,
    pub global: GlobalState,
    pub clock: Arc<dyn BlockClock>,
    pub proof_backend: P,
    pub ri: R,
    pub blob_carrier: B,
    petitions: HashMap<PetitionId, PetitionEntry>,
    /// Initial empty-IMT root used as the first `prior_running_root`.
    empty_imt_root: Bytes32,
}

impl<P, R, B> PetitionRegistry<P, R, B>
where
    P: ProofBackend,
    R: RiCredentialLayer,
    B: BlobCarrier,
{
    pub fn new(
        address: Address,
        global: GlobalState,
        clock: Arc<dyn BlockClock>,
        proof_backend: P,
        ri: R,
        blob_carrier: B,
    ) -> Self {
        let empty = IndexedMerkleTree::new();
        Self {
            address,
            global,
            clock,
            proof_backend,
            ri,
            blob_carrier,
            petitions: HashMap::new(),
            empty_imt_root: empty.root(),
        }
    }

    fn now(&self) -> u64 {
        self.clock.block_number()
    }

    /// Advance the petition lifecycle based on the current block.
    fn step_state(
        &mut self,
        petition_id: &PetitionId,
    ) -> Result<PetitionState, RegistryError> {
        let block = self.now();
        let entry = self.petition_mut(petition_id)?;
        loop {
            let next = match entry.record.state {
                PetitionState::Registered => Some(PetitionState::SigningOpen),
                PetitionState::SigningOpen if block >= entry.record.close_at_block => {
                    Some(PetitionState::SigningClosed)
                }
                PetitionState::SigningClosed => Some(PetitionState::Cooldown),
                PetitionState::Cooldown
                    if block >= entry.record.close_at_block + COOLDOWN_BLOCKS =>
                {
                    Some(PetitionState::DisputeWindow)
                }
                _ => None,
            };
            if let Some(next) = next {
                entry.record.state = next;
            } else {
                break;
            }
        }
        Ok(entry.record.state)
    }

    fn petition(&self, id: &PetitionId) -> Result<&PetitionEntry, RegistryError> {
        self.petitions.get(id).ok_or(RegistryError::UnknownPetition)
    }

    fn petition_mut(
        &mut self,
        id: &PetitionId,
    ) -> Result<&mut PetitionEntry, RegistryError> {
        self.petitions
            .get_mut(id)
            .ok_or(RegistryError::UnknownPetition)
    }

    /// Read-side view for Organizers, Relayers, Disputants, and Resolvers.
    pub fn state_view(
        &self,
        id: &PetitionId,
    ) -> Result<PetitionStateView, RegistryError> {
        let entry = self.petition(id)?;
        Ok(PetitionStateView {
            petition_id: entry.record.petition_id,
            r_root: entry.record.r_root,
            predicate_hash: entry.record.predicate_hash,
            class_set: entry.record.class_set.clone(),
            class_thresholds: entry.record.class_thresholds.clone(),
            class_index: entry.record.class_index,
            slot: entry.record.slot,
            running_root: entry.record.running_root,
            identity_tag_set_root: entry.record.identity_tag_set_root,
            leaf_count: entry.record.leaf_count,
        })
    }

    pub fn current_state(&self, id: &PetitionId) -> Result<PetitionState, RegistryError> {
        Ok(self.petition(id)?.record.state)
    }

    pub fn active_batch_versioned_hashes(
        &self,
        id: &PetitionId,
    ) -> Result<Vec<Bytes32>, RegistryError> {
        let entry = self.petition(id)?;
        Ok(entry
            .batches
            .iter()
            .filter(|b| b.record.state == BatchState::Active)
            .map(|b| b.record.batch_versioned_hash)
            .collect())
    }

    /// Register a petition; returns the `PetitionRegisteredEvent`.
    pub fn register(
        &mut self,
        draft: PetitionDraft,
    ) -> Result<(RegisteredPetition, PetitionRegisteredEvent), RegistryError> {
        draft.predicate_def.validate()?;
        // Structural checks first; predicate-binding lookup last so its
        // error surface is not masked by an empty class_set.
        if draft.class_set.is_empty() {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::Malformed(
                    "class_set must be non-empty".into(),
                ),
            ));
        }
        if draft.class_thresholds.len() != draft.class_set.len() {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::Malformed(
                    "class_thresholds.len() != class_set.len()".into(),
                ),
            ));
        }
        // Zero thresholds make `b_per_class[i]` trivially true and collapse `B_min` to zero.
        if draft.class_thresholds.contains(&0) {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::Malformed(
                    "every class_thresholds[i] must be >= 1".into(),
                ),
            ));
        }
        if !draft.class_set.windows(2).all(|w| w[0] < w[1]) {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::Malformed(
                    "class_set must be strictly increasing".into(),
                ),
            ));
        }
        if (draft.class_index as usize) >= self.global.n as usize {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::Malformed(format!(
                    "class_index {} >= n ({})",
                    draft.class_index, self.global.n
                )),
            ));
        }
        let operand = draft
            .predicate_def
            .find_class_binding_operand(draft.class_index)?;
        if !draft.class_set.contains(&operand) {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::MissingClassBinding,
            ));
        }

        let root_first_seen =
            self.ri.root_first_seen(&draft.r_root).ok_or_else(|| {
                RegistryError::Predicate(crate::error::PredicateError::Malformed(
                    "R is not a known RI root".into(),
                ))
            })?;
        let now = self.now();
        if now < root_first_seen || now - root_first_seen < MIN_R_AGE_BLOCKS {
            return Err(RegistryError::RRootTooYoung);
        }
        if draft.close_at_block <= now {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::Malformed(
                    "close_at_block must be in the future".into(),
                ),
            ));
        }
        if draft.close_at_block - now > crate::MAX_SIGNING_WINDOW_BLOCKS {
            return Err(RegistryError::Predicate(
                crate::error::PredicateError::Malformed(
                    "signing window exceeds 11.5 days".into(),
                ),
            ));
        }

        // Derive petition_id using pre-id predicate hash (petition_id = 0).
        let encoded = draft.predicate_def.encode()?;
        let canonical = canonical_scalars(&encoded)?;
        let pre_id_hash =
            hash_predicate(&canonical, Fr::from(0u64), fr_from_be_bytes(&draft.salt));
        let pre_id_hash_be = fr_to_be_bytes(&pre_id_hash);
        let s_at_registration = self.global.s;
        if s_at_registration >= FSRT_SLOT_COUNT {
            return Err(RegistryError::SlotCounterExhausted(s_at_registration));
        }
        let petition_id = derive_petition_id(
            self.global.chain_id,
            &self.address,
            &draft.organizer,
            s_at_registration,
            &pre_id_hash_be,
            draft.close_at_block,
        );
        if self.petitions.contains_key(&petition_id) {
            return Err(RegistryError::DuplicatePetition);
        }
        let predicate_hash = hash_predicate(
            &canonical,
            fr_from_be_bytes(&petition_id),
            fr_from_be_bytes(&draft.salt),
        );
        let predicate_hash_be = fr_to_be_bytes(&predicate_hash);

        if !(self.global.alpha_min..=self.global.alpha_max).contains(&self.global.alpha) {
            return Err(RegistryError::AlphaOutOfBounds {
                alpha: self.global.alpha,
                min: self.global.alpha_min,
                max: self.global.alpha_max,
            });
        }
        let alpha_at_registration = self.global.alpha;
        // u128 arithmetic prevents u64 overflow silently collapsing the bounty floor.
        let threshold_sum: u128 = draft
            .class_thresholds
            .iter()
            .try_fold(0u128, |acc, t| acc.checked_add(*t as u128))
            .ok_or_else(|| {
                RegistryError::Predicate(crate::error::PredicateError::Malformed(
                    "class_thresholds sum overflow".into(),
                ))
            })?;
        let n_expected: u128 = threshold_sum.checked_mul(10).ok_or_else(|| {
            RegistryError::Predicate(crate::error::PredicateError::Malformed(
                "N_expected overflow".into(),
            ))
        })?;
        let predicate_op_count: u128 = draft.predicate_def.op_count() as u128;
        let b_min: u128 = (alpha_at_registration as u128)
            .checked_mul(n_expected)
            .and_then(|x| x.checked_mul(predicate_op_count))
            .ok_or_else(|| {
                RegistryError::Predicate(crate::error::PredicateError::Malformed(
                    "B_min overflow".into(),
                ))
            })?;
        let bounty_u128 = u256_to_u128(&draft.bounty)?;
        if bounty_u128 < b_min {
            return Err(RegistryError::BountyBelowMinimum {
                bounty: bounty_u128,
                min: b_min,
            });
        }

        let slot = s_at_registration;
        self.global.s = self
            .global
            .s
            .checked_add(1)
            .ok_or(RegistryError::SlotCounterExhausted(s_at_registration))?;

        let petition_record = PetitionRecord {
            petition_id,
            slot,
            r_root: draft.r_root,
            predicate_def: encoded,
            predicate_hash: predicate_hash_be,
            salt: draft.salt,
            class_set: draft.class_set.clone(),
            class_thresholds: draft.class_thresholds.clone(),
            class_index: draft.class_index,
            close_at_block: draft.close_at_block,
            bounty: draft.bounty,
            alpha_at_registration,
            organizer: draft.organizer,
            running_root: self.empty_imt_root,
            identity_tag_set_root: self.empty_imt_root,
            leaf_count: 0,
            resolution_proof: Vec::new(),
            b: false,
            b_per_class: Vec::new(),
            state: PetitionState::Registered,
            registration_block: now,
        };
        self.petitions.insert(
            petition_id,
            PetitionEntry {
                record: petition_record,
                batches: Vec::new(),
                running_imt: IndexedMerkleTree::new(),
                identity_tag_imt: IndexedMerkleTree::new(),
            },
        );
        self.step_state(&petition_id)?;

        let event = PetitionRegisteredEvent {
            petition_id,
            slot,
            r_root: draft.r_root,
            predicate_hash: predicate_hash_be,
            class_set: draft.class_set,
            class_thresholds: draft.class_thresholds,
            class_index: draft.class_index,
            close_at_block: draft.close_at_block,
            bounty: bounty_u128,
        };
        Ok((
            RegisteredPetition {
                petition_id,
                slot,
                predicate_hash: predicate_hash_be,
                registered_at_block: now,
            },
            event,
        ))
    }

    /// Verify batch SNARK, assert petition bindings + prior state, apply new roots.
    pub fn publish_batch(
        &mut self,
        petition_id: &PetitionId,
        relayer: Address,
        submission: BatchSubmission,
    ) -> Result<BatchPublishedEvent, RegistryError> {
        let state = self.step_state(petition_id)?;
        if state != PetitionState::SigningOpen {
            return Err(RegistryError::BadState(state, "publish_batch"));
        }
        // Cross-check the blob carrier by recomputing `batch_versioned_hash`.
        let local_vh =
            compute_batch_versioned_hash(&crate::blob::encode_blob(&submission.records)?);
        let public = &submission.public_inputs;
        if local_vh != fr_to_be_bytes(&public.batch_versioned_hash) {
            return Err(RegistryError::Blob(crate::error::BlobError::Malformed(
                "batch_versioned_hash mismatch".into(),
            )));
        }
        self.proof_backend
            .verify_batch_proof(&submission.proof_bytes, public)
            .map_err(RegistryError::BadBatchProof)?;
        let submitted_at_block = self.now();
        let entry = self.petition_mut(petition_id)?;
        let pid_fr = fr_from_be_bytes(&entry.record.petition_id);
        let r_fr = fr_from_be_bytes(&entry.record.r_root);
        let ph_fr = fr_from_be_bytes(&entry.record.predicate_hash);
        let ci_fr = Fr::from(entry.record.class_index as u64);
        if public.petition_id != pid_fr
            || public.r_root != r_fr
            || public.predicate_hash != ph_fr
            || public.class_index != ci_fr
        {
            return Err(RegistryError::BadBatchProof(ProofError::Verification(
                "batch public-input petition bindings mismatch".into(),
            )));
        }
        if public.slot != Fr::from(entry.record.slot as u64) {
            return Err(RegistryError::BadBatchProof(ProofError::Verification(
                "batch public-input slot mismatch".into(),
            )));
        }
        let batch_size_u = fr_to_u64(public.batch_size)?;
        if batch_size_u == 0 || batch_size_u > BATCH_SIZE_MAX as u64 {
            return Err(RegistryError::BatchSizeOutOfRange(batch_size_u as usize));
        }
        if submission.records.len() as u64 != batch_size_u {
            return Err(RegistryError::BatchSizeOutOfRange(submission.records.len()));
        }
        let prior_rr_be = fr_to_be_bytes(&public.prior_running_root);
        let prior_idt_be = fr_to_be_bytes(&public.prior_identity_tag_set_root);
        let prior_lc_u = fr_to_u64(public.prior_leaf_count)?;
        if prior_rr_be != entry.record.running_root
            || prior_idt_be != entry.record.identity_tag_set_root
            || prior_lc_u != entry.record.leaf_count
        {
            return Err(RegistryError::BatchPriorMismatch(Box::new(
                BatchPriorMismatch {
                    expected_rr: entry.record.running_root,
                    expected_idt: entry.record.identity_tag_set_root,
                    expected_lc: entry.record.leaf_count,
                    got_rr: prior_rr_be,
                    got_idt: prior_idt_be,
                    got_lc: prior_lc_u,
                },
            )));
        }
        let new_lc_u = fr_to_u64(public.new_leaf_count)?;
        let expected_new_lc = prior_lc_u.checked_add(batch_size_u).ok_or_else(|| {
            RegistryError::BadBatchProof(ProofError::Verification(
                "prior_leaf_count + batch_size overflow".into(),
            ))
        })?;
        if new_lc_u != expected_new_lc {
            return Err(RegistryError::BadBatchProof(ProofError::Verification(
                "new_leaf_count != prior_leaf_count + batch_size".into(),
            )));
        }
        // Re-execute SNARK constraints on cloned IMTs; commit atomically.
        let mut scratch_running_imt = entry.running_imt.clone();
        let mut scratch_identity_tag_imt = entry.identity_tag_imt.clone();
        let mut prev_leaf_be: Option<[u8; 32]> = None;
        let mut last_running_root_be = prior_rr_be;
        let mut last_identity_tag_root_be = prior_idt_be;
        for (i, record) in submission.records.iter().enumerate() {
            // Defense-in-depth: mock backend cannot enforce constraint 4, so block out-of-set class_tag here.
            let entry_class_set = &entry.record.class_set;
            if !entry_class_set.contains(&record.class_tag) {
                return Err(RegistryError::BadBatchProof(ProofError::Verification(
                    format!(
                        "class_tag {} at position {i} not in petition's class_set",
                        record.class_tag
                    ),
                )));
            }
            let nullifier_fr = fr_from_be_bytes(&record.nullifier);
            let class_tag_fr = Fr::from(record.class_tag as u64);
            let leaf_fr = hash_leaf(nullifier_fr, class_tag_fr);
            let leaf_be = fr_to_be_bytes(&leaf_fr);
            if let Some(prev) = prev_leaf_be
                && prev >= leaf_be
            {
                return Err(RegistryError::BadBatchProof(ProofError::Verification(
                    format!("leaf ordering violation at position {i}"),
                )));
            }
            prev_leaf_be = Some(leaf_be);
            let leaf_witness = scratch_running_imt.insert(&leaf_be).map_err(|e| {
                RegistryError::BadBatchProof(ProofError::Verification(format!(
                    "running_imt insert at position {i}: {e}"
                )))
            })?;
            last_running_root_be = leaf_witness.new_root;
            let id_witness = scratch_identity_tag_imt
                .insert(&record.identity_tag)
                .map_err(|e| {
                    RegistryError::BadBatchProof(ProofError::Verification(format!(
                        "identity_tag_imt insert at position {i}: {e}"
                    )))
                })?;
            last_identity_tag_root_be = id_witness.new_root;
        }
        let claimed_new_rr_be = fr_to_be_bytes(&public.new_running_root);
        let claimed_new_idt_be = fr_to_be_bytes(&public.new_identity_tag_set_root);
        if claimed_new_rr_be != last_running_root_be {
            return Err(RegistryError::BadBatchProof(ProofError::Verification(
                "submitted new_running_root disagrees with registry IMT".into(),
            )));
        }
        if claimed_new_idt_be != last_identity_tag_root_be {
            return Err(RegistryError::BadBatchProof(ProofError::Verification(
                "submitted new_identity_tag_set_root disagrees with registry IMT".into(),
            )));
        }
        entry.running_imt = scratch_running_imt;
        entry.identity_tag_imt = scratch_identity_tag_imt;
        let new_rr_be = claimed_new_rr_be;
        let new_idt_be = claimed_new_idt_be;
        let batch_index = u32::try_from(entry.batches.len()).map_err(|_| {
            RegistryError::BadBatchProof(ProofError::Verification(
                "batch index overflow".into(),
            ))
        })?;
        entry.record.running_root = new_rr_be;
        entry.record.identity_tag_set_root = new_idt_be;
        entry.record.leaf_count = new_lc_u;

        entry.batches.push(InternalBatch {
            record: BatchRecord {
                petition_id: *petition_id,
                batch_index,
                batch_versioned_hash: local_vh,
                new_running_root: new_rr_be,
                new_identity_tag_set_root: new_idt_be,
                prior_running_root: prior_rr_be,
                prior_identity_tag_set_root: prior_idt_be,
                prior_leaf_count: prior_lc_u,
                new_leaf_count: new_lc_u,
                relayer,
                submitted_at_block,
                state: BatchState::Active,
            },
        });

        Ok(BatchPublishedEvent {
            petition_id: *petition_id,
            batch_index,
            batch_versioned_hash: local_vh,
            new_running_root: new_rr_be,
            new_identity_tag_set_root: new_idt_be,
            new_leaf_count: new_lc_u,
        })
    }

    /// Validate openings, run violation predicate, repudiate batch, roll back state.
    pub fn dispute(
        &mut self,
        dispute: Dispute,
    ) -> Result<BatchRepudiatedEvent, RegistryError> {
        let state = self.step_state(&dispute.petition_id)?;
        if state != PetitionState::DisputeWindow {
            return Err(RegistryError::BadState(state, "dispute"));
        }
        let close_at_block = self.petition(&dispute.petition_id)?.record.close_at_block;
        let dispute_close = close_at_block
            .checked_add(RESOLUTION_DEADLINE_BLOCKS)
            .ok_or(RegistryError::BadState(state, "dispute"))?;
        if self.now() >= dispute_close {
            return Err(RegistryError::DisputeWindowClosed);
        }
        // Pre-fetch `batch_versioned_hash` without a mut borrow so verification runs uncontended.
        let vh = {
            let entry = self.petition(&dispute.petition_id)?;
            let batch_idx = dispute.batch_index as usize;
            if batch_idx >= entry.batches.len() {
                return Err(RegistryError::DisputeUnknownBatch(dispute.batch_index));
            }
            if entry.batches[batch_idx].record.state == BatchState::Repudiated {
                return Err(RegistryError::DisputeBatchAlreadyRepudiated(
                    dispute.batch_index,
                ));
            }
            entry.batches[batch_idx].record.batch_versioned_hash
        };
        for opening in &dispute.openings {
            self.blob_carrier
                .verify(&vh, opening)
                .map_err(RegistryError::BadDisputeOpening)?;
        }
        let empty_imt_root = self.empty_imt_root;
        let entry = self.petition_mut(&dispute.petition_id)?;
        let batch_idx = dispute.batch_index as usize;
        let evidence_i =
            derive_evidence(&dispute, dispute.position_i).ok_or_else(|| {
                RegistryError::BadDisputeOpening(crate::error::BlobError::Malformed(
                    "could not derive evidence_i from openings".into(),
                ))
            })?;
        match dispute.violation_type {
            ViolationType::ClassTagOutOfSet => {
                if entry.record.class_set.contains(&evidence_i.class_tag) {
                    return Err(RegistryError::DisputePredicateNotMet);
                }
            }
            ViolationType::IntraBatchDuplicateIdentityTag => {
                let pos_j = dispute.position_j.ok_or_else(|| {
                    RegistryError::BadDisputeOpening(crate::error::BlobError::Malformed(
                        "missing position_j".into(),
                    ))
                })?;
                if pos_j == dispute.position_i {
                    return Err(RegistryError::DisputePredicateNotMet);
                }
                let ev_j = derive_evidence(&dispute, pos_j).ok_or_else(|| {
                    RegistryError::BadDisputeOpening(crate::error::BlobError::Malformed(
                        "could not derive evidence_j from openings".into(),
                    ))
                })?;
                if evidence_i.identity_tag != ev_j.identity_tag {
                    return Err(RegistryError::DisputePredicateNotMet);
                }
            }
            ViolationType::LeafOrderingViolation => {
                let pos_j = dispute.position_j.ok_or_else(|| {
                    RegistryError::BadDisputeOpening(crate::error::BlobError::Malformed(
                        "missing position_j".into(),
                    ))
                })?;
                let expected_j = dispute.position_i.checked_add(1).ok_or_else(|| {
                    RegistryError::BadDisputeOpening(crate::error::BlobError::Malformed(
                        "position_i overflow".into(),
                    ))
                })?;
                if pos_j != expected_j {
                    return Err(RegistryError::DisputePredicateNotMet);
                }
                let ev_j = derive_evidence(&dispute, pos_j).ok_or_else(|| {
                    RegistryError::BadDisputeOpening(crate::error::BlobError::Malformed(
                        "could not derive evidence_j from openings".into(),
                    ))
                })?;
                let leaf_i = hash_leaf(
                    fr_from_be_bytes(&evidence_i.nullifier),
                    Fr::from(evidence_i.class_tag as u64),
                );
                let leaf_ip1 = hash_leaf(
                    fr_from_be_bytes(&ev_j.nullifier),
                    Fr::from(ev_j.class_tag as u64),
                );
                if !leaf_ordering_violated(&leaf_i, &leaf_ip1) {
                    return Err(RegistryError::DisputePredicateNotMet);
                }
            }
        }

        // Rollback in scratch buffers; commit only if every step succeeds.
        let active_vhs_to_replay: Vec<Bytes32> = entry
            .batches
            .iter()
            .take(batch_idx)
            .filter(|b| b.record.state == BatchState::Active)
            .map(|b| b.record.batch_versioned_hash)
            .collect();
        let mut scratch_records: Vec<crate::types::RecordEntry> = Vec::new();
        for vh in &active_vhs_to_replay {
            let records = self
                .blob_carrier
                .fetch_records(vh)
                .map_err(RegistryError::Blob)?;
            scratch_records.extend(records);
        }
        let mut scratch_running_imt = IndexedMerkleTree::new();
        let mut scratch_identity_tag_imt = IndexedMerkleTree::new();
        for record in &scratch_records {
            let nullifier_fr = fr_from_be_bytes(&record.nullifier);
            let class_tag_fr = Fr::from(record.class_tag as u64);
            let leaf_fr = hash_leaf(nullifier_fr, class_tag_fr);
            let _ = scratch_running_imt.insert(&fr_to_be_bytes(&leaf_fr))?;
            let _ = scratch_identity_tag_imt.insert(&record.identity_tag)?;
        }
        let (rb_rr, rb_idt, rb_lc) = {
            let entry = self.petition(&dispute.petition_id)?;
            roll_back_to_predecessor(&entry.batches, batch_idx, empty_imt_root)
        };
        let entry = self.petition_mut(&dispute.petition_id)?;
        for b in entry.batches[batch_idx..].iter_mut() {
            b.record.state = BatchState::Repudiated;
        }
        entry.record.running_root = rb_rr;
        entry.record.identity_tag_set_root = rb_idt;
        entry.record.leaf_count = rb_lc;
        entry.running_imt = scratch_running_imt;
        entry.identity_tag_imt = scratch_identity_tag_imt;

        Ok(BatchRepudiatedEvent {
            petition_id: dispute.petition_id,
            batch_index: dispute.batch_index,
            new_running_root: rb_rr,
            new_identity_tag_set_root: rb_idt,
            new_leaf_count: rb_lc,
        })
    }

    /// Validate the resolution SNARK; apply outcome bits and transition to `Resolved`.
    pub fn resolve(
        &mut self,
        petition_id: &PetitionId,
        resolver: Address,
        submission: ResolutionSubmission,
    ) -> Result<(PetitionResolvedEvent, BountyPaidEvent), RegistryError> {
        let state = self.step_state(petition_id)?;
        if state != PetitionState::DisputeWindow {
            return Err(RegistryError::BadState(state, "resolve"));
        }
        let now = self.now();
        let close_at_block = self.petition(petition_id)?.record.close_at_block;
        let deadline = close_at_block
            .checked_add(RESOLUTION_DEADLINE_BLOCKS)
            .ok_or(RegistryError::BadState(state, "resolve"))?;
        if now < deadline {
            return Err(RegistryError::BadState(state, "resolve"));
        }
        // Verify before taking a mut borrow.
        self.proof_backend
            .verify_resolution_proof(&submission.proof_bytes, &submission.public_inputs)
            .map_err(RegistryError::BadResolutionProof)?;
        let entry = self.petition_mut(petition_id)?;
        let public = &submission.public_inputs;
        let leaf_count_pi = fr_to_u64(public.leaf_count)?;
        if fr_to_be_bytes(&public.predicate_hash) != entry.record.predicate_hash
            || fr_to_be_bytes(&public.r_root) != entry.record.r_root
            || fr_to_be_bytes(&public.running_root) != entry.record.running_root
            || leaf_count_pi != entry.record.leaf_count
        {
            return Err(RegistryError::ResolutionStateMismatch);
        }
        if public.class_set.len() != entry.record.class_set.len()
            || public.class_thresholds.len() != entry.record.class_thresholds.len()
            || public.b_per_class.len() != entry.record.class_set.len()
        {
            return Err(RegistryError::ResolutionStateMismatch);
        }
        for (i, c) in entry.record.class_set.iter().enumerate() {
            if public.class_set[i] != Fr::from(*c as u64) {
                return Err(RegistryError::ResolutionStateMismatch);
            }
            if public.class_thresholds[i] != Fr::from(entry.record.class_thresholds[i]) {
                return Err(RegistryError::ResolutionStateMismatch);
            }
        }
        let b = !public.b.is_zero();
        let b_per_class: Vec<bool> =
            public.b_per_class.iter().map(|x| !x.is_zero()).collect();
        entry.record.b = b;
        entry.record.b_per_class = b_per_class.clone();
        entry.record.state = PetitionState::Resolved;
        entry.record.resolution_proof = submission.proof_bytes;
        let bounty_amount = u256_to_u128(&entry.record.bounty)?;
        Ok((
            PetitionResolvedEvent {
                petition_id: *petition_id,
                b,
                b_per_class,
            },
            BountyPaidEvent {
                petition_id: *petition_id,
                recipient: resolver,
                amount: bounty_amount,
            },
        ))
    }

    /// Refund bounty (minus caller gas rebate), write tombstone, transition to `Unresolved`.
    pub fn mark_unresolved(
        &mut self,
        petition_id: &PetitionId,
        caller: Address,
        gas_rebate: u128,
    ) -> Result<
        (
            PetitionUnresolvedEvent,
            BountyRefundedEvent,
            BountyRefundedEvent,
        ),
        RegistryError,
    > {
        let state = self.step_state(petition_id)?;
        let now = self.now();
        let entry = self.petition_mut(petition_id)?;
        let deadline = entry
            .record
            .close_at_block
            .checked_add(RESOLUTION_DEADLINE_BLOCKS)
            .and_then(|d| d.checked_add(MARK_UNRESOLVED_GRACE_BLOCKS))
            .ok_or(RegistryError::BadState(state, "mark_unresolved"))?;
        if now < deadline {
            return Err(RegistryError::BadState(state, "mark_unresolved"));
        }
        // Only DisputeWindow may transition to Unresolved.
        if state != PetitionState::DisputeWindow {
            return Err(RegistryError::BadState(state, "mark_unresolved"));
        }
        let bounty_total = u256_to_u128(&entry.record.bounty)?;
        // Cap rebate at 1% so caller cannot starve the organizer of the refund.
        let rebate_cap = bounty_total / 100;
        let rebate = gas_rebate.min(rebate_cap);
        let refund = bounty_total - rebate;
        entry.record.running_root = TOMBSTONE_MARKER;
        entry.record.state = PetitionState::Unresolved;
        Ok((
            PetitionUnresolvedEvent {
                petition_id: *petition_id,
            },
            BountyRefundedEvent {
                petition_id: *petition_id,
                recipient: entry.record.organizer,
                amount: refund,
            },
            BountyRefundedEvent {
                petition_id: *petition_id,
                recipient: caller,
                amount: rebate,
            },
        ))
    }

    /// Governance hook; PoC accepts any caller, production MUST gate by role.
    pub fn update_alpha(
        &mut self,
        new_alpha: u64,
    ) -> Result<AlphaUpdatedEvent, RegistryError> {
        if !(self.global.alpha_min..=self.global.alpha_max).contains(&new_alpha) {
            return Err(RegistryError::AlphaOutOfBounds {
                alpha: new_alpha,
                min: self.global.alpha_min,
                max: self.global.alpha_max,
            });
        }
        let old_alpha = self.global.alpha;
        self.global.alpha = new_alpha;
        Ok(AlphaUpdatedEvent {
            old_alpha,
            new_alpha,
        })
    }
}

fn fr_to_u64(fr: Fr) -> Result<u64, RegistryError> {
    let be = fr_to_be_bytes(&fr);
    if be[..24].iter().any(|&b| b != 0) {
        return Err(RegistryError::BadBatchProof(ProofError::Verification(
            "public-input field element exceeds u64 range".into(),
        )));
    }
    Ok(u64::from_be_bytes(be[24..32].try_into().unwrap()))
}

fn u256_to_u128(v: &U256Be) -> Result<u128, RegistryError> {
    // High 16 bytes MUST be zero for a u128 fit.
    let bytes = v.as_bytes();
    if bytes[..16].iter().any(|&b| b != 0) {
        return Err(RegistryError::Predicate(
            crate::error::PredicateError::Malformed("bounty exceeds u128 range".into()),
        ));
    }
    Ok(u128::from_be_bytes(bytes[16..32].try_into().unwrap()))
}

fn derive_evidence(
    dispute: &Dispute,
    position: u32,
) -> Option<crate::types::RecordEntry> {
    let base = position.checked_mul(4)?;
    let last = base.checked_add(3)?;
    let max_fe_index = (crate::RECORDS_PER_BLOB * crate::blob::FE_PER_RECORD) as u32;
    if last >= max_fe_index {
        return None;
    }
    // Reject duplicate openings for the same field-element index.
    let mut by_offset: [Option<&crate::types::KzgOpening>; 4] = [None; 4];
    for o in &dispute.openings {
        if let Some(off) = o.field_element_index.checked_sub(base)
            && off < 4
        {
            if by_offset[off as usize].is_some() {
                return None;
            }
            by_offset[off as usize] = Some(o);
        }
    }
    let mut record_bytes = [0u8; crate::RECORD_LEN];
    for (j, slot) in by_offset.iter().enumerate() {
        let o = (*slot)?;
        let start = j * crate::blob::CONTENT_PER_FE;
        let end = ((j + 1) * crate::blob::CONTENT_PER_FE).min(crate::RECORD_LEN);
        let take = end - start;
        record_bytes[start..end].copy_from_slice(&o.claimed_value[1..1 + take]);
    }
    Some(crate::blob::decode_record(&record_bytes))
}

fn roll_back_to_predecessor(
    batches: &[InternalBatch],
    repudiated_idx: usize,
    empty_imt_root: Bytes32,
) -> (Bytes32, Bytes32, u64) {
    for prev in batches[..repudiated_idx].iter().rev() {
        if prev.record.state == BatchState::Active {
            return (
                prev.record.new_running_root,
                prev.record.new_identity_tag_set_root,
                prev.record.new_leaf_count,
            );
        }
    }
    (empty_imt_root, empty_imt_root, 0)
}

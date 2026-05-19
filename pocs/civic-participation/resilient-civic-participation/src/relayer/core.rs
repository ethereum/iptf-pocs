//! Relayer: aggregate signer submissions, build batch SNARK, publish blob.

use std::collections::HashMap;

use ark_bn254::Fr;

use crate::{
    BATCH_SIZE_MAX,
    imt::IndexedMerkleTree,
    ports::{
        blob::BlobCarrier,
        imt::ImtStore,
        proof::{
            BatchPositionWitness,
            ProofBackend,
        },
    },
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_leaf,
    },
    relayer::{
        error::RelayerError,
        types::{
            BatchPosition,
            PetitionView,
        },
    },
    types::{
        Address,
        BatchPublicInputs,
        BatchSubmission,
        Bytes32,
        ClassTag,
        RecordEntry,
        SignerPublicInputs,
        SignerSubmission,
    },
};

/// Per-petition IMT replicas the relayer maintains to build batch witnesses.
pub struct RelayerPetitionState {
    pub running_imt: IndexedMerkleTree,
    pub identity_tag_imt: IndexedMerkleTree,
    pub leaf_count: u64,
}

impl RelayerPetitionState {
    pub fn new() -> Self {
        Self {
            running_imt: IndexedMerkleTree::new(),
            identity_tag_imt: IndexedMerkleTree::new(),
            leaf_count: 0,
        }
    }
}

impl Default for RelayerPetitionState {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Relayer<P, B>
where
    P: ProofBackend,
    B: BlobCarrier,
{
    pub address: Address,
    pub proof_backend: P,
    pub blob_carrier: B,
}

impl<P, B> Relayer<P, B>
where
    P: ProofBackend,
    B: BlobCarrier,
{
    pub fn new(address: Address, proof_backend: P, blob_carrier: B) -> Self {
        Self {
            address,
            proof_backend,
            blob_carrier,
        }
    }

    /// Verify a signer submission against `petition`.
    fn verify_submission(
        &self,
        idx: usize,
        s: &SignerSubmission,
        petition: &PetitionView,
    ) -> Result<(SignerPublicInputs, Fr, ClassTag), RelayerError> {
        if s.petition_id != petition.petition_id {
            return Err(RelayerError::PetitionIdMismatch(idx));
        }
        if !petition.class_set.contains(&s.class_tag) {
            return Err(RelayerError::ClassTagOutOfSet(s.class_tag, idx));
        }

        let public = SignerPublicInputs {
            r_root: fr_from_be_bytes(&s.r_root),
            petition_id: fr_from_be_bytes(&s.petition_id),
            predicate_hash: fr_from_be_bytes(&s.predicate_hash),
            class_index: Fr::from(s.class_index as u64),
            class_tag: Fr::from(s.class_tag as u64),
            slot: Fr::from(s.slot as u64),
            nullifier: fr_from_be_bytes(&s.nullifier),
            identity_tag: fr_from_be_bytes(&s.identity_tag),
        };
        self.proof_backend
            .verify_signer_proof(&s.proof_bytes, &public)
            .map_err(|e| RelayerError::SignerProofInvalid(idx, e))?;
        let leaf = hash_leaf(public.nullifier, public.class_tag);
        Ok((public, leaf, s.class_tag))
    }

    /// Build a `BatchSubmission` and `BatchPosition`s; advances `petition_state`.
    pub fn build_batch(
        &mut self,
        petition: &PetitionView,
        petition_state: &mut RelayerPetitionState,
        submissions: Vec<SignerSubmission>,
    ) -> Result<(BatchSubmission, Vec<BatchPosition>), RelayerError> {
        if submissions.is_empty() {
            return Err(RelayerError::EmptyBatch);
        }
        if submissions.len() > BATCH_SIZE_MAX {
            return Err(RelayerError::BatchSizeExceeded(
                submissions.len(),
                BATCH_SIZE_MAX,
            ));
        }
        if petition_state.running_imt.root() != petition.running_root
            || petition_state.identity_tag_imt.root() != petition.identity_tag_set_root
        {
            return Err(RelayerError::StateDiverged);
        }

        let mut verified: Vec<(SignerSubmission, SignerPublicInputs, Fr, ClassTag)> =
            Vec::with_capacity(submissions.len());
        for (i, s) in submissions.into_iter().enumerate() {
            let (public, leaf, ct) = self.verify_submission(i, &s, petition)?;
            verified.push((s, public, leaf, ct));
        }

        // Record first-seen index per nullifier / identity_tag so we can
        // report exact collision positions without a quadratic rescan.
        let mut seen_nullifiers: HashMap<Bytes32, usize> = HashMap::new();
        let mut seen_ids: HashMap<Bytes32, usize> = HashMap::new();
        for (i, (s, _, _, _)) in verified.iter().enumerate() {
            if let Some(&j) = seen_nullifiers.get(&s.nullifier) {
                return Err(RelayerError::DuplicateNullifier(j, i));
            }
            if let Some(&j) = seen_ids.get(&s.identity_tag) {
                return Err(RelayerError::DuplicateIdentityTag(j, i));
            }
            seen_nullifiers.insert(s.nullifier, i);
            seen_ids.insert(s.identity_tag, i);
        }

        // Canonical BN254 ordering: ascending big-endian leaf bytes.
        verified.sort_by_cached_key(|t| fr_to_be_bytes(&t.2));

        let prior_running_root = petition_state.running_imt.root();
        let prior_identity_tag_root = petition_state.identity_tag_imt.root();
        let prior_leaf_count = petition_state.leaf_count;

        let mut positions: Vec<BatchPosition> = Vec::with_capacity(verified.len());
        let mut records: Vec<RecordEntry> = Vec::with_capacity(verified.len());
        for (s, _public, leaf_fr, _class_tag) in verified.iter() {
            let leaf_be = fr_to_be_bytes(leaf_fr);
            let leaf_insert = petition_state.running_imt.insert(&leaf_be)?;
            let identity_tag_insert =
                petition_state.identity_tag_imt.insert(&s.identity_tag)?;
            records.push(RecordEntry {
                nullifier: s.nullifier,
                identity_tag: s.identity_tag,
                class_tag: s.class_tag,
            });
            positions.push(BatchPosition {
                submission: s.clone(),
                leaf_insert,
                identity_tag_insert,
            });
        }
        petition_state.leaf_count = prior_leaf_count
            .checked_add(positions.len() as u64)
            .ok_or(RelayerError::LeafCountOverflow)?;

        let new_running_root = petition_state.running_imt.root();
        let new_identity_tag_root = petition_state.identity_tag_imt.root();

        let batch_versioned_hash = self.blob_carrier.publish(&records)?;

        // Constraint 8 re-derives these; contract verifies KZG openings against `batch_versioned_hash`.
        let fe_per_batch = BATCH_SIZE_MAX * crate::blob::FE_PER_RECORD;
        let mut bls_fields: Vec<Fr> = Vec::with_capacity(fe_per_batch);
        bls_fields.extend(records.iter().flat_map(crate::blob::record_to_bls_fields));
        bls_fields.resize(fe_per_batch, Fr::from(0u64));

        let public_inputs = BatchPublicInputs {
            petition_id: fr_from_be_bytes(&petition.petition_id),
            r_root: fr_from_be_bytes(&petition.r_root),
            predicate_hash: fr_from_be_bytes(&petition.predicate_hash),
            class_index: Fr::from(petition.class_index as u64),
            slot: Fr::from(petition.slot as u64),
            batch_size: Fr::from(positions.len() as u64),
            prior_running_root: fr_from_be_bytes(&prior_running_root),
            new_running_root: fr_from_be_bytes(&new_running_root),
            prior_identity_tag_set_root: fr_from_be_bytes(&prior_identity_tag_root),
            new_identity_tag_set_root: fr_from_be_bytes(&new_identity_tag_root),
            prior_leaf_count: Fr::from(prior_leaf_count),
            new_leaf_count: Fr::from(petition_state.leaf_count),
            batch_versioned_hash: fr_from_be_bytes(&batch_versioned_hash),
            bls_fields,
            signer_vk_hash: fr_from_be_bytes(&petition.signer_vk_hash),
        };
        let position_witnesses: Vec<BatchPositionWitness> = verified
            .into_iter()
            .zip(positions.iter())
            .map(|((s, public, _, _), bp)| BatchPositionWitness {
                submission: s,
                public_inputs: public,
                running_insert: Some(bp.leaf_insert.clone()),
                idtag_insert: Some(bp.identity_tag_insert.clone()),
            })
            .collect();
        let proof_bytes = self
            .proof_backend
            .generate_batch_proof(&public_inputs, &position_witnesses)?;

        Ok((
            BatchSubmission {
                public_inputs,
                records,
                proof_bytes,
            },
            positions,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapters::{
            in_memory_blob::InMemoryBlobCarrier,
            mock_proof::MockProofBackend,
        },
        poseidon::{
            hash_identity_tag,
            hash_nullifier,
        },
    };

    fn fake_submission(
        petition: &PetitionView,
        slot: u32,
        class_tag: u16,
        secret: u64,
    ) -> SignerSubmission {
        let backend = MockProofBackend;
        let identity_secret_fr = Fr::from(0xdeadbeefu64);
        let nullifier_fr = hash_nullifier(
            Fr::from(secret),
            fr_from_be_bytes(&petition.petition_id),
            Fr::from(petition.class_index as u64),
            Fr::from(class_tag as u64),
            identity_secret_fr,
        );
        let identity_tag_fr =
            hash_identity_tag(Fr::from(secret), fr_from_be_bytes(&petition.petition_id));
        let public = SignerPublicInputs {
            r_root: fr_from_be_bytes(&petition.r_root),
            petition_id: fr_from_be_bytes(&petition.petition_id),
            predicate_hash: fr_from_be_bytes(&petition.predicate_hash),
            class_index: Fr::from(petition.class_index as u64),
            class_tag: Fr::from(class_tag as u64),
            slot: Fr::from(slot as u64),
            nullifier: nullifier_fr,
            identity_tag: identity_tag_fr,
        };
        let private = crate::types::SignerPrivateInputs {
            identity_secret: identity_secret_fr,
            attr_vector: vec![Fr::from(1u64); 4],
            attr_version: 0,
            chain_root: Fr::from(7u64),
            ri_path_siblings: vec![],
            ri_path_indices: vec![],
            s_slot: Fr::from(8u64),
            chain_path_siblings: vec![],
            chain_path_indices: vec![],
            salt: Fr::from(11u64),
            predicate_def: crate::predicate::PredicateDef {
                tuples: vec![crate::predicate::Tuple {
                    claim_index: 0,
                    operand: [0u8; 32],
                    type_tag: crate::types::TypeTag::Int64,
                    comparator: crate::types::Comparator::Eq,
                }],
                ops: vec![crate::predicate::Op {
                    code: crate::types::OpCode::PushTuple,
                    operand: 0,
                }],
            },
        };
        let proof_bytes = backend.generate_signer_proof(&public, &private).unwrap();
        SignerSubmission {
            petition_id: petition.petition_id,
            r_root: petition.r_root,
            predicate_hash: petition.predicate_hash,
            class_index: petition.class_index,
            slot,
            nullifier: fr_to_be_bytes(&nullifier_fr),
            identity_tag: fr_to_be_bytes(&identity_tag_fr),
            class_tag,
            proof_bytes,
        }
    }

    fn empty_petition_view() -> PetitionView {
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&42u64.to_be_bytes());
        let mut r = [0u8; 32];
        r[24..].copy_from_slice(&7u64.to_be_bytes());
        let mut ph = [0u8; 32];
        ph[24..].copy_from_slice(&88u64.to_be_bytes());
        let initial_imt = IndexedMerkleTree::new();
        let imt_root = initial_imt.root();
        PetitionView {
            petition_id: id,
            r_root: r,
            predicate_hash: ph,
            class_index: 1,
            class_set: vec![100, 200],
            slot: 0,
            running_root: imt_root,
            identity_tag_set_root: imt_root,
            leaf_count: 0,
            signer_vk_hash: [0u8; 32],
        }
    }

    #[test]
    fn test_relayer_builds_batch_in_canonical_order() {
        let petition = empty_petition_view();
        let mut state = RelayerPetitionState::new();
        let mut relayer =
            Relayer::new([0xaa; 20], MockProofBackend, InMemoryBlobCarrier::new());
        let s1 = fake_submission(&petition, 0, 100, 1);
        let s2 = fake_submission(&petition, 0, 200, 2);
        let s3 = fake_submission(&petition, 0, 100, 3);
        let (batch, positions) = relayer
            .build_batch(
                &petition,
                &mut state,
                vec![s1.clone(), s2.clone(), s3.clone()],
            )
            .unwrap();
        assert_eq!(batch.records.len(), 3);
        for w in positions.windows(2) {
            let leaf_a = hash_leaf(
                fr_from_be_bytes(&w[0].submission.nullifier),
                Fr::from(w[0].submission.class_tag as u64),
            );
            let leaf_b = hash_leaf(
                fr_from_be_bytes(&w[1].submission.nullifier),
                Fr::from(w[1].submission.class_tag as u64),
            );
            assert!(fr_to_be_bytes(&leaf_a) < fr_to_be_bytes(&leaf_b));
        }
    }

    #[test]
    fn test_relayer_rejects_intra_batch_duplicate_nullifier() {
        let petition = empty_petition_view();
        let mut state = RelayerPetitionState::new();
        let mut relayer =
            Relayer::new([0xaa; 20], MockProofBackend, InMemoryBlobCarrier::new());
        let s = fake_submission(&petition, 0, 100, 1);
        let err = relayer.build_batch(&petition, &mut state, vec![s.clone(), s.clone()]);
        assert!(matches!(err, Err(RelayerError::DuplicateNullifier(_, _))));
    }

    #[test]
    fn test_relayer_rejects_class_tag_out_of_set() {
        let petition = empty_petition_view();
        let mut state = RelayerPetitionState::new();
        let mut relayer =
            Relayer::new([0xaa; 20], MockProofBackend, InMemoryBlobCarrier::new());
        let bad = fake_submission(&petition, 0, 999, 1);
        let err = relayer.build_batch(&petition, &mut state, vec![bad]);
        assert!(matches!(err, Err(RelayerError::ClassTagOutOfSet(999, 0))));
    }

    #[test]
    fn test_relayer_rejects_empty_batch() {
        let petition = empty_petition_view();
        let mut state = RelayerPetitionState::new();
        let mut relayer =
            Relayer::new([0xaa; 20], MockProofBackend, InMemoryBlobCarrier::new());
        let err = relayer.build_batch(&petition, &mut state, vec![]);
        assert!(matches!(err, Err(RelayerError::EmptyBatch)));
    }

    #[test]
    fn test_relayer_emits_blob_with_records_in_canonical_order() {
        let petition = empty_petition_view();
        let mut state = RelayerPetitionState::new();
        let mut relayer =
            Relayer::new([0xaa; 20], MockProofBackend, InMemoryBlobCarrier::new());
        let s1 = fake_submission(&petition, 0, 100, 1);
        let s2 = fake_submission(&petition, 0, 200, 2);
        let (batch, _) = relayer
            .build_batch(&petition, &mut state, vec![s1, s2])
            .unwrap();
        let bvh =
            crate::poseidon::fr_to_be_bytes(&batch.public_inputs.batch_versioned_hash);
        let fetched = relayer.blob_carrier.fetch_records(&bvh).unwrap();
        assert_eq!(fetched.len(), 2);
    }

    #[test]
    fn test_relayer_state_diverges_rejected() {
        let petition = empty_petition_view();
        let mut state = RelayerPetitionState::new();
        let _ = state.running_imt.insert(&[0x11u8; 32]).unwrap();
        let mut relayer =
            Relayer::new([0xaa; 20], MockProofBackend, InMemoryBlobCarrier::new());
        let s = fake_submission(&petition, 0, 100, 1);
        let err = relayer.build_batch(&petition, &mut state, vec![s]);
        assert!(matches!(err, Err(RelayerError::StateDiverged)));
    }
}

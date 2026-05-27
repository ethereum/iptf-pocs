//! Resolver: reconstruct leaves from blobs, count classes, prove resolution.

use ark_bn254::Fr;

use crate::{
    imt::IndexedMerkleTree,
    ports::{
        blob::BlobCarrier,
        imt::ImtStore,
        proof::ProofBackend,
    },
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_leaf,
    },
    resolver::{
        error::ResolverError,
        types::ResolverView,
    },
    types::{
        ImtMembershipFr,
        ResolutionPrivateInputs,
        ResolutionPublicInputs,
        ResolutionSubmission,
    },
};

pub struct Resolver<P, B>
where
    P: ProofBackend,
    B: BlobCarrier,
{
    pub proof_backend: P,
    pub blob_carrier: B,
}

impl<P, B> Resolver<P, B>
where
    P: ProofBackend,
    B: BlobCarrier,
{
    pub fn new(proof_backend: P, blob_carrier: B) -> Self {
        Self {
            proof_backend,
            blob_carrier,
        }
    }

    /// Reconstruct `L` from active-batch blobs; verifies `running_root` and `leaf_count`.
    pub fn reconstruct(
        &self,
        view: &ResolverView,
    ) -> Result<Vec<(Fr, Fr, Fr)>, ResolverError> {
        if view.active_batch_versioned_hashes.is_empty() {
            return Err(ResolverError::NoBatches);
        }
        let mut imt = IndexedMerkleTree::new();
        let mut entries: Vec<(Fr, Fr, Fr)> = Vec::new();
        for vh in &view.active_batch_versioned_hashes {
            let records = self.blob_carrier.fetch_records(vh)?;
            for record in records {
                let nullifier_fr = fr_from_be_bytes(&record.nullifier);
                let class_tag_fr = Fr::from(record.class_tag as u64);
                let leaf_fr = hash_leaf(nullifier_fr, class_tag_fr);
                let _ = imt.insert(&fr_to_be_bytes(&leaf_fr))?;
                entries.push((leaf_fr, nullifier_fr, class_tag_fr));
            }
        }
        if (entries.len() as u64) != view.leaf_count {
            return Err(ResolverError::LeafCountMismatch(
                entries.len() as u64,
                view.leaf_count,
            ));
        }
        if imt.root() != view.running_root {
            return Err(ResolverError::RootMismatch);
        }
        Ok(entries)
    }

    /// Build the resolution SNARK.
    pub fn build_submission(
        &self,
        view: &ResolverView,
        entries: &[(Fr, Fr, Fr)],
    ) -> Result<ResolutionSubmission, ResolverError> {
        let (b, b_per_class) = compute_outcome(view, entries);

        // Two-pass: insert all leaves to materialize the final IMT, then
        // query membership per leaf to read the final-state path and
        // linked-list pointers. Insertion-time witnesses are stale for
        // every leaf except the last because later inserts mutate
        // siblings along the earlier leaves' paths and rewrite the
        // bracketing low leaf's next_index/next_value.
        let mut imt = IndexedMerkleTree::new();
        let mut leaves = Vec::with_capacity(entries.len());
        let mut witness_pairs = Vec::with_capacity(entries.len());
        for (leaf_fr, nullifier_fr, class_tag_fr) in entries {
            imt.insert(&fr_to_be_bytes(leaf_fr))?;
            leaves.push(*leaf_fr);
            witness_pairs.push((*nullifier_fr, *class_tag_fr));
        }
        let mut imt_membership = Vec::with_capacity(entries.len());
        for (leaf_fr, _, _) in entries {
            let m = imt
                .membership(&fr_to_be_bytes(leaf_fr))
                .ok_or(ResolverError::RootMismatch)?;
            imt_membership.push(ImtMembershipFr {
                leaf_hash: hash_imt_leaf(&m.leaf),
                leaf_index: m.leaf_index,
                next_index: m.leaf.next_index,
                next_value: fr_from_be_bytes(&m.leaf.next_value),
                siblings: m
                    .path
                    .siblings
                    .iter()
                    .map(|s| fr_from_be_bytes(s))
                    .collect(),
                indices: m.path.indices.clone(),
            });
        }

        let public = ResolutionPublicInputs {
            predicate_hash: fr_from_be_bytes(&view.predicate_hash),
            r_root: fr_from_be_bytes(&view.r_root),
            running_root: fr_from_be_bytes(&view.running_root),
            leaf_count: Fr::from(view.leaf_count),
            class_set: view.class_set.iter().map(|c| Fr::from(*c as u64)).collect(),
            class_thresholds: view
                .class_thresholds
                .iter()
                .map(|t| Fr::from(*t))
                .collect(),
            b: Fr::from(b as u64),
            b_per_class: b_per_class.iter().map(|x| Fr::from(*x as u64)).collect(),
            class_index: Fr::from(view.class_index as u64),
        };
        let private = ResolutionPrivateInputs {
            leaves,
            imt_membership_paths: imt_membership,
            witness_pairs,
        };
        let proof_bytes = self
            .proof_backend
            .generate_resolution_proof(&public, &private)?;
        Ok(ResolutionSubmission {
            public_inputs: public,
            proof_bytes,
        })
    }

    /// `reconstruct` + `build_submission`.
    pub fn resolve(
        &self,
        view: &ResolverView,
    ) -> Result<ResolutionSubmission, ResolverError> {
        let entries = self.reconstruct(view)?;
        self.build_submission(view, &entries)
    }
}

fn hash_imt_leaf(leaf: &crate::ports::imt::ImtLeaf) -> Fr {
    use crate::poseidon::poseidon4;
    poseidon4(
        fr_from_be_bytes(&leaf.value),
        Fr::from(leaf.next_index as u64),
        fr_from_be_bytes(&leaf.next_value),
        Fr::from(0u64),
    )
}

/// Per-class counts and outcome bits `b`, `b_per_class`. `class_set` is
/// strictly increasing (registry-enforced) so we binary-search by tag.
pub fn compute_outcome(
    view: &ResolverView,
    entries: &[(Fr, Fr, Fr)],
) -> (bool, Vec<bool>) {
    let mut counts = vec![0u64; view.class_set.len()];
    for (_, _, class_tag_fr) in entries {
        let bytes = fr_to_be_bytes(class_tag_fr);
        let class_tag = u16::from_be_bytes([bytes[30], bytes[31]]);
        if let Ok(i) = view.class_set.binary_search(&class_tag) {
            counts[i] += 1;
        }
    }
    let b_per_class: Vec<bool> = counts
        .iter()
        .zip(view.class_thresholds.iter())
        .map(|(c, t)| *c >= *t)
        .collect();
    let b = b_per_class.iter().all(|x| *x);
    (b, b_per_class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapters::{
            in_memory_blob::InMemoryBlobCarrier,
            mock_proof::MockProofBackend,
        },
        types::RecordEntry,
    };

    fn sample_record(seed: u64, class_tag: u16) -> RecordEntry {
        let mut nullifier = [0u8; 32];
        nullifier[24..].copy_from_slice(&seed.to_be_bytes());
        let mut identity_tag = [0u8; 32];
        identity_tag[24..].copy_from_slice(&(seed + 100).to_be_bytes());
        RecordEntry {
            nullifier,
            identity_tag,
            class_tag,
        }
    }

    fn build_view_from_records(
        view_records: &[Vec<RecordEntry>],
        bc: &mut InMemoryBlobCarrier,
    ) -> ResolverView {
        let mut imt = IndexedMerkleTree::new();
        let mut vhs = Vec::new();
        let mut leaf_count: u64 = 0;
        // Mirror relayer's canonical leaf ordering per batch.
        let mut sorted_batches: Vec<Vec<RecordEntry>> = Vec::new();
        for batch in view_records {
            let mut copy = batch.clone();
            copy.sort_by(|a, b| {
                let la = hash_leaf(
                    fr_from_be_bytes(&a.nullifier),
                    Fr::from(a.class_tag as u64),
                );
                let lb = hash_leaf(
                    fr_from_be_bytes(&b.nullifier),
                    Fr::from(b.class_tag as u64),
                );
                fr_to_be_bytes(&la).cmp(&fr_to_be_bytes(&lb))
            });
            sorted_batches.push(copy);
        }
        for batch in &sorted_batches {
            for r in batch {
                let leaf_fr = hash_leaf(
                    fr_from_be_bytes(&r.nullifier),
                    Fr::from(r.class_tag as u64),
                );
                imt.insert(&fr_to_be_bytes(&leaf_fr)).unwrap();
                leaf_count += 1;
            }
            let vh = bc.publish(batch).unwrap();
            vhs.push(vh);
        }
        ResolverView {
            petition_id: [0x42; 32],
            r_root: [0x77; 32],
            predicate_hash: [0x88; 32],
            running_root: imt.root(),
            leaf_count,
            class_set: vec![100, 200],
            class_thresholds: vec![1, 1],
            class_index: 1,
            active_batch_versioned_hashes: vhs,
        }
    }

    #[test]
    fn test_reconstruct_validates_root_and_leaf_count() {
        let mut bc = InMemoryBlobCarrier::new();
        let view = build_view_from_records(
            &[
                vec![sample_record(1, 100), sample_record(2, 200)],
                vec![sample_record(3, 100), sample_record(4, 200)],
            ],
            &mut bc,
        );
        let resolver = Resolver::new(MockProofBackend, bc);
        let entries = resolver.reconstruct(&view).unwrap();
        assert_eq!(entries.len() as u64, view.leaf_count);
    }

    #[test]
    fn test_compute_outcome_b_per_class() {
        let mut bc = InMemoryBlobCarrier::new();
        let view = build_view_from_records(
            &[vec![sample_record(1, 100), sample_record(2, 200)]],
            &mut bc,
        );
        let resolver = Resolver::new(MockProofBackend, bc);
        let entries = resolver.reconstruct(&view).unwrap();
        let (b, per) = compute_outcome(&view, &entries);
        assert!(b);
        assert_eq!(per, vec![true, true]);
    }

    #[test]
    fn test_compute_outcome_threshold_not_met() {
        let mut bc = InMemoryBlobCarrier::new();
        let mut view = build_view_from_records(&[vec![sample_record(1, 100)]], &mut bc);
        view.class_thresholds = vec![1, 1];
        view.class_set = vec![100, 200];
        let resolver = Resolver::new(MockProofBackend, bc);
        let entries = resolver.reconstruct(&view).unwrap();
        let (b, per) = compute_outcome(&view, &entries);
        assert!(!b);
        assert_eq!(per, vec![true, false]);
    }

    #[test]
    fn test_resolve_end_to_end_emits_valid_submission() {
        let mut bc = InMemoryBlobCarrier::new();
        let view = build_view_from_records(
            &[
                vec![sample_record(1, 100), sample_record(2, 200)],
                vec![sample_record(3, 100), sample_record(4, 200)],
            ],
            &mut bc,
        );
        let resolver = Resolver::new(MockProofBackend, bc);
        let submission = resolver.resolve(&view).unwrap();
        let backend = MockProofBackend;
        backend
            .verify_resolution_proof(&submission.proof_bytes, &submission.public_inputs)
            .unwrap();
    }

    #[test]
    fn test_reconstruct_rejects_root_mismatch() {
        let mut bc = InMemoryBlobCarrier::new();
        let mut view = build_view_from_records(&[vec![sample_record(1, 100)]], &mut bc);
        view.running_root = [0xee; 32];
        let resolver = Resolver::new(MockProofBackend, bc);
        let err = resolver.reconstruct(&view);
        assert!(matches!(err, Err(ResolverError::RootMismatch)));
    }
}

//! Disputant actor: build SPEC Dispute envelopes against a published batch.

use crate::{
    blob::fe_index,
    disputant::{
        error::DisputantError,
        types::DisputeContext,
    },
    ports::blob::BlobCarrier,
    poseidon::{
        fr_from_be_bytes,
        hash_leaf,
    },
    types::{
        Dispute,
        KzgOpening,
        RecordEntry,
        ViolationType,
    },
};
use ark_bn254::Fr;

pub struct Disputant<B: BlobCarrier> {
    pub blob_carrier: B,
}

impl<B: BlobCarrier> Disputant<B> {
    pub fn new(blob_carrier: B) -> Self {
        Self { blob_carrier }
    }

    /// Read a record by querying 4 field-element openings.
    fn read_record(
        &self,
        batch_versioned_hash: &[u8; 32],
        position: u32,
    ) -> Result<(RecordEntry, [KzgOpening; 4]), DisputantError> {
        let openings = [
            self.blob_carrier
                .open(batch_versioned_hash, fe_index(position as usize, 0))?,
            self.blob_carrier
                .open(batch_versioned_hash, fe_index(position as usize, 1))?,
            self.blob_carrier
                .open(batch_versioned_hash, fe_index(position as usize, 2))?,
            self.blob_carrier
                .open(batch_versioned_hash, fe_index(position as usize, 3))?,
        ];
        let mut record_bytes = [0u8; crate::RECORD_LEN];
        for (j, o) in openings.iter().enumerate() {
            let start = j * crate::blob::CONTENT_PER_FE;
            let end = ((j + 1) * crate::blob::CONTENT_PER_FE).min(crate::RECORD_LEN);
            let take = end - start;
            record_bytes[start..end].copy_from_slice(&o.claimed_value[1..1 + take]);
        }
        let record = crate::blob::decode_record(&record_bytes);
        Ok((record, openings))
    }

    /// SPEC Dispute 0x01: class_tag at position `i` not in `class_set`.
    pub fn build_class_tag_out_of_set(
        &self,
        ctx: &DisputeContext,
        position_i: u32,
    ) -> Result<Dispute, DisputantError> {
        let (rec_i, openings_i) =
            self.read_record(&ctx.batch_versioned_hash, position_i)?;
        if ctx.class_set.contains(&rec_i.class_tag) {
            return Err(DisputantError::PredicateNotViolated);
        }
        let mut openings = openings_i.to_vec();
        openings.sort_by_key(|o| o.field_element_index);
        Ok(Dispute {
            petition_id: ctx.petition_id,
            batch_index: ctx.batch_index,
            violation_type: ViolationType::ClassTagOutOfSet,
            position_i,
            position_j: None,
            openings,
        })
    }

    /// SPEC Dispute 0x02: positions `i != j` share an identity_tag.
    pub fn build_intra_batch_duplicate_identity_tag(
        &self,
        ctx: &DisputeContext,
        position_i: u32,
        position_j: u32,
    ) -> Result<Dispute, DisputantError> {
        if position_i == position_j {
            return Err(DisputantError::PredicateNotViolated);
        }
        let (rec_i, openings_i) =
            self.read_record(&ctx.batch_versioned_hash, position_i)?;
        let (rec_j, openings_j) =
            self.read_record(&ctx.batch_versioned_hash, position_j)?;
        if rec_i.identity_tag != rec_j.identity_tag {
            return Err(DisputantError::PredicateNotViolated);
        }
        let mut openings: Vec<KzgOpening> =
            openings_i.into_iter().chain(openings_j).collect();
        openings.sort_by_key(|o| o.field_element_index);
        Ok(Dispute {
            petition_id: ctx.petition_id,
            batch_index: ctx.batch_index,
            violation_type: ViolationType::IntraBatchDuplicateIdentityTag,
            position_i,
            position_j: Some(position_j),
            openings,
        })
    }

    /// SPEC Dispute 0x03: leaf ordering violation at `(i, i+1)`.
    pub fn build_leaf_ordering_violation(
        &self,
        ctx: &DisputeContext,
        position_i: u32,
    ) -> Result<Dispute, DisputantError> {
        let position_j = position_i.checked_add(1).ok_or_else(|| {
            DisputantError::Blob(crate::error::BlobError::Malformed(
                "position_i overflow".into(),
            ))
        })?;
        let (rec_i, openings_i) =
            self.read_record(&ctx.batch_versioned_hash, position_i)?;
        let (rec_ip1, openings_ip1) =
            self.read_record(&ctx.batch_versioned_hash, position_j)?;
        let leaf_i = hash_leaf(
            fr_from_be_bytes(&rec_i.nullifier),
            Fr::from(rec_i.class_tag as u64),
        );
        let leaf_ip1 = hash_leaf(
            fr_from_be_bytes(&rec_ip1.nullifier),
            Fr::from(rec_ip1.class_tag as u64),
        );
        if !leaf_ordering_violated(&leaf_i, &leaf_ip1) {
            return Err(DisputantError::PredicateNotViolated);
        }
        let mut openings: Vec<KzgOpening> =
            openings_i.into_iter().chain(openings_ip1).collect();
        openings.sort_by_key(|o| o.field_element_index);
        Ok(Dispute {
            petition_id: ctx.petition_id,
            batch_index: ctx.batch_index,
            violation_type: ViolationType::LeafOrderingViolation,
            position_i,
            position_j: Some(position_j),
            openings,
        })
    }
}

/// Violation predicate: `leaf_i >= leaf_{i+1}` under BE byte ordering.
pub(crate) fn leaf_ordering_violated(leaf_i: &Fr, leaf_ip1: &Fr) -> bool {
    let a = crate::poseidon::fr_to_be_bytes(leaf_i);
    let b = crate::poseidon::fr_to_be_bytes(leaf_ip1);
    a >= b
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::in_memory_blob::InMemoryBlobCarrier;

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

    fn dispute_ctx(vh: [u8; 32], class_set: Vec<u16>) -> DisputeContext {
        let mut pid = [0u8; 32];
        pid[24..].copy_from_slice(&7u64.to_be_bytes());
        DisputeContext {
            petition_id: pid,
            batch_versioned_hash: vh,
            batch_index: 0,
            class_set,
        }
    }

    #[test]
    fn test_build_class_tag_out_of_set_detects_violation() {
        let mut bc = InMemoryBlobCarrier::new();
        let records = vec![sample_record(1, 100), sample_record(2, 999)];
        let vh = bc.publish(&records).unwrap();
        let d = Disputant::new(bc);
        let ctx = dispute_ctx(vh, vec![100, 200]);
        let dispute = d.build_class_tag_out_of_set(&ctx, 1).unwrap();
        assert_eq!(dispute.violation_type, ViolationType::ClassTagOutOfSet);
        assert_eq!(dispute.openings.len(), 4);
    }

    #[test]
    fn test_build_class_tag_out_of_set_no_violation() {
        let mut bc = InMemoryBlobCarrier::new();
        let records = vec![sample_record(1, 100), sample_record(2, 200)];
        let vh = bc.publish(&records).unwrap();
        let d = Disputant::new(bc);
        let ctx = dispute_ctx(vh, vec![100, 200]);
        let err = d.build_class_tag_out_of_set(&ctx, 1);
        assert!(matches!(err, Err(DisputantError::PredicateNotViolated)));
    }

    #[test]
    fn test_build_intra_batch_duplicate_identity_tag_detects_violation() {
        let mut bc = InMemoryBlobCarrier::new();
        let a = sample_record(1, 100);
        let mut b = sample_record(2, 100);
        b.identity_tag = a.identity_tag;
        let records = vec![a, b];
        let vh = bc.publish(&records).unwrap();
        let d = Disputant::new(bc);
        let ctx = dispute_ctx(vh, vec![100, 200]);
        let dispute = d
            .build_intra_batch_duplicate_identity_tag(&ctx, 0, 1)
            .unwrap();
        assert_eq!(
            dispute.violation_type,
            ViolationType::IntraBatchDuplicateIdentityTag
        );
        assert_eq!(dispute.position_j, Some(1));
    }

    #[test]
    fn test_build_intra_batch_duplicate_identity_tag_no_violation() {
        let mut bc = InMemoryBlobCarrier::new();
        let records = vec![sample_record(1, 100), sample_record(2, 100)];
        let vh = bc.publish(&records).unwrap();
        let d = Disputant::new(bc);
        let ctx = dispute_ctx(vh, vec![100, 200]);
        let err = d.build_intra_batch_duplicate_identity_tag(&ctx, 0, 1);
        assert!(matches!(err, Err(DisputantError::PredicateNotViolated)));
    }

    #[test]
    fn test_build_leaf_ordering_violation_detects_violation() {
        let mut bc = InMemoryBlobCarrier::new();
        let records = vec![sample_record(99, 100), sample_record(1, 100)];
        let leaf0 = hash_leaf(
            fr_from_be_bytes(&records[0].nullifier),
            Fr::from(records[0].class_tag as u64),
        );
        let leaf1 = hash_leaf(
            fr_from_be_bytes(&records[1].nullifier),
            Fr::from(records[1].class_tag as u64),
        );
        let records = if crate::poseidon::fr_to_be_bytes(&leaf0)
            < crate::poseidon::fr_to_be_bytes(&leaf1)
        {
            vec![records[1], records[0]]
        } else {
            records
        };
        let leaf0 = hash_leaf(
            fr_from_be_bytes(&records[0].nullifier),
            Fr::from(records[0].class_tag as u64),
        );
        let leaf1 = hash_leaf(
            fr_from_be_bytes(&records[1].nullifier),
            Fr::from(records[1].class_tag as u64),
        );
        assert!(super::leaf_ordering_violated(&leaf0, &leaf1));

        let vh = bc.publish(&records).unwrap();
        let d = Disputant::new(bc);
        let ctx = dispute_ctx(vh, vec![100, 200]);
        let dispute = d.build_leaf_ordering_violation(&ctx, 0).unwrap();
        assert_eq!(dispute.violation_type, ViolationType::LeafOrderingViolation);
    }
}

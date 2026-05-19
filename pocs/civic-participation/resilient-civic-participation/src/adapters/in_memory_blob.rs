//! In-process EIP-4844 blob carrier. The "opening proof" is a SHA-256 tag
//! that lets `verify` re-derive what `open` returned; the security boundary
//! is the locally stored payload, not the digest (forging would require the
//! same blob bytes to be present).

use std::collections::HashMap;

use sha2::{
    Digest,
    Sha256,
};

use crate::{
    blob::{
        compute_batch_versioned_hash,
        encode_blob,
    },
    error::BlobError,
    ports::blob::BlobCarrier,
    types::{
        Bytes32,
        KzgOpening,
        RecordEntry,
    },
};

struct BlobEntry {
    fes: Vec<[u8; 32]>,
    records: Vec<RecordEntry>,
}

#[derive(Default)]
pub struct InMemoryBlobCarrier {
    blobs: HashMap<Bytes32, BlobEntry>,
}

impl InMemoryBlobCarrier {
    pub fn new() -> Self {
        Self::default()
    }

    fn opening_proof_bytes(
        versioned_hash: &Bytes32,
        index: u32,
        value: &Bytes32,
    ) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"RCP-mock-kzg/v1");
        h.update(versioned_hash);
        h.update(index.to_be_bytes());
        h.update(value);
        h.finalize().to_vec()
    }
}

impl BlobCarrier for InMemoryBlobCarrier {
    fn publish(&mut self, records: &[RecordEntry]) -> Result<Bytes32, BlobError> {
        let fes = encode_blob(records)?;
        let vh = compute_batch_versioned_hash(&fes);
        self.blobs.insert(
            vh,
            BlobEntry {
                fes,
                records: records.to_vec(),
            },
        );
        Ok(vh)
    }

    fn open(
        &self,
        batch_versioned_hash: &Bytes32,
        field_element_index: u32,
    ) -> Result<KzgOpening, BlobError> {
        let entry = self
            .blobs
            .get(batch_versioned_hash)
            .ok_or(BlobError::NotFound)?;
        let idx = field_element_index as usize;
        if idx >= entry.fes.len() {
            return Err(BlobError::Malformed(format!(
                "fe index {idx} out of range (blob len {})",
                entry.fes.len()
            )));
        }
        let value = entry.fes[idx];
        Ok(KzgOpening {
            field_element_index,
            claimed_value: value,
            proof_bytes: Self::opening_proof_bytes(
                batch_versioned_hash,
                field_element_index,
                &value,
            ),
        })
    }

    fn verify(
        &self,
        batch_versioned_hash: &Bytes32,
        opening: &KzgOpening,
    ) -> Result<(), BlobError> {
        let entry = self
            .blobs
            .get(batch_versioned_hash)
            .ok_or(BlobError::NotFound)?;
        let idx = opening.field_element_index as usize;
        if idx >= entry.fes.len() {
            return Err(BlobError::InvalidOpening(format!(
                "fe index {idx} out of range (blob len {})",
                entry.fes.len()
            )));
        }
        if entry.fes[idx] != opening.claimed_value {
            return Err(BlobError::InvalidOpening(
                "opening claims a value the published blob does not carry".into(),
            ));
        }
        let expected = Self::opening_proof_bytes(
            batch_versioned_hash,
            opening.field_element_index,
            &opening.claimed_value,
        );
        if expected != opening.proof_bytes {
            return Err(BlobError::InvalidOpening(
                "mock KZG opening proof mismatch".into(),
            ));
        }
        Ok(())
    }

    fn fetch_records(
        &self,
        batch_versioned_hash: &Bytes32,
    ) -> Result<Vec<RecordEntry>, BlobError> {
        self.blobs
            .get(batch_versioned_hash)
            .map(|e| e.records.clone())
            .ok_or(BlobError::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(i: u64) -> RecordEntry {
        let mut nullifier = [0u8; 32];
        nullifier[24..].copy_from_slice(&i.to_be_bytes());
        let mut identity_tag = [0u8; 32];
        identity_tag[24..].copy_from_slice(&(i + 1).to_be_bytes());
        RecordEntry {
            nullifier,
            identity_tag,
            class_tag: (i as u16) + 100,
        }
    }

    #[test]
    fn test_publish_open_verify_roundtrip() {
        let mut bc = InMemoryBlobCarrier::new();
        let r = sample_record(1);
        let vh = bc.publish(&[r]).unwrap();
        let opening = bc.open(&vh, 0).unwrap();
        bc.verify(&vh, &opening).unwrap();
        assert_eq!(opening.field_element_index, 0);
    }

    #[test]
    fn test_fetch_records_returns_published_set() {
        let mut bc = InMemoryBlobCarrier::new();
        let records = vec![sample_record(1), sample_record(2), sample_record(3)];
        let vh = bc.publish(&records).unwrap();
        let fetched = bc.fetch_records(&vh).unwrap();
        assert_eq!(fetched, records);
    }

    #[test]
    fn test_open_unknown_versioned_hash_errors() {
        let bc = InMemoryBlobCarrier::new();
        let err = bc.open(&[0u8; 32], 0);
        assert!(matches!(err, Err(BlobError::NotFound)));
    }

    #[test]
    fn test_verify_rejects_tampered_value() {
        let mut bc = InMemoryBlobCarrier::new();
        let vh = bc.publish(&[sample_record(1)]).unwrap();
        let mut opening = bc.open(&vh, 0).unwrap();
        opening.claimed_value[0] ^= 0x01;
        let err = bc.verify(&vh, &opening);
        assert!(matches!(err, Err(BlobError::InvalidOpening(_))));
    }

    #[test]
    fn test_verify_rejects_wrong_versioned_hash() {
        let mut bc = InMemoryBlobCarrier::new();
        let vh = bc.publish(&[sample_record(1)]).unwrap();
        let opening = bc.open(&vh, 0).unwrap();
        let bad_vh = [0x55; 32];
        let err = bc.verify(&bad_vh, &opening);
        assert!(matches!(err, Err(BlobError::NotFound)));
    }

    #[test]
    fn test_verify_rejects_forged_value_for_existing_blob() {
        // Forged opening must be rejected even when proof_bytes re-derives cleanly.
        let mut bc = InMemoryBlobCarrier::new();
        let vh = bc.publish(&[sample_record(1)]).unwrap();
        let real_opening = bc.open(&vh, 0).unwrap();
        let mut forged = real_opening.clone();
        forged.claimed_value = [0x66; 32];
        forged.proof_bytes = InMemoryBlobCarrier::opening_proof_bytes(
            &vh,
            forged.field_element_index,
            &forged.claimed_value,
        );
        let err = bc.verify(&vh, &forged);
        assert!(matches!(err, Err(BlobError::InvalidOpening(_))));
    }
}

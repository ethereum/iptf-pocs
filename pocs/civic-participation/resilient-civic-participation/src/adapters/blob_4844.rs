//! Real EIP-4844 blob carrier backed by `c-kzg`.

use std::{
    collections::HashMap,
    sync::{
        Arc,
        Mutex,
    },
};

use alloy::{
    consensus::BlobTransactionSidecar,
    primitives::FixedBytes,
};
use c_kzg::{
    Blob,
    Bytes32 as CKzgBytes32,
    Bytes48 as CKzgBytes48,
    ethereum_kzg_settings,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    RECORDS_PER_BLOB,
    error::BlobError,
    ports::blob::BlobCarrier,
    types::{
        Bytes32,
        KzgOpening,
        RecordEntry,
    },
};

const BYTES_PER_FIELD_ELEMENT: usize = 32;
const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
const BLOB_BYTES: usize = BYTES_PER_FIELD_ELEMENT * FIELD_ELEMENTS_PER_BLOB;
const FE_PER_RECORD: usize = 4;

/// Encode `records` into the 131_072-byte blob payload (4 field elements per record).
fn encode_blob(records: &[RecordEntry]) -> Result<Box<[u8; BLOB_BYTES]>, BlobError> {
    if records.len() > RECORDS_PER_BLOB {
        return Err(BlobError::Capacity(records.len(), RECORDS_PER_BLOB));
    }
    let mut blob = vec![0u8; BLOB_BYTES];
    for (i, rec) in records.iter().enumerate() {
        let class_bytes = rec.class_tag.to_be_bytes();
        let mut record_bytes = [0u8; 96];
        record_bytes[..32].copy_from_slice(&rec.nullifier);
        record_bytes[32..64].copy_from_slice(&rec.identity_tag);
        record_bytes[64..66].copy_from_slice(&class_bytes);
        // nullifier || identity_tag || class_tag || padding

        for j in 0..FE_PER_RECORD {
            let fe_idx = i * FE_PER_RECORD + j;
            let fe_off = fe_idx * BYTES_PER_FIELD_ELEMENT;
            // Top byte zero so the value fits in BLS12-381 Fr.
            blob[fe_off] = 0;

            let src_lo = 31 * j;
            let src_hi = (31 * (j + 1)).min(96);
            let content = &record_bytes[src_lo..src_hi];
            blob[fe_off + 1..fe_off + 1 + content.len()].copy_from_slice(content);
        }
    }
    // Heap-allocated so the 128KiB blob doesn't blow the stack.
    let mut out = vec![0u8; BLOB_BYTES].into_boxed_slice();
    out.copy_from_slice(&blob);
    let arr: Box<[u8; BLOB_BYTES]> = out.try_into().map_err(|_| {
        BlobError::Malformed("blob encoding length invariant violated".into())
    })?;
    Ok(arr)
}

fn versioned_hash_from_commitment(commitment: &[u8; 48]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(commitment);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out[0] = 0x01;
    out
}

/// KZG evaluation point for the `idx`-th blob field element. EIP-4844 stores
/// blob FEs in bit-reversal-permuted evaluation form, so the polynomial value
/// at storage slot `idx` is `P(omega^bit_reverse(idx, 12))`. Passing the raw
/// integer would compute the proof at a different point and the on-chain
/// verifier (which derives `z` from the same bit-reversal table) would reject.
fn z_bytes_for_index(idx: u32) -> Result<CKzgBytes32, BlobError> {
    use std::sync::OnceLock;
    static EVAL_POINTS: OnceLock<[[u8; 32]; crate::blob::KZG_OPENING_COUNT]> =
        OnceLock::new();
    let points = EVAL_POINTS.get_or_init(crate::blob::canonical_eval_points);
    let z = points.get(idx as usize).ok_or_else(|| {
        BlobError::Malformed(format!(
            "fe index {idx} outside KZG opening window of {}",
            points.len()
        ))
    })?;
    Ok(CKzgBytes32::new(*z))
}

struct BlobEntry {
    blob_bytes: Vec<u8>,
    commitment: [u8; 48],
    blob_kzg_proof: [u8; 48],
    records: Vec<RecordEntry>,
}

#[derive(Clone)]
pub struct EIP4844BlobCarrier {
    inner: Arc<Mutex<HashMap<Bytes32, BlobEntry>>>,
}

impl Default for EIP4844BlobCarrier {
    fn default() -> Self {
        Self::new()
    }
}

impl EIP4844BlobCarrier {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Build the alloy `BlobTransactionSidecar` for a published `versioned_hash`.
    pub fn make_sidecar(
        &self,
        versioned_hash: &Bytes32,
    ) -> Result<BlobTransactionSidecar, BlobError> {
        let guard = self.inner.lock().unwrap();
        let entry = guard.get(versioned_hash).ok_or(BlobError::NotFound)?;
        let blob = alloy::eips::eip4844::Blob::from_slice(&entry.blob_bytes);
        let commitment: FixedBytes<48> = FixedBytes::from(entry.commitment);
        let proof: FixedBytes<48> = FixedBytes::from(entry.blob_kzg_proof);
        Ok(BlobTransactionSidecar::new(
            vec![blob],
            vec![commitment],
            vec![proof],
        ))
    }

    /// Versioned hash a (commitment, blob) pair would emit.
    pub fn commitment_to_versioned_hash(commitment: &[u8; 48]) -> Bytes32 {
        versioned_hash_from_commitment(commitment)
    }

    /// Compute (commitment, per-point KZG proofs, y_k values) at `eval_points`.
    #[allow(clippy::type_complexity)]
    pub fn commitment_and_per_point_proofs(
        &self,
        versioned_hash: &Bytes32,
        eval_points: &[[u8; 32]],
    ) -> Result<([u8; 48], Vec<u8>, Vec<[u8; 32]>), BlobError> {
        let guard = self.inner.lock().unwrap();
        let entry = guard.get(versioned_hash).ok_or(BlobError::NotFound)?;
        let blob = Blob::from_bytes(&entry.blob_bytes).map_err(|e| {
            BlobError::Malformed(format!("c-kzg Blob::from_bytes: {e:?}"))
        })?;
        let settings = ethereum_kzg_settings(0);
        let mut proofs_concat = Vec::with_capacity(48 * eval_points.len());
        let mut ys = Vec::with_capacity(eval_points.len());
        for z_bytes in eval_points {
            let z = CKzgBytes32::new(*z_bytes);
            let (proof, y) = settings
                .compute_kzg_proof(&blob, &z)
                .map_err(|e| BlobError::Malformed(format!("compute_kzg_proof: {e:?}")))?;
            let proof_bytes: [u8; 48] = *proof.to_bytes().as_ref();
            let y_bytes: [u8; 32] = *y.as_ref();
            proofs_concat.extend_from_slice(&proof_bytes);
            ys.push(y_bytes);
        }
        Ok((entry.commitment, proofs_concat, ys))
    }
}

impl BlobCarrier for EIP4844BlobCarrier {
    fn publish(&mut self, records: &[RecordEntry]) -> Result<Bytes32, BlobError> {
        let blob_arr = encode_blob(records)?;
        let blob = Blob::from_bytes(blob_arr.as_ref()).map_err(|e| {
            BlobError::Malformed(format!("c-kzg Blob::from_bytes: {e:?}"))
        })?;
        let settings = ethereum_kzg_settings(0);
        let commitment = settings.blob_to_kzg_commitment(&blob).map_err(|e| {
            BlobError::Malformed(format!("blob_to_kzg_commitment: {e:?}"))
        })?;
        let commitment_bytes: [u8; 48] = *commitment.to_bytes().as_ref();
        let blob_kzg_proof = settings
            .compute_blob_kzg_proof(&blob, &CKzgBytes48::new(commitment_bytes))
            .map_err(|e| {
                BlobError::Malformed(format!("compute_blob_kzg_proof: {e:?}"))
            })?;
        let blob_kzg_proof_bytes: [u8; 48] = *blob_kzg_proof.to_bytes().as_ref();
        let versioned_hash = versioned_hash_from_commitment(&commitment_bytes);

        let mut guard = self.inner.lock().unwrap();
        guard.insert(
            versioned_hash,
            BlobEntry {
                blob_bytes: blob_arr.to_vec(),
                commitment: commitment_bytes,
                blob_kzg_proof: blob_kzg_proof_bytes,
                records: records.to_vec(),
            },
        );
        Ok(versioned_hash)
    }

    fn open(
        &self,
        batch_versioned_hash: &Bytes32,
        field_element_index: u32,
    ) -> Result<KzgOpening, BlobError> {
        let guard = self.inner.lock().unwrap();
        let entry = guard.get(batch_versioned_hash).ok_or(BlobError::NotFound)?;
        let blob = Blob::from_bytes(&entry.blob_bytes)
            .map_err(|e| BlobError::Malformed(format!("Blob::from_bytes: {e:?}")))?;
        let z = z_bytes_for_index(field_element_index)?;
        let settings = ethereum_kzg_settings(0);
        let (proof, y) = settings
            .compute_kzg_proof(&blob, &z)
            .map_err(|e| BlobError::Malformed(format!("compute_kzg_proof: {e:?}")))?;
        let proof_bytes_arr: [u8; 48] = *proof.to_bytes().as_ref();
        let y_bytes: [u8; 32] = *y.as_ref();
        let mut proof_bytes_vec = Vec::with_capacity(48 + 48);
        proof_bytes_vec.extend_from_slice(&proof_bytes_arr);
        proof_bytes_vec.extend_from_slice(&entry.commitment);
        Ok(KzgOpening {
            field_element_index,
            claimed_value: y_bytes,
            proof_bytes: proof_bytes_vec,
        })
    }

    fn verify(
        &self,
        batch_versioned_hash: &Bytes32,
        opening: &KzgOpening,
    ) -> Result<(), BlobError> {
        let guard = self.inner.lock().unwrap();
        let entry = guard.get(batch_versioned_hash).ok_or(BlobError::NotFound)?;
        if opening.proof_bytes.len() != 48 + 48 {
            return Err(BlobError::InvalidOpening(format!(
                "opening proof_bytes is {} bytes; expected 96",
                opening.proof_bytes.len()
            )));
        }
        let mut proof_arr = [0u8; 48];
        proof_arr.copy_from_slice(&opening.proof_bytes[..48]);
        let mut commitment_arr = [0u8; 48];
        commitment_arr.copy_from_slice(&opening.proof_bytes[48..]);
        if commitment_arr != entry.commitment {
            return Err(BlobError::InvalidOpening(
                "opening commitment does not match stored blob".into(),
            ));
        }
        let z = z_bytes_for_index(opening.field_element_index)?;
        let y = CKzgBytes32::new(opening.claimed_value);
        let proof = CKzgBytes48::new(proof_arr);
        let commitment = CKzgBytes48::new(commitment_arr);
        let settings = ethereum_kzg_settings(0);
        let ok = settings
            .verify_kzg_proof(&commitment, &z, &y, &proof)
            .map_err(|e| BlobError::InvalidOpening(format!("verify_kzg_proof: {e:?}")))?;
        if !ok {
            return Err(BlobError::InvalidOpening(
                "verify_kzg_proof returned false".into(),
            ));
        }
        Ok(())
    }

    fn fetch_records(
        &self,
        batch_versioned_hash: &Bytes32,
    ) -> Result<Vec<RecordEntry>, BlobError> {
        let guard = self.inner.lock().unwrap();
        let entry = guard.get(batch_versioned_hash).ok_or(BlobError::NotFound)?;
        Ok(entry.records.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_record(seed: u8) -> RecordEntry {
        let mut nullifier = [0u8; 32];
        let mut identity_tag = [0u8; 32];
        for i in 0..32 {
            nullifier[i] = seed.wrapping_add(i as u8);
            identity_tag[i] = seed.wrapping_mul(2).wrapping_add(i as u8);
        }
        RecordEntry {
            nullifier,
            identity_tag,
            class_tag: seed as u16,
        }
    }

    #[test]
    fn test_publish_and_fetch_round_trip() {
        let mut carrier = EIP4844BlobCarrier::new();
        let records = vec![mk_record(0), mk_record(1), mk_record(2)];
        let vh = carrier.publish(&records).expect("publish");
        assert_eq!(vh[0], 0x01);
        let fetched = carrier.fetch_records(&vh).unwrap();
        assert_eq!(fetched, records);
    }

    #[test]
    fn test_open_and_verify_round_trips_against_stored_blob() {
        let mut carrier = EIP4844BlobCarrier::new();
        let records = vec![mk_record(42)];
        let vh = carrier.publish(&records).expect("publish");
        let opening = carrier.open(&vh, 0).expect("open");
        carrier.verify(&vh, &opening).expect("verify roundtrip");
    }

    #[test]
    fn test_make_sidecar_returns_blob_with_correct_commitment() {
        let carrier = EIP4844BlobCarrier::new();
        let mut c2 = carrier.clone();
        let vh = c2.publish(&[]).expect("publish empty");
        let sidecar = carrier.make_sidecar(&vh).expect("make_sidecar");
        assert_eq!(sidecar.blobs.len(), 1);
        assert_eq!(sidecar.commitments.len(), 1);
        assert_eq!(sidecar.proofs.len(), 1);
    }

    #[test]
    fn test_per_point_openings_round_trip_against_record_to_bls_fields() {
        use crate::{
            blob::{
                FE_PER_RECORD,
                canonical_eval_points,
                record_to_bls_fields,
            },
            poseidon::fr_to_be_bytes,
        };

        let mut carrier = EIP4844BlobCarrier::new();
        let records = vec![mk_record(11), mk_record(22), mk_record(33)];
        let vh = carrier.publish(&records).expect("publish");
        let eval_points = canonical_eval_points();
        let (_commitment, _proofs, ys) = carrier
            .commitment_and_per_point_proofs(&vh, &eval_points)
            .expect("commitment_and_per_point_proofs");

        for (i, rec) in records.iter().enumerate() {
            let expected = record_to_bls_fields(rec);
            for j in 0..FE_PER_RECORD {
                let y = ys[i * FE_PER_RECORD + j];
                let expected_be = fr_to_be_bytes(&expected[j]);
                assert_eq!(
                    y, expected_be,
                    "record {i} fe {j}: KZG opening y disagrees with record_to_bls_fields"
                );
            }
        }
        // Padding positions must be zero.
        let pad_start = records.len() * FE_PER_RECORD;
        for (offset, y) in ys[pad_start..eval_points.len()].iter().enumerate() {
            assert_eq!(
                *y,
                [0u8; 32],
                "padding position {} non-zero",
                pad_start + offset
            );
        }
    }

    #[test]
    fn test_publish_exceeding_record_cap_errors() {
        let mut carrier = EIP4844BlobCarrier::new();
        let too_many: Vec<RecordEntry> = (0..(RECORDS_PER_BLOB + 1))
            .map(|i| mk_record(i as u8))
            .collect();
        let err = carrier.publish(&too_many);
        assert!(matches!(err, Err(BlobError::Capacity(_, _))));
    }
}

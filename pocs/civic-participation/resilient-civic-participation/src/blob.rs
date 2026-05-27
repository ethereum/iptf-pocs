//! EIP-4844 blob payload encoder / decoder (SPEC Blob Payload).

use ark_bls12_381::Fr as BlsFr;
use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    FftField,
    Field,
    PrimeField,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    RECORD_LEN,
    RECORDS_PER_BLOB,
    error::BlobError,
    poseidon::fr_from_be_bytes,
    types::{
        Bytes32,
        RecordEntry,
    },
};

/// Number of distinct (record, field-element) positions that the
/// contract verifies via KZG point-evaluation on `publishBatch`.
/// Equal to `BATCH_SIZE_MAX * FE_PER_RECORD` = 6 * 4.
pub const KZG_OPENING_COUNT: usize = crate::BATCH_SIZE_MAX * FE_PER_RECORD;

/// EIP-4844 blob size: 4096 BLS12-381 field elements.
const BLOB_FIELD_ELEMENTS: u64 = 4096;

pub const FE_PER_RECORD: usize = 4;
pub const CONTENT_PER_FE: usize = 31;

pub fn fe_index(i: usize, j: usize) -> u32 {
    (FE_PER_RECORD * i + j) as u32
}

/// Encode a record into its 96-byte canonical form.
pub fn encode_record(r: &RecordEntry) -> [u8; RECORD_LEN] {
    let mut out = [0u8; RECORD_LEN];
    out[0..32].copy_from_slice(&r.nullifier);
    out[32..64].copy_from_slice(&r.identity_tag);
    out[64..66].copy_from_slice(&r.class_tag.to_be_bytes());
    out
}

/// Decode a record from its 96-byte canonical form.
pub fn decode_record(bytes: &[u8; RECORD_LEN]) -> RecordEntry {
    let mut nullifier = [0u8; 32];
    nullifier.copy_from_slice(&bytes[0..32]);
    let mut identity_tag = [0u8; 32];
    identity_tag.copy_from_slice(&bytes[32..64]);
    let class_tag = u16::from_be_bytes([bytes[64], bytes[65]]);
    RecordEntry {
        nullifier,
        identity_tag,
        class_tag,
    }
}

/// Encode `records` into the field-element byte string, padded to `RECORDS_PER_BLOB`.
pub fn encode_blob(records: &[RecordEntry]) -> Result<Vec<[u8; 32]>, BlobError> {
    if records.len() > RECORDS_PER_BLOB {
        return Err(BlobError::Capacity(records.len(), RECORDS_PER_BLOB));
    }
    let mut out: Vec<[u8; 32]> = Vec::with_capacity(RECORDS_PER_BLOB * FE_PER_RECORD);
    for i in 0..RECORDS_PER_BLOB {
        let record_bytes = if i < records.len() {
            encode_record(&records[i])
        } else {
            [0u8; RECORD_LEN]
        };
        for j in 0..FE_PER_RECORD {
            let mut fe = [0u8; 32];
            let start = j * CONTENT_PER_FE;
            let end = ((j + 1) * CONTENT_PER_FE).min(RECORD_LEN);
            let take = end - start;
            fe[1..1 + take].copy_from_slice(&record_bytes[start..end]);
            out.push(fe);
        }
    }
    Ok(out)
}

/// Decode the field-element byte string back to records.
pub fn decode_blob(field_elements: &[[u8; 32]]) -> Result<Vec<RecordEntry>, BlobError> {
    if field_elements.len() != RECORDS_PER_BLOB * FE_PER_RECORD {
        return Err(BlobError::Malformed(format!(
            "blob has {} field elements, expected {}",
            field_elements.len(),
            RECORDS_PER_BLOB * FE_PER_RECORD
        )));
    }
    let mut records = Vec::with_capacity(RECORDS_PER_BLOB);
    for i in 0..RECORDS_PER_BLOB {
        let mut record_bytes = [0u8; RECORD_LEN];
        for j in 0..FE_PER_RECORD {
            let fe = &field_elements[FE_PER_RECORD * i + j];
            let start = j * CONTENT_PER_FE;
            let end = ((j + 1) * CONTENT_PER_FE).min(RECORD_LEN);
            let take = end - start;
            record_bytes[start..end].copy_from_slice(&fe[1..1 + take]);
        }
        if record_bytes[..66].iter().all(|&b| b == 0) {
            break;
        }
        records.push(decode_record(&record_bytes));
    }
    Ok(records)
}

/// `batch_versioned_hash`: SHA-256 over field-element bytes; high byte zeroed
/// so the value fits in a BN254 scalar without reduction.
pub fn compute_batch_versioned_hash(field_elements: &[[u8; 32]]) -> Bytes32 {
    let mut h = Sha256::new();
    for fe in field_elements {
        h.update(fe);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out[0] = 0;
    out
}

/// Recompute the 4 BLS12-381 field elements occupied by `record` per
/// SPEC Blob Payload. The returned values are BN254 scalars whose
/// numeric value matches the corresponding 32-byte BLS field element
/// (each fe has its high byte zero, so the value fits in either field
/// without reduction). Mirrors `circuits/lib/src/blob.nr::record_to_fields`.
pub fn record_to_bls_fields(record: &RecordEntry) -> [Fr; FE_PER_RECORD] {
    let bytes = encode_record(record);
    let mut out = [Fr::from(0u64); FE_PER_RECORD];
    for (j, slot) in out.iter_mut().enumerate() {
        let start = j * CONTENT_PER_FE;
        let end = ((j + 1) * CONTENT_PER_FE).min(RECORD_LEN);
        let mut fe_bytes = [0u8; 32];
        fe_bytes[1..1 + (end - start)].copy_from_slice(&bytes[start..end]);
        *slot = fr_from_be_bytes(&fe_bytes);
    }
    out
}

/// Bit-reversal permutation for a `log_n`-bit index. EIP-4844 stores blob
/// field elements in bit-reversal-permuted evaluation form: the k-th stored
/// 32-byte chunk equals the polynomial evaluated at `omega^{bit_reverse(k, log_n)}`.
fn bit_reverse(k: u32, log_n: u32) -> u32 {
    k.reverse_bits() >> (32 - log_n)
}

/// Canonical evaluation points used by the SPEC's constraint 8 KZG
/// binding: `z_k = omega^{bit_reverse(k, 12)}` where `omega` is the
/// primitive 4096th root of unity in BLS12-381 Fr (EIP-4844 stores blobs
/// in bit-reversal-permuted evaluation form). Returns `KZG_OPENING_COUNT`
/// 32-byte big-endian encodings.
///
/// The contract uses the same `omega` and bit-reversal table (hardcoded)
/// to derive `z_k` on chain; the relayer uses these bytes to call
/// `c-kzg::compute_kzg_proof(blob, z_k)`.
pub fn canonical_eval_points() -> [[u8; 32]; KZG_OPENING_COUNT] {
    let omega = BlsFr::get_root_of_unity(BLOB_FIELD_ELEMENTS)
        .expect("BLS12-381 Fr must have a 4096th root of unity");
    let log_n = BLOB_FIELD_ELEMENTS.trailing_zeros();
    let mut out = [[0u8; 32]; KZG_OPENING_COUNT];
    for (k, slot) in out.iter_mut().enumerate() {
        let exponent = bit_reverse(k as u32, log_n) as u64;
        let z = omega.pow([exponent]);
        *slot = bls_fr_to_be_bytes(&z);
    }
    out
}

/// `omega` (primitive 4096th root of unity in BLS12-381 Fr), encoded
/// big-endian. Exposed so the Solidity constant table can be
/// generated/checked.
pub fn bls_omega_4096_be() -> [u8; 32] {
    let omega = BlsFr::get_root_of_unity(BLOB_FIELD_ELEMENTS)
        .expect("BLS12-381 Fr must have a 4096th root of unity");
    bls_fr_to_be_bytes(&omega)
}

fn bls_fr_to_be_bytes(fr: &BlsFr) -> [u8; 32] {
    let be = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
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
    fn test_encode_decode_record_roundtrip() {
        let r = sample_record(7);
        let bytes = encode_record(&r);
        let back = decode_record(&bytes);
        assert_eq!(r, back);
    }

    #[test]
    fn test_encode_blob_pads_to_full_capacity() {
        let records = [sample_record(1), sample_record(2), sample_record(3)];
        let fes = encode_blob(&records).unwrap();
        assert_eq!(fes.len(), RECORDS_PER_BLOB * FE_PER_RECORD);
        let back = decode_blob(&fes).unwrap();
        assert_eq!(back.len(), records.len());
        for (a, b) in records.iter().zip(back.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_encode_blob_rejects_overflow() {
        let records = vec![sample_record(0); RECORDS_PER_BLOB + 1];
        let err = encode_blob(&records);
        assert!(matches!(err, Err(BlobError::Capacity(_, _))));
    }

    #[test]
    fn test_compute_batch_versioned_hash_deterministic_and_distinct() {
        let r1 = [sample_record(1)];
        let r2 = [sample_record(2)];
        let h1 = compute_batch_versioned_hash(&encode_blob(&r1).unwrap());
        let h2 = compute_batch_versioned_hash(&encode_blob(&r2).unwrap());
        let h1b = compute_batch_versioned_hash(&encode_blob(&r1).unwrap());
        assert_eq!(h1, h1b);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_fe_index_layout() {
        assert_eq!(fe_index(0, 0), 0);
        assert_eq!(fe_index(0, 3), 3);
        assert_eq!(fe_index(1, 0), 4);
        assert_eq!(fe_index(999, 3), 3999);
    }

    #[test]
    fn test_decode_blob_rejects_wrong_length() {
        let fe = vec![[0u8; 32]; 10];
        let err = decode_blob(&fe);
        assert!(matches!(err, Err(BlobError::Malformed(_))));
    }

    #[test]
    fn test_field_element_high_byte_zero() {
        let r = sample_record(42);
        let fes = encode_blob(&[r]).unwrap();
        for (i, fe) in fes.iter().enumerate() {
            assert_eq!(fe[0], 0, "fe {i} has non-zero high byte");
        }
    }

    /// Codegen helper masquerading as a test. Run with
    /// `cargo test print_omega_constants -- --ignored --nocapture` to dump the
    /// Solidity-side constants (`omega`, BLS Fr modulus, 24 canonical z_k points).
    #[test]
    #[ignore]
    fn print_omega_constants() {
        let omega = bls_omega_4096_be();
        eprintln!("BLS_FR_OMEGA_4096 = 0x{}", hex::encode(omega));
        eprintln!(
            "BLS_FR_MODULUS    = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"
        );
        let pts = canonical_eval_points();
        for (k, p) in pts.iter().enumerate() {
            eprintln!("z[{k}] = 0x{}", hex::encode(p));
        }
    }

    #[test]
    fn test_canonical_eval_points_first_is_one() {
        let pts = canonical_eval_points();
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(pts[0], expected, "z_0 must equal Fr(1)");
    }

    #[test]
    fn test_canonical_eval_points_distinct() {
        let pts = canonical_eval_points();
        for i in 0..KZG_OPENING_COUNT {
            for j in (i + 1)..KZG_OPENING_COUNT {
                assert_ne!(pts[i], pts[j], "z_{i} == z_{j}");
            }
        }
    }

    #[test]
    fn test_record_to_bls_fields_high_byte_zero() {
        let r = sample_record(7);
        let fes = record_to_bls_fields(&r);
        for (k, fe) in fes.iter().enumerate() {
            let be = crate::poseidon::fr_to_be_bytes(fe);
            assert_eq!(be[0], 0, "fe {k} has non-zero high byte");
        }
    }

    #[test]
    fn test_record_to_bls_fields_matches_encode_blob() {
        // Cross-check: record_to_bls_fields agrees with the per-position
        // bytes that encode_blob writes into the blob payload.
        let records = [sample_record(7), sample_record(13)];
        let fes_bytes = encode_blob(&records).unwrap();
        for (i, r) in records.iter().enumerate() {
            let fes = record_to_bls_fields(r);
            for j in 0..FE_PER_RECORD {
                let blob_fe = &fes_bytes[i * FE_PER_RECORD + j];
                let computed_fe = crate::poseidon::fr_to_be_bytes(&fes[j]);
                assert_eq!(
                    blob_fe, &computed_fe,
                    "record {i} fe {j}: encode_blob bytes != record_to_bls_fields"
                );
            }
        }
    }

    #[test]
    fn test_record_padding_preserved() {
        let r = sample_record(123);
        let bytes = encode_record(&r);
        for b in &bytes[66..96] {
            assert_eq!(*b, 0);
        }
    }
}

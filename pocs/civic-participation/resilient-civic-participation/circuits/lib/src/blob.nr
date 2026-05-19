// Cross-field decomposition between the BN254 in-circuit scalars and
// the BLS12-381 field elements that make up an EIP-4844 blob (SPEC
// section Blob Payload).
//
// Each `RecordEntry` occupies 4 BLS12-381 field elements with layout:
//   fe(4i + 0) = 0x00 || nullifier_bytes[0..31]
//   fe(4i + 1) = 0x00 || nullifier_bytes[31..32] || identity_tag_bytes[0..30]
//   fe(4i + 2) = 0x00 || identity_tag_bytes[30..32] || class_tag_bytes[0..2] || padding[0..27]
//   fe(4i + 3) = 0x00 || padding[27..30] || zeros[3..31]
//
// The on-chain registry derives the four-element opening of each record
// from the blob KZG commitments and binds them into `batch_versioned_hash`
// via constraint 8. Inside the batch circuit we recompute the four
// field-element values from the in-circuit `(nullifier_i, identity_tag_i,
// class_tag_i)` and constrain equality.

pub struct RecordFields {
    pub fe0: Field,
    pub fe1: Field,
    pub fe2: Field,
    pub fe3: Field,
}

// Decompose a 32-byte big-endian Field into 32 bytes (range-checked).
pub fn field_to_be_bytes_32(f: Field) -> [u8; 32] {
    let bytes: [u8; 32] = f.to_be_bytes();
    bytes
}

// Assemble a BLS12-381 field element from at most 31 content bytes
// prefixed with a leading 0x00 byte. The high byte clearing keeps the
// value within the BLS scalar field for any 31-byte payload.
pub fn assemble_bls_fe(bytes: [u8; 31]) -> Field {
    let mut acc: Field = 0;
    for i in 0..31 {
        acc = acc * 256 + bytes[i] as Field;
    }
    acc
}

// Recompute the four BLS12-381 field elements for the i-th record.
pub fn record_to_fields(nullifier: Field, identity_tag: Field, class_tag: Field) -> RecordFields {
    let null_bytes = field_to_be_bytes_32(nullifier);
    let idtag_bytes = field_to_be_bytes_32(identity_tag);
    let class_bytes: [u8; 32] = class_tag.to_be_bytes();

    // fe0: 31 content bytes = nullifier_bytes[0..31].
    let mut fe0_bytes: [u8; 31] = [0; 31];
    for i in 0..31 {
        fe0_bytes[i] = null_bytes[i];
    }

    // fe1: 1 byte of nullifier + 30 bytes of identity_tag.
    let mut fe1_bytes: [u8; 31] = [0; 31];
    fe1_bytes[0] = null_bytes[31];
    for i in 0..30 {
        fe1_bytes[1 + i] = idtag_bytes[i];
    }

    // fe2: 2 bytes of identity_tag + 2 bytes of class_tag + 27 bytes
    //      of zero padding.
    let mut fe2_bytes: [u8; 31] = [0; 31];
    fe2_bytes[0] = idtag_bytes[30];
    fe2_bytes[1] = idtag_bytes[31];
    fe2_bytes[2] = class_bytes[30];
    fe2_bytes[3] = class_bytes[31];

    // fe3: 31 zero bytes (full record padding).
    let fe3_bytes: [u8; 31] = [0; 31];

    RecordFields {
        fe0: assemble_bls_fe(fe0_bytes),
        fe1: assemble_bls_fe(fe1_bytes),
        fe2: assemble_bls_fe(fe2_bytes),
        fe3: assemble_bls_fe(fe3_bytes),
    }
}

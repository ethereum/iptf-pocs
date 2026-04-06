use rpi_lib::hasher;

use noir_bigcurve::BigCurve;
use noir_bigcurve::curves::bn254::{BN254, BN254_Fq, BN254Scalar};
use bignum::BigNum;

// Number of bytes for a BN254 base field element: (254 + 7) / 8 = 32
global FQ_BYTE_LEN: u32 = 32;
// Total serialization: 6 points * 2 coordinates * 32 bytes = 384
global SERIALIZED_LEN: u32 = 384;

// SHA-256 initial hash values
global SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Build SHA-256 from the stdlib compression function.
// Input must be exactly 384 bytes (6 * 64-byte blocks).
// Padding adds one more 64-byte block (total 7 blocks).
fn sha256_384(input: [u8; SERIALIZED_LEN]) -> [u8; 32] {
    // Prepare padded message: 384 + 64 = 448 bytes = 7 blocks
    let mut padded: [u8; 448] = [0; 448];
    for i in 0..SERIALIZED_LEN {
        padded[i] = input[i];
    }
    // Append the 0x80 byte
    padded[384] = 0x80;
    // Last 8 bytes encode the bit length in big-endian.
    // 384 bytes = 3072 bits = 0x0C00
    // padded[440..448] = big-endian 64-bit encoding of 3072
    padded[446] = 0x0C;
    padded[447] = 0x00;

    // Process 7 blocks
    let mut state = SHA256_INIT;
    for block_idx in 0..7 {
        let mut w: [u32; 16] = [0; 16];
        let base = block_idx * 64;
        for i in 0..16 {
            let b = base + i * 4;
            w[i] = (padded[b] as u32) << 24
                | (padded[b + 1] as u32) << 16
                | (padded[b + 2] as u32) << 8
                | (padded[b + 3] as u32);
        }
        state = std::hash::sha256_compression(w, state);
    }

    // Convert state to 32 bytes big-endian
    let mut result: [u8; 32] = [0; 32];
    for i in 0..8 {
        result[i * 4] = (state[i] >> 24) as u8;
        result[i * 4 + 1] = ((state[i] >> 16) & 0xFF) as u8;
        result[i * 4 + 2] = ((state[i] >> 8) & 0xFF) as u8;
        result[i * 4 + 3] = (state[i] & 0xFF) as u8;
    }
    result
}

fn main(
    // Public inputs
    leaf: pub Field,
    enrollment_nullifier: pub Field,
    mpc_public_key_x: pub Field,
    mpc_public_key_y: pub Field,
    g_id_x: pub Field,
    g_id_y: pub Field,
    // Private inputs
    identity_secret: Field,
    version: Field,
    attr0: Field,
    attr1: Field,
    attr2: Field,
    attr3: Field,
    raw_nullifier_x: Field,
    raw_nullifier_y: Field,
    chaum_pedersen_c: Field,
    chaum_pedersen_z: Field,
) {
    // 1. Version check
    assert(version == 1);

    // 2. DLEQ / Chaum-Pedersen verification
    //    Proves: log_G(PK) == log_{G_id}(Q)
    //    where G = BN254 generator, PK = mpc_public_key,
    //          G_id = identity point, Q = raw_nullifier

    // 2a. Reconstruct BN254 G1 points from (x, y) coordinates.
    //     Native Field values are in Fr (scalar field).
    //     BN254 G1 coordinates are in Fq (base field).
    //     Since Fr < Fq for BN254, From<Field> works correctly.
    let g: BN254 = BN254::one();

    let pk_x_fq: BN254_Fq = BN254_Fq::from(mpc_public_key_x);
    let pk_y_fq: BN254_Fq = BN254_Fq::from(mpc_public_key_y);
    let pk: BN254 = BN254::from_coordinates(pk_x_fq, pk_y_fq, false);
    pk.validate_on_curve();

    let g_id_x_fq: BN254_Fq = BN254_Fq::from(g_id_x);
    let g_id_y_fq: BN254_Fq = BN254_Fq::from(g_id_y);
    let g_id: BN254 = BN254::from_coordinates(g_id_x_fq, g_id_y_fq, false);
    g_id.validate_on_curve();

    let q_x_fq: BN254_Fq = BN254_Fq::from(raw_nullifier_x);
    let q_y_fq: BN254_Fq = BN254_Fq::from(raw_nullifier_y);
    let q: BN254 = BN254::from_coordinates(q_x_fq, q_y_fq, false);
    q.validate_on_curve();

    // 2b. Compute R1 = z*G + c*PK using batched evaluation
    let scalar_z: BN254Scalar = BN254Scalar::from(chaum_pedersen_z);
    let scalar_c: BN254Scalar = BN254Scalar::from(chaum_pedersen_c);

    // Use point_at_infinity as a dummy add_point since NAdds=0 triggers
    // a soundness check issue in noir_bigcurve's evaluate_linear_expression.
    let infinity: BN254 = BN254::point_at_infinity();

    let r1: BN254 = BN254::evaluate_linear_expression(
        [g, pk],
        [scalar_z, scalar_c],
        [infinity],
    );

    // 2c. Compute R2 = z*G_id + c*Q
    let r2: BN254 = BN254::evaluate_linear_expression(
        [g_id, q],
        [scalar_z, scalar_c],
        [infinity],
    );

    // 2d. Serialize all 6 points for Fiat-Shamir transcript.
    //     Order: G, PK, G_id, Q, R1, R2
    //     Each point: x (32 bytes BE) || y (32 bytes BE)
    let points: [BN254; 6] = [g, pk, g_id, q, r1, r2];
    let mut serialized: [u8; SERIALIZED_LEN] = [0; SERIALIZED_LEN];

    for i in 0..6 {
        let x_bytes: [u8; FQ_BYTE_LEN] = points[i].x().to_be_bytes();
        let y_bytes: [u8; FQ_BYTE_LEN] = points[i].y().to_be_bytes();
        let base = i * 64;
        for j in 0..FQ_BYTE_LEN {
            serialized[base + j] = x_bytes[j];
            serialized[base + FQ_BYTE_LEN + j] = y_bytes[j];
        }
    }

    // 2e. Compute Fiat-Shamir challenge: c' = SHA-256(serialized) mod r
    let hash_output: [u8; 32] = sha256_384(serialized);

    // Convert 32 big-endian bytes to native Field (which is mod r).
    // Since Field arithmetic is mod r, accumulating bytes naturally reduces.
    let mut c_prime: Field = 0;
    for i in 0..32 {
        c_prime = c_prime * 256 + hash_output[i] as Field;
    }

    // 2f. Verify challenge matches
    assert(chaum_pedersen_c == c_prime);

    // 3. Enrollment nullifier binding
    let computed_enrollment_nullifier =
        hasher::hash_enrollment_nullifier(raw_nullifier_x, raw_nullifier_y);
    assert(enrollment_nullifier == computed_enrollment_nullifier);

    // 4. Attribute hash
    let attr_hash = hasher::hash_attr(version, [attr0, attr1, attr2, attr3]);

    // 5. Leaf commitment
    let computed_leaf = hasher::hash_leaf(identity_secret, attr_hash);
    assert(leaf == computed_leaf);
}

// Keccak-256 (Ethereum-style; 0x01 ... 0x80 padding) over a fixed 64-byte
// input. Sole call site is the claim circuit's
// destination = keccak256(derivedPubkey_x || derivedPubkey_y)[-20:]
// constraint, where the input is exactly 64 bytes (two 32-byte field
// limbs concatenated big-endian). One absorption block is sufficient
// because 64 + 1 (padding marker) + 1 (final bit) <= 136 (rate in bytes).

global RATE_BYTES: u32 = 136;
global RATE_LANES: u32 = 17;

pub fn keccak256_64(input: [u8; 64]) -> [u8; 32] {
    let mut block: [u8; RATE_BYTES] = [0; RATE_BYTES];
    for i in 0..64 {
        block[i] = input[i];
    }
    block[64] = 0x01;
    block[RATE_BYTES - 1] = 0x80;

    let mut state: [u64; 25] = [0; 25];
    for lane_idx in 0..RATE_LANES {
        let mut lane: u64 = 0;
        let mut mult: u64 = 1;
        for b in 0..8 {
            let byte_val = block[lane_idx * 8 + b] as u64;
            lane = lane + byte_val * mult;
            if b < 7 {
                mult = mult * 256;
            }
        }
        state[lane_idx] = state[lane_idx] ^ lane;
    }

    state = std::hash::keccakf1600(state);

    let mut out: [u8; 32] = [0; 32];
    for i in 0..4 {
        let mut lane = state[i];
        for b in 0..8 {
            out[i * 8 + b] = (lane & 0xff) as u8;
            lane = lane / 256;
        }
    }
    out
}

#[test]
fn test_keccak256_64_empty_zero_input() {
    let zeros: [u8; 64] = [0; 64];
    let h = keccak256_64(zeros);
    // keccak256(0x00 * 64). Reference value computed off-circuit:
    //   0xad3228b676f7d3cd4284a5443f17f1962b36e491b30a40b2405849e597ba5fb5
    let expected: [u8; 32] = [
        0xad, 0x32, 0x28, 0xb6, 0x76, 0xf7, 0xd3, 0xcd, 0x42, 0x84, 0xa5, 0x44, 0x3f, 0x17, 0xf1,
        0x96, 0x2b, 0x36, 0xe4, 0x91, 0xb3, 0x0a, 0x40, 0xb2, 0x40, 0x58, 0x49, 0xe5, 0x97, 0xba,
        0x5f, 0xb5,
    ];
    for i in 0..32 {
        assert(h[i] == expected[i]);
    }
}

#[test]
fn test_keccak256_64_byte_pattern() {
    // Non-zero input exercises the byte-to-lane LE assembly across all 8
    // lanes used for the input; the all-zero test only exercises padding
    // and the keccakf1600 permutation.
    //
    // Input: 0x000102...3f (the bytes 0..=63 in big-endian order).
    // Reference: cast keccak 0x000102...3f
    //   0x002030bde3d4cf89919649775cd71875c4d0ab1708a380e03fefc3a28aa24831
    let mut input: [u8; 64] = [0; 64];
    for i in 0..64 {
        input[i] = i as u8;
    }
    let h = keccak256_64(input);
    let expected: [u8; 32] = [
        0x00, 0x20, 0x30, 0xbd, 0xe3, 0xd4, 0xcf, 0x89, 0x91, 0x96, 0x49, 0x77, 0x5c, 0xd7, 0x18,
        0x75, 0xc4, 0xd0, 0xab, 0x17, 0x08, 0xa3, 0x80, 0xe0, 0x3f, 0xef, 0xc3, 0xa2, 0x8a, 0xa2,
        0x48, 0x31,
    ];
    for i in 0..32 {
        assert(h[i] == expected[i]);
    }
}

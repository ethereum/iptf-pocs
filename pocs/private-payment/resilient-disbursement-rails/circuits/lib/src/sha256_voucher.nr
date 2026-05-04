// SHA-256 over the 308-byte voucher preimage.
//
// Padding for 308 bytes -> 320 bytes (5 blocks of 64):
//   bytes[0..308] = input
//   bytes[308]    = 0x80
//   bytes[309..318] = 0
//   bytes[318..320] = bit length 308*8 = 2464 = 0x09A0 (BE)

global PADDED_LEN: u32 = 320;
global NUM_BLOCKS: u32 = 5;

global SHA256_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn sha256_308(input: [u8; 308]) -> [u8; 32] {
    let mut padded: [u8; PADDED_LEN] = [0; PADDED_LEN];
    for i in 0..308 {
        padded[i] = input[i];
    }
    padded[308] = 0x80;
    padded[318] = 0x09;
    padded[319] = 0xa0;

    let mut state = SHA256_INIT;
    for block_idx in 0..NUM_BLOCKS {
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

    let mut out: [u8; 32] = [0; 32];
    for i in 0..8 {
        out[i * 4] = (state[i] >> 24) as u8;
        out[i * 4 + 1] = ((state[i] >> 16) & 0xff) as u8;
        out[i * 4 + 2] = ((state[i] >> 8) & 0xff) as u8;
        out[i * 4 + 3] = (state[i] & 0xff) as u8;
    }
    out
}

#[test]
fn test_sha256_zero_input() {
    let input: [u8; 308] = [0; 308];
    let digest = sha256_308(input);
    let expected: [u8; 32] = [
        0x95, 0x75, 0xb2, 0x12, 0x51, 0x69, 0x37, 0x7b, 0x2a, 0xde, 0x7b, 0x40, 0x1e, 0xa3, 0x6c,
        0x81, 0x22, 0x83, 0x31, 0xd9, 0x71, 0xf4, 0x96, 0x64, 0xd9, 0x64, 0x8d, 0x4f, 0x25, 0x5d,
        0x48, 0x68,
    ];
    for i in 0..32 {
        assert(digest[i] == expected[i]);
    }
}

#[test]
fn test_sha256_abc_prefix() {
    let mut input: [u8; 308] = [0; 308];
    input[0] = 0x61;
    input[1] = 0x62;
    input[2] = 0x63;
    let digest = sha256_308(input);
    let expected: [u8; 32] = [
        0xb8, 0x09, 0xa5, 0xd5, 0x07, 0xfe, 0x87, 0xa6, 0xa2, 0x50, 0x3b, 0x57, 0xe6, 0x1d, 0x65,
        0x77, 0x63, 0x07, 0x9a, 0x23, 0x84, 0x99, 0x92, 0x9b, 0xff, 0x71, 0xdf, 0xae, 0x7f, 0x70,
        0xfb, 0xd2,
    ];
    for i in 0..32 {
        assert(digest[i] == expected[i]);
    }
}

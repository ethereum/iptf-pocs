// secp256k1 ECDSA verification + canonical-s enforcement.
//
// Built on Noir stdlib (std::ecdsa_secp256k1::verify_signature). The stdlib
// gadget does NOT enforce low-s; we add an explicit BE byte-level compare
// against n/2.
//
// secp256k1 curve order n = 2 * (n/2) + 1, so n/2 has BE bytes:
//   7f ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
//   5d 57 6e 73 57 a4 50 1d df e9 2f 46 68 1b 20 a0
// EIP-2 / BIP-146: a signature is canonical iff s <= n/2.

global SECP256K1_HALF_N: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

pub fn verify_ecdsa(
    m_x_bytes: [u8; 32],
    m_y_bytes: [u8; 32],
    h_msg: [u8; 32],
    signature_r: [u8; 32],
    signature_s: [u8; 32],
) {
    let mut sig: [u8; 64] = [0; 64];
    for i in 0..32 {
        sig[i] = signature_r[i];
        sig[32 + i] = signature_s[i];
    }
    let ok = std::ecdsa_secp256k1::verify_signature(m_x_bytes, m_y_bytes, sig, h_msg);
    assert(ok, "ECDSA signature invalid");
    assert_canonical_s(signature_s);
}

// BE lex compare s <= n/2: latch on the first byte where s and n/2 differ;
// reject if that byte is greater. Equality through all 32 bytes (s == n/2)
// is acceptable.
pub fn assert_canonical_s(s: [u8; 32]) {
    let mut decided: bool = false;
    let mut s_le: bool = true;
    for i in 0..32 {
        let s_b = s[i];
        let h_b = SECP256K1_HALF_N[i];
        let s_lt = s_b < h_b;
        let s_gt = s_b > h_b;
        let first_diff_gt = (!decided) & s_gt;
        s_le = s_le & !first_diff_gt;
        decided = decided | s_lt | s_gt;
    }
    assert(s_le, "non-canonical s");
}

#[test]
fn test_canonical_s_accepts_zero() {
    let s: [u8; 32] = [0; 32];
    assert_canonical_s(s);
}

#[test]
fn test_canonical_s_accepts_half_n() {
    assert_canonical_s(SECP256K1_HALF_N);
}

#[test]
fn test_canonical_s_accepts_below_half_n_msb() {
    let mut s = SECP256K1_HALF_N;
    s[0] = 0x7e; // strictly less in the most significant byte
    assert_canonical_s(s);
}

#[test(should_fail)]
fn test_canonical_s_rejects_just_above_half_n() {
    let mut s = SECP256K1_HALF_N;
    s[31] = s[31] + 1;
    assert_canonical_s(s);
}

#[test(should_fail)]
fn test_canonical_s_rejects_msb_greater() {
    let mut s: [u8; 32] = [0; 32];
    s[0] = 0x80;
    assert_canonical_s(s);
}

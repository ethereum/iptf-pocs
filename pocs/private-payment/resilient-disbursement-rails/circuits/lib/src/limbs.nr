// Range checks and limb-to-bytes helpers for the disbursement-rails circuits.
// `to_be_bytes::<N>()` asserts the field value fits in N bytes.

pub fn assert_lt_2_128(x: Field) {
    let _: [u8; 16] = x.to_be_bytes();
}

pub fn assert_lt_2_160(x: Field) {
    let _: [u8; 20] = x.to_be_bytes();
}

// Concatenate two 128-bit limbs (hi, lo) into a 32-byte big-endian array.
// Each limb must fit in 16 bytes; `to_be_bytes::<16>` enforces this.
pub fn limbs_to_be_bytes_32(hi: Field, lo: Field) -> [u8; 32] {
    let hi_bytes: [u8; 16] = hi.to_be_bytes();
    let lo_bytes: [u8; 16] = lo.to_be_bytes();
    let mut out: [u8; 32] = [0; 32];
    for i in 0..16 {
        out[i] = hi_bytes[i];
        out[16 + i] = lo_bytes[i];
    }
    out
}

#[test]
fn test_assert_lt_2_128_accepts_max() {
    assert_lt_2_128(0xffffffffffffffffffffffffffffffff);
}

#[test(should_fail)]
fn test_assert_lt_2_128_rejects_overflow() {
    assert_lt_2_128(0x100000000000000000000000000000000);
}

#[test]
fn test_limbs_to_be_bytes_32_roundtrip() {
    let hi: Field = 0x0102030405060708090a0b0c0d0e0f10;
    let lo: Field = 0x1112131415161718191a1b1c1d1e1f20;
    let bytes = limbs_to_be_bytes_32(hi, lo);
    for i in 0..32 {
        assert(bytes[i] == (i + 1) as u8);
    }
}

#[test]
fn test_limbs_to_be_bytes_32_zero() {
    let bytes = limbs_to_be_bytes_32(0, 0);
    for i in 0..32 {
        assert(bytes[i] == 0);
    }
}

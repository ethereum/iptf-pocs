// Field-level less-than under canonical BN254 ordering.
//
// Noir's `Ord for Field` ships in newer compilers, but pinning the
// helper here gives a stable signature across compiler versions and
// keeps the call sites readable.
//
// Both inputs are reduced canonical BN254 representatives (`< p`); the
// caller is responsible for that (Poseidon outputs satisfy this by
// construction, and witnessed Field inputs are range-checked by the
// witness contract). We compare lexicographically over the 32-byte
// little-endian representation starting from the most-significant byte.

pub fn lt_field(a: Field, b: Field) -> bool {
    let a_le: [u8; 32] = a.to_le_bytes();
    let b_le: [u8; 32] = b.to_le_bytes();
    let mut decided: bool = false;
    let mut result: bool = false;
    for i in 0..32 {
        let ai = a_le[31 - i];
        let bi = b_le[31 - i];
        if !decided {
            if ai < bi {
                result = true;
                decided = true;
            } else if ai > bi {
                result = false;
                decided = true;
            }
        }
    }
    result
}

// Assert `f` is a canonical BN254 representative. In Noir, `to_le_bytes(32)`
// is constrained to produce the unique canonical 32-byte decomposition of
// the field element, so calling it forces the witness to round-trip via
// the canonical form. The high-byte check is conservative (BN254 modulus
// high byte = 0x30; any canonical scalar's high byte is <= 0x30).
pub fn assert_canonical(f: Field) {
    let bytes: [u8; 32] = f.to_le_bytes();
    assert(bytes[31] <= 0x30, "cmp: scalar exceeds BN254 modulus high byte");
}

pub fn le_field(a: Field, b: Field) -> bool {
    !lt_field(b, a)
}

pub fn ge_field(a: Field, b: Field) -> bool {
    !lt_field(a, b)
}

#[test]
fn test_lt_field_small() {
    assert(lt_field(0, 1));
    assert(!lt_field(1, 0));
    assert(!lt_field(5, 5));
    assert(lt_field(100, 200));
}

#[test]
fn test_le_ge_edges() {
    assert(le_field(5, 5));
    assert(ge_field(5, 5));
    assert(le_field(5, 6));
    assert(!le_field(6, 5));
    assert(ge_field(7, 6));
}

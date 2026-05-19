// Postfix predicate evaluator (SPEC section Predicate).
//
// Each operation is one of:
//   0x20  PushTuple    operand: tuple index (in [0, tuple_count))
//   0x21  And
//   0x22  Or
//   0x23  Not
//   0xff  Nop
//
// Tuples are pre-evaluated outside this module: the signer SNARK
// computes `tuple_bool[t]` from `(claim_index, operand, type_tag,
// comparator, attrs[claim_index])` and feeds an array of N=20 booleans
// in. This keeps the postfix loop branch-free.
//
// The evaluator runs over a padded fixed-size op array of length 20 and
// a runtime `op_count` parameter; ops past `op_count` are required to
// be NOP. The class-binding clause is checked structurally by the
// caller before this function is invoked.

use crate::cmp;

pub global STACK_CAPACITY: u32 = 20;

pub fn evaluate(
    op_codes: [u8; 20],
    op_operands: [u8; 20],
    tuple_bool: [bool; 20],
    op_count: u32,
) -> bool {
    let mut stack: [bool; 20] = [false; 20];
    let mut sp: u32 = 0;

    for i in 0..20 {
        let active = (i as u32) < op_count;
        let code = op_codes[i];
        let operand = op_operands[i];

        // PUSH_TUPLE: push tuple_bool[operand].
        let push_v = tuple_bool[operand as u32];

        let mut new_stack = stack;
        let mut new_sp = sp;

        if active {
            if code == 0x20 {
                new_stack[sp] = push_v;
                new_sp = sp + 1;
            } else if code == 0x21 {
                // AND: stack[sp-2] = stack[sp-2] && stack[sp-1]; sp -= 1.
                assert(sp >= 2, "predicate: AND on short stack");
                let a = stack[sp - 1];
                let b = stack[sp - 2];
                new_stack[sp - 2] = a & b;
                new_sp = sp - 1;
            } else if code == 0x22 {
                assert(sp >= 2, "predicate: OR on short stack");
                let a = stack[sp - 1];
                let b = stack[sp - 2];
                new_stack[sp - 2] = a | b;
                new_sp = sp - 1;
            } else if code == 0x23 {
                assert(sp >= 1, "predicate: NOT on empty stack");
                let a = stack[sp - 1];
                new_stack[sp - 1] = !a;
                new_sp = sp;
            } else {
                assert(code == 0xff, "predicate: unknown opcode");
            }
        } else {
            // Inactive positions must be NOP.
            assert(code == 0xff, "predicate: non-NOP past op_count");
        }

        stack = new_stack;
        sp = new_sp;
    }

    assert(sp == 1, "predicate: final stack depth != 1");
    stack[0]
}

// In-circuit version of `src/predicate.rs::canonical_scalars`. Encodes
// the (tuples + ops + counts) witness into a 742-byte serialized buffer
// matching SPEC section Predicate, then packs into 34 BN254 scalars.
//
// Used by the signer SNARK to bind the EVALUATED predicate program to
// the HASHED `predicate_hash`.
pub fn encode_canonical_def(
    op_codes: [u8; 20],
    op_operands: [u8; 20],
    op_count: u32,
    tuple_claim_index: [u8; 20],
    tuple_operand: [Field; 20],
    tuple_type_tag: [u8; 20],
    tuple_comparator: [u8; 20],
    tuple_count: u32,
) -> [Field; 34] {
    // Step 0: precompute tuple operand bytes with R3 canonicity checks.
    let mut tuple_operand_bytes: [[u8; 32]; 20] = [[0; 32]; 20];
    for t in 0..20 {
        let bytes: [u8; 32] = tuple_operand[t].to_be_bytes();
        tuple_operand_bytes[t] = bytes;
        let active = (t as u32) < tuple_count;
        if active {
            // R3: operand high byte must be < 0x30 (canonical BN254).
            assert(bytes[0] < 0x30, "predicate: tuple operand exceeds BN254 modulus");
            // INT64 operands must fit in low 8 bytes.
            if tuple_type_tag[t] == 0x01 {
                for k in 0..24 {
                    assert(bytes[k] == 0, "predicate: INT64 operand exceeds 64 bits");
                }
            }
        }
    }

    // Step 1: build the 742-byte serialized buffer (max-sized).
    let mut buf: [u8; 742] = [0; 742];
    buf[0] = tuple_count as u8;

    // Tuple section (35 bytes per tuple).
    for t in 0..20 {
        let active = (t as u32) < tuple_count;
        let t_off: u32 = 1 + (t as u32) * 35;
        if active {
            buf[t_off] = tuple_claim_index[t];
            for k in 0..32 {
                buf[t_off + 1 + (k as u32)] = tuple_operand_bytes[t][k];
            }
            buf[t_off + 33] = tuple_type_tag[t];
            buf[t_off + 34] = tuple_comparator[t];
        }
    }

    // Op-count + op section: variable offset (depends on tuple_count).
    for tc in 0..21 {
        if (tc as u32) == tuple_count {
            let oc_pos: u32 = 1 + (tc as u32) * 35;
            buf[oc_pos] = op_count as u8;
            for o in 0..20 {
                let o_active = (o as u32) < op_count;
                if o_active {
                    let o_off: u32 = oc_pos + 1 + (o as u32) * 2;
                    buf[o_off] = op_codes[o];
                    buf[o_off + 1] = op_operands[o];
                }
            }
        }
    }

    // Step 2: compute actual serialized length (1 + tc*35 + 1 + oc*2).
    let serialized_len: u32 = 2 + tuple_count * 35 + op_count * 2;
    let len_hi: u8 = (serialized_len / 256) as u8;
    let len_lo: u8 = (serialized_len % 256) as u8;

    // Step 3: pack buf into 34 canonical scalars.
    let mut canonical: [Field; 34] = [0; 34];

    // Segment 0: 0x00 (top byte) | length_hi | length_lo | buf[0..29].
    let mut seg0: [u8; 32] = [0; 32];
    seg0[1] = len_hi;
    seg0[2] = len_lo;
    for k in 0..29 {
        seg0[3 + k] = buf[k];
    }
    canonical[0] = field_from_be_bytes_32(seg0);

    // Segments 1..34: 0x00 (top byte) | buf[29 + 31*(i-1) .. 29 + 31*i].
    for i in 1..34 {
        let mut seg: [u8; 32] = [0; 32];
        let src_off: u32 = 29 + 31 * (i as u32 - 1);
        for k in 0..31 {
            let src_idx: u32 = src_off + (k as u32);
            if src_idx < 742 {
                seg[1 + k] = buf[src_idx];
            }
        }
        canonical[i] = field_from_be_bytes_32(seg);
    }

    canonical
}

// Construct a Field from 32 BE bytes; asserts canonicity (top byte <= 0x30).
fn field_from_be_bytes_32(bytes: [u8; 32]) -> Field {
    assert(bytes[0] <= 0x30, "predicate: scalar top byte exceeds BN254 modulus");
    let mut acc: Field = 0;
    for i in 0..32 {
        acc = acc * 256 + (bytes[i] as Field);
    }
    acc
}

// Per-tuple evaluation: `attrs[claim_index] OP operand`. SPEC section
// Predicate lists OP in {0x10 ==, 0x11 <=, 0x12 >=}. type_tag selects
// how the operand is interpreted; for the PoC we lift INT64 to a
// Field comparison via canonical BN254 ordering, and HASH / BOOL use
// equality only.
pub fn evaluate_tuple(attr_value: Field, operand: Field, type_tag: u8, comparator: u8) -> bool {
    if (type_tag == 0x02) | (type_tag == 0x03) {
        // HASH and BOOL: equality only.
        assert(comparator == 0x10, "predicate: HASH/BOOL must use ==");
        attr_value == operand
    } else if type_tag == 0x01 {
        // INT64: ==, <=, >=. Use canonical BN254 ordering; INT64
        // attribute values fit in 64 bits so the ordering coincides
        // with integer ordering.
        if comparator == 0x10 {
            attr_value == operand
        } else if comparator == 0x11 {
            cmp::le_field(attr_value, operand)
        } else if comparator == 0x12 {
            cmp::ge_field(attr_value, operand)
        } else {
            assert(false, "predicate: unknown comparator");
            false
        }
    } else {
        assert(false, "predicate: unknown type_tag");
        false
    }
}

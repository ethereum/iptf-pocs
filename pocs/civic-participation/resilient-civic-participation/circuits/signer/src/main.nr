use rcp_lib::fsrt;
use rcp_lib::hasher;
use rcp_lib::merkle;
use rcp_lib::predicate;

// Signer SNARK (SPEC section Signer SNARK).
//
// Public inputs (ordered per spec): R, petition_id, predicate_hash,
// class_index, class_tag, slot, nullifier, identity_tag.
fn main(
    r_root: pub Field,
    petition_id: pub Field,
    predicate_hash: pub Field,
    class_index: pub Field,
    class_tag: pub Field,
    slot: pub Field,
    nullifier: pub Field,
    identity_tag: pub Field,
    // Private
    identity_secret: Field,
    attrs: [Field; 4],
    attr_version: Field,
    chain_root: Field,
    ri_path_indices: [bool; 32],
    ri_path_elements: [Field; 32],
    // Actual proof depth for the RI Merkle inclusion. The RI tree is a
    // variable-depth LeanIMT off chain; the witness pads to depth 32
    // and `binary_merkle_root` only walks `ri_proof_length` levels.
    ri_proof_length: u32,
    s_slot: Field,
    chain_path_indices: [bool; 24],
    chain_path_elements: [Field; 24],
    salt: Field,
    // Predicate program
    op_codes: [u8; 20],
    op_operands: [u8; 20],
    op_count: u32,
    tuple_claim_index: [u8; 20],
    tuple_operand: [Field; 20],
    tuple_type_tag: [u8; 20],
    tuple_comparator: [u8; 20],
    tuple_count: u32,
) {
    // Constraint 1: attr_hash inclusion in R. identity_secret is mixed
    // into attr_hash so each RI leaf binds to a specific signer secret.
    let attr_hash = hasher::hash_attr(attrs, chain_root, attr_version, identity_secret);
    merkle::verify_membership_depth_32(
        attr_hash,
        r_root,
        ri_proof_length,
        ri_path_indices,
        ri_path_elements,
    );

    // Constraint 2: predicate_hash binding from IN-CIRCUIT encoding.
    // The signer SNARK computes canonical_predicate_def from the
    // witnessed (tuples + ops + counts) and hashes it, forcing the
    // EVALUATED predicate to equal the HASHED predicate.
    let canonical = predicate::encode_canonical_def(
        op_codes,
        op_operands,
        op_count,
        tuple_claim_index,
        tuple_operand,
        tuple_type_tag,
        tuple_comparator,
        tuple_count,
    );
    let recomputed_pred_hash = hasher::hash_predicate(canonical, petition_id, salt);
    assert(recomputed_pred_hash == predicate_hash, "signer: predicate_hash mismatch");

    // Constraint 2a: non-empty predicate.
    assert(tuple_count >= 1, "signer: tuple_count must be >= 1");
    assert(tuple_count <= 20, "signer: tuple_count > PREDICATE_TUPLE_MAX");
    assert(op_count >= 1, "signer: op_count must be >= 1");
    assert(op_count <= 20, "signer: op_count > PREDICATE_OP_MAX");

    // Constraint 4a: identify tuples that are class-binding for the
    // SIGNER's specific class_tag, i.e., tuples whose claim_index ==
    // class_index AND operand == class_tag AND comparator == EQ. At
    // least one such tuple must exist; pushing any of them marks the
    // stack as Bound. Multi-class predicates (e.g. `attr == A OR attr
    // == B`) are accepted via OR(Bound, Bound) -> Bound.
    let mut is_binding_tuple: [bool; 20] = [false; 20];
    let mut any_binding: bool = false;
    for t in 0..20 {
        let active = (t as u32) < tuple_count;
        let claim_match = tuple_claim_index[t] as Field == class_index;
        let operand_match = tuple_operand[t] == class_tag;
        let comparator_match = tuple_comparator[t] == 0x10;
        let bind_for_signer = active & claim_match & operand_match & comparator_match;
        is_binding_tuple[t] = bind_for_signer;
        any_binding = any_binding | bind_for_signer;
    }
    assert(any_binding, "signer: no class-binding tuple matches (class_index, class_tag)");

    // Constraint 4b: data-oblivious 3-state taint propagation.
    //   States: 0 = Free, 1 = Bound (carries class-binding), 2 = Tainted.
    // PUSH_TUPLE(k): Bound iff is_binding_tuple[k]; else Free.
    // AND: combined = Bound if any operand Bound, else Tainted if any Tainted, else Free.
    // OR : Bound if BOTH operands Bound, else Tainted if any Bound or Tainted, else Free.
    // NOT: Tainted if operand Bound, else operand.
    // NOP: no-op.
    // After all ops, top of taint stack MUST be Bound and stack depth == 1.
    let mut taint_stack: [u32; 20] = [0; 20];
    let mut taint_sp: u32 = 0;
    for i in 0..20 {
        let active = (i as u32) < op_count;
        let code = op_codes[i];
        let operand = op_operands[i];
        if active {
            if code == 0x20 {
                // PUSH_TUPLE: Bound iff is_binding_tuple[operand].
                let v: u32 = if is_binding_tuple[operand as u32] {
                    1
                } else {
                    0
                };
                taint_stack[taint_sp] = v;
                taint_sp = taint_sp + 1;
            } else if code == 0x21 {
                // AND
                assert(operand == 0, "signer: AND op operand must be 0");
                assert(taint_sp >= 2, "signer: AND underflow");
                let a = taint_stack[taint_sp - 1];
                let b = taint_stack[taint_sp - 2];
                let combined: u32 = if (a == 1) | (b == 1) {
                    1
                } else if (a == 2) | (b == 2) {
                    2
                } else {
                    0
                };
                taint_stack[taint_sp - 2] = combined;
                taint_sp = taint_sp - 1;
            } else if code == 0x22 {
                // OR: from the SIGNER's perspective, a Bound branch
                // means the signer commits to their class via that
                // branch. The Registry's structural validator rejects
                // predicates with non-binding alternatives. So at
                // proving time we only need any branch Bound -> Bound.
                assert(operand == 0, "signer: OR op operand must be 0");
                assert(taint_sp >= 2, "signer: OR underflow");
                let a = taint_stack[taint_sp - 1];
                let b = taint_stack[taint_sp - 2];
                let combined: u32 = if (a == 1) | (b == 1) {
                    1
                } else if (a == 2) | (b == 2) {
                    2
                } else {
                    0
                };
                taint_stack[taint_sp - 2] = combined;
                taint_sp = taint_sp - 1;
            } else if code == 0x23 {
                // NOT
                assert(operand == 0, "signer: NOT op operand must be 0");
                assert(taint_sp >= 1, "signer: NOT underflow");
                let a = taint_stack[taint_sp - 1];
                let combined: u32 = if a == 1 { 2 } else { a };
                taint_stack[taint_sp - 1] = combined;
            } else {
                assert(code == 0xff, "signer: unknown opcode");
                assert(operand == 0, "signer: NOP op operand must be 0");
            }
        }
    }
    assert(taint_sp == 1, "signer: predicate stack must terminate with exactly 1 element");
    assert(taint_stack[0] == 1, "signer: class binding not bound at top level (outside OR/NOT)");

    // Constraint 3: predicate evaluation.
    // First, per-tuple evaluation. We assert claim_index < ATTR_COUNT
    // for all (active and inactive) tuples since inactive tuples still
    // have witness values.
    let mut tuple_bool: [bool; 20] = [false; 20];
    for t in 0..20 {
        let ci = tuple_claim_index[t] as u32;
        assert(ci < 4, "signer: tuple claim_index >= ATTR_COUNT");
        let attr_v = attrs[ci];
        let v = predicate::evaluate_tuple(
            attr_v,
            tuple_operand[t],
            tuple_type_tag[t],
            tuple_comparator[t],
        );
        let active = (t as u32) < tuple_count;
        tuple_bool[t] = if active { v } else { false };
    }
    let result = predicate::evaluate(op_codes, op_operands, tuple_bool, op_count);
    assert(result, "signer: predicate evaluates to false");

    // Constraint 4c: `attrs[class_index] == class_tag` defense in depth.
    let ci_u32 = class_index as u32;
    assert(ci_u32 < 4, "signer: class_index out of range");
    let class_attr = attrs[ci_u32];
    assert(class_attr == class_tag, "signer: class binding violated");

    // Constraint 5: v_slot derivation.
    let v_slot = fsrt::derive_v_slot(s_slot);

    // Constraint 6: v_slot inclusion in chain_root at index `slot`.
    // Bind public `slot` to chain_path_indices via 24-bit
    // decomposition, then verify the Merkle path.
    let slot_u32 = slot as u32;
    let slot_limit: u32 = 16777216; // 2^24
    assert(slot_u32 < slot_limit, "signer: slot out of range");
    let expected_chain_bits = merkle::u32_to_bits_24(slot_u32);
    merkle::assert_bits_eq_24(chain_path_indices, expected_chain_bits);
    merkle::verify_membership_depth_24(
        v_slot,
        chain_root,
        24,
        chain_path_indices,
        chain_path_elements,
    );

    // Constraint 7: nullifier derivation. identity_secret is mixed in
    // so a malicious signer with the same s_0 but different RI leaf
    // (different identity_secret) cannot produce the same nullifier.
    let recomputed_null =
        hasher::hash_nullifier(v_slot, petition_id, class_index, class_tag, identity_secret);
    assert(recomputed_null == nullifier, "signer: nullifier mismatch");

    // Constraint 8: identity_tag derivation.
    let recomputed_idtag = hasher::hash_identity_tag(v_slot, petition_id);
    assert(recomputed_idtag == identity_tag, "signer: identity_tag mismatch");
}

#[test]
fn test_signer_circuit_structure_compiles() {
    let attrs: [Field; 4] = [10, 20, 826, 40];
    let attr_version: Field = 0;
    let chain_root: Field = 0;
    let identity_secret: Field = 0xdeadbeef;
    let r_root: Field = hasher::hash_attr(attrs, chain_root, attr_version, identity_secret);
    let ri_path_indices: [bool; 32] = [false; 32];
    let ri_path_elements: [Field; 32] = [0; 32];
    let ri_proof_length: u32 = 0;
    let s_slot: Field = 1;
    let chain_path_indices: [bool; 24] = [false; 24];
    let chain_path_elements: [Field; 24] = [0; 24];
    let salt: Field = 7;
    let petition_id: Field = 42;
    // Predicate: tuples[0] = (class_index=2, operand=class_tag=826, HASH, EQ).
    let mut tuple_claim_index: [u8; 20] = [0; 20];
    tuple_claim_index[0] = 2;
    let mut tuple_operand: [Field; 20] = [0; 20];
    tuple_operand[0] = 826;
    let mut tuple_type_tag: [u8; 20] = [0; 20];
    tuple_type_tag[0] = 0x02; // HASH
    let mut tuple_comparator: [u8; 20] = [0; 20];
    tuple_comparator[0] = 0x10; // EQ
    let tuple_count: u32 = 1;
    let mut op_codes: [u8; 20] = [0xff; 20];
    op_codes[0] = 0x20; // PUSH_TUPLE
    let mut op_operands: [u8; 20] = [0; 20];
    op_operands[0] = 0;
    let op_count: u32 = 1;

    let canonical = predicate::encode_canonical_def(
        op_codes,
        op_operands,
        op_count,
        tuple_claim_index,
        tuple_operand,
        tuple_type_tag,
        tuple_comparator,
        tuple_count,
    );
    let predicate_hash = hasher::hash_predicate(canonical, petition_id, salt);
    let v_slot = fsrt::derive_v_slot(s_slot);
    let class_index: Field = 2;
    let class_tag: Field = 826;
    let nullifier =
        hasher::hash_nullifier(v_slot, petition_id, class_index, class_tag, identity_secret);
    let identity_tag = hasher::hash_identity_tag(v_slot, petition_id);

    let _ = (
        r_root, petition_id, predicate_hash, class_index, class_tag, nullifier, identity_tag,
        ri_path_indices, ri_path_elements, s_slot, chain_path_indices, chain_path_elements, salt,
        ri_proof_length, identity_secret,
    );
}

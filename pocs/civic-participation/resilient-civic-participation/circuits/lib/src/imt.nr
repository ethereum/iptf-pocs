// Sorted-linked-list Indexed Merkle Tree (Aztec-style).
//
// Each leaf is `H(value, next_index, next_value)`. Membership proves a
// value is in the tree; non-membership proves a value lies strictly
// between `low_leaf.value` and `low_leaf.next_value`. Insertion replaces
// the low leaf and adds a new leaf at the next free position (absolute
// index `prior_leaf_count + 1`, since index 0 holds the sentinel empty
// leaf), mutating two Merkle paths.

use crate::cmp;
use crate::hasher;
use crate::hasher::hash_imt_leaf;
use crate::merkle;

pub struct ImtLowLeafWitness {
    pub leaf_index: u32,
    pub value: Field,
    pub next_index: Field,
    pub next_value: Field,
    pub path_indices: [bool; 24],
    pub path_elements: [Field; 24],
}

pub struct ImtInsertWitness {
    pub low: ImtLowLeafWitness,
    // Post-update low leaf points at the newly inserted leaf and at the
    // new value. The Aztec-style scheme places the new leaf at the next
    // free absolute index = `prior_leaf_count + 1`.
    pub new_low_next_index: Field,
    // Merkle siblings of the new-leaf position in the post-low-update
    // tree. Bound by `verify_insert` step 3 against the intermediate
    // root.
    pub new_leaf_path_indices: [bool; 24],
    pub new_leaf_path_elements: [Field; 24],
}

// Non-membership of `value` against root `r`: prove `low.value < value`
// AND `(low.next_value > value || low.next_index == 0)`, and that `low`
// hashes to a leaf opening to `r` under its Merkle path.
pub fn verify_non_membership(value: Field, root: Field, low: ImtLowLeafWitness) {
    // Canonicity invariants: lt_field's byte comparison is sound only on
    // canonical BN254 representatives. Poseidon outputs are canonical by
    // construction; we defensively enforce the same for the witnessed
    // low.value / low.next_value (which the prover supplies).
    cmp::assert_canonical(low.value);
    cmp::assert_canonical(low.next_value);
    cmp::assert_canonical(value);

    // 1. low.value < value (strict, integer ordering).
    let lt_low = cmp::lt_field(low.value, value);
    assert(lt_low, "imt: low.value >= value (would be membership or out of order)");

    // 2. Either low is the tail (next_index == 0) or value < low.next_value.
    if low.next_index != 0 {
        let lt_next = cmp::lt_field(value, low.next_value);
        assert(lt_next, "imt: value >= low.next_value (would be membership or out of order)");
    }

    // 3. low's hash opens at low.leaf_index to root under path_elements.
    //    Binding leaf_index to path_indices via 24-bit decomposition is
    //    deferred to verify_insert (where it matters for the linked-list
    //    invariant); membership-only callers don't need it.
    let low_hash = hash_imt_leaf(low.value, low.next_index, low.next_value);
    merkle::verify_membership_depth_24(low_hash, root, 24, low.path_indices, low.path_elements);
}

// Insertion: prove that inserting `value` into `prior_root` yields
// `new_root`. The new low leaf points at the new leaf (`next_index =
// prior_leaf_count + 1`, since index 0 is the sentinel), and the new
// leaf inherits low's prior `next_index` / `next_value`.
//
// `prior_leaf_count` is the count of REAL leaves (excluding sentinel)
// before this insertion; the new leaf goes to absolute index
// `prior_leaf_count + 1`.
pub fn verify_insert(
    value: Field,
    prior_root: Field,
    new_root: Field,
    prior_leaf_count: u32,
    insert: ImtInsertWitness,
) {
    // Bound the absolute new-leaf index: must be < 2^24 (tree depth).
    assert(prior_leaf_count < 16777215, "imt: tree full");

    // 1. Non-membership of `value` against `prior_root` via `low`.
    verify_non_membership(value, prior_root, insert.low);

    // 1a. Bind low.leaf_index to low.path_indices via 24-bit
    //     decomposition. Without this the prover could supply
    //     path_indices for a different leaf position than low.leaf_index,
    //     breaking the linked-list invariant on later inserts.
    let expected_low_bits = merkle::u32_to_bits_24(insert.low.leaf_index);
    merkle::assert_bits_eq_24(insert.low.path_indices, expected_low_bits);

    // 1b. Reject the degenerate case where low and the new insertion
    //     collide at the same position; insertion requires the new slot
    //     to be previously empty AND distinct from low's slot.
    let new_absolute: u32 = prior_leaf_count + 1;
    assert(
        insert.low.leaf_index != new_absolute,
        "imt: low.leaf_index collides with new insertion position",
    );

    // 1c. Bind new_low_next_index to the new leaf's absolute index.
    //     SPEC's "Aztec-style 1-indexed scheme" maps to: new leaf at
    //     index `prior_leaf_count + 1` (since index 0 is the sentinel).
    let expected_new_low_next: Field = new_absolute as Field;
    assert(
        insert.new_low_next_index == expected_new_low_next,
        "imt: new_low_next_index != prior_leaf_count + 1",
    );

    // 2. Compute the post-update low-leaf hash and the intermediate
    //    root by re-running the low-leaf path with the updated leaf
    //    (siblings unchanged).
    let updated_low_hash = hash_imt_leaf(insert.low.value, insert.new_low_next_index, value);
    let intermediate_root = merkle::compute_root_depth_24(
        updated_low_hash,
        insert.low.path_indices,
        insert.low.path_elements,
    );

    // 3. Bind new_leaf_path_indices to the bit decomposition of the new
    //    leaf's absolute index. Without this the prover picks the
    //    insertion position freely.
    let expected_new_bits = merkle::u32_to_bits_24(new_absolute);
    merkle::assert_bits_eq_24(insert.new_leaf_path_indices, expected_new_bits);

    // 4. Bind the new-leaf path to the intermediate tree: the new-leaf
    //    position must have been empty (hash = imt_empty_leaf_hash) in
    //    the post-low-update root. This closes the Aztec-style two-path
    //    insertion proof.
    let empty_leaf = hasher::imt_empty_leaf_hash();
    let intermediate_via_new = merkle::compute_root_depth_24(
        empty_leaf,
        insert.new_leaf_path_indices,
        insert.new_leaf_path_elements,
    );
    assert(
        intermediate_via_new == intermediate_root,
        "imt: new-leaf position was not empty in intermediate root",
    );

    // 5. Compute new_root from the new leaf with the same siblings.
    //    The new leaf's `next_index` and `next_value` inherit from low.
    let new_leaf_hash = hash_imt_leaf(value, insert.low.next_index, insert.low.next_value);
    let recomputed_root = merkle::compute_root_depth_24(
        new_leaf_hash,
        insert.new_leaf_path_indices,
        insert.new_leaf_path_elements,
    );
    assert(recomputed_root == new_root, "imt: post-insert root mismatch");
}

// Membership check: `value` is in the tree at `leaf_index` (the leaf at
// `leaf_index` has `.value == value`).
pub fn verify_membership(
    value: Field,
    next_index: Field,
    next_value: Field,
    root: Field,
    path_indices: [bool; 24],
    path_elements: [Field; 24],
) {
    let leaf_hash = hash_imt_leaf(value, next_index, next_value);
    merkle::verify_membership_depth_24(leaf_hash, root, 24, path_indices, path_elements);
}

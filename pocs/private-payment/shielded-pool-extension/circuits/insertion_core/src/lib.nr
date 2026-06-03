use poseidon::poseidon::bn254::{hash_2, hash_3};

// Shared insertion logic for the relayer's insertion proof, generic over the
// number of insertions `N`. Instantiated at N = 2 (a 2-in transfer) by the
// `insertion` circuit and at N = 1 (a 1-in withdraw) by `insertion_withdraw`;
// the logic is identical, only the insertion count differs. The in-circuit
// mirror of the off-chain `InsertionWitness::verify_and_apply`
// (src/lib/domain/indexed_merkle.rs). See ../../SPEC.md "Insertion Circuit (new)".

pub global NULLIFIER_TREE_DEPTH: u32 = 32;

fn poseidon2(a: Field, b: Field) -> Field {
    hash_2([a, b])
}

// leaf = hash_3(value, next_value, next_index) - matches the off-chain IMT.
fn leaf_hash(value: Field, next_value: Field, next_index: Field) -> Field {
    hash_3([value, next_value, next_index])
}

// Reconstruct the root from a leaf and a sibling path; bit false = left child.
fn root_from_path(
    leaf: Field,
    bits: [bool; NULLIFIER_TREE_DEPTH],
    siblings: [Field; NULLIFIER_TREE_DEPTH],
) -> Field {
    let mut node = leaf;
    for i in 0..NULLIFIER_TREE_DEPTH {
        if bits[i] {
            node = poseidon2(siblings[i], node);
        } else {
            node = poseidon2(node, siblings[i]);
        }
    }
    node
}

// Little-endian bit decomposition of a tree index (binds the new leaf to its
// canonical append slot).
fn index_bits(index: u32) -> [bool; NULLIFIER_TREE_DEPTH] {
    let mut bits: [bool; NULLIFIER_TREE_DEPTH] = [false; NULLIFIER_TREE_DEPTH];
    for j in 0..NULLIFIER_TREE_DEPTH {
        bits[j] = ((index >> j) & 1) == 1;
    }
    bits
}

// Chain `N` sorted-low-leaf insertions of the public `nullifiers` list into the
// active indexed Merkle tree, threading `pre_active_root` to `post_active_root`.
pub fn run_insertions<let N: u32>(
    pre_active_root: Field,
    post_active_root: Field,
    pre_leaf_count: u32,
    nullifiers: [Field; N],
    // Per insertion: predecessor (low) leaf + its sibling path, and the sibling
    // path of the (empty) append slot.
    low_value: [Field; N],
    low_next_value: [Field; N],
    low_next_index: [Field; N],
    low_path_bits: [[bool; NULLIFIER_TREE_DEPTH]; N],
    low_siblings: [[Field; NULLIFIER_TREE_DEPTH]; N],
    new_siblings: [[Field; NULLIFIER_TREE_DEPTH]; N],
) {
    let empty = leaf_hash(0, 0, 0);
    let mut root = pre_active_root;

    for i in 0..N {
        let nullifier = nullifiers[i];
        // Canonical append index for this insertion.
        let new_index = pre_leaf_count + i;
        let new_bits = index_bits(new_index);

        // 1. Predecessor membership in the current root + non-membership of the
        //    nullifier (low.value < nullifier < low.next_value; next_value 0 = inf).
        let low = leaf_hash(low_value[i], low_next_value[i], low_next_index[i]);
        assert(
            root_from_path(low, low_path_bits[i], low_siblings[i]) == root,
            "insertion: predecessor membership",
        );
        assert(low_value[i].lt(nullifier), "insertion: nullifier <= low_value");
        if low_next_value[i] != 0 {
            assert(nullifier.lt(low_next_value[i]), "insertion: nullifier >= low_next_value");
        }

        // 2. Repoint the predecessor at the new leaf -> intermediate root r'.
        let updated_low = leaf_hash(low_value[i], nullifier, new_index as Field);
        let r_prime = root_from_path(updated_low, low_path_bits[i], low_siblings[i]);

        // 3. The canonical append slot must be empty in r'.
        assert(
            root_from_path(empty, new_bits, new_siblings[i]) == r_prime,
            "insertion: append slot not empty",
        );

        // 4. Write the new leaf (inherits the predecessor's old forward pointer).
        let new_leaf = leaf_hash(nullifier, low_next_value[i], low_next_index[i]);
        root = root_from_path(new_leaf, new_bits, new_siblings[i]);
    }

    assert(root == post_active_root, "insertion: post-root mismatch");
}

use crate::hasher::hash_merkle_node;

fn merkle_hash(pair: [Field; 2]) -> Field {
    hash_merkle_node(pair[0], pair[1])
}

// Generic binary Merkle root with a runtime depth bounded by the
// compile-time MAX_DEPTH. Path bits are bool (false = left, true =
// right).
pub fn binary_merkle_root<let MAX_DEPTH: u32>(
    hasher: fn([Field; 2]) -> Field,
    leaf: Field,
    depth: u32,
    indices: [bool; MAX_DEPTH],
    siblings: [Field; MAX_DEPTH],
) -> Field {
    let mut node = leaf;
    for i in 0..MAX_DEPTH {
        if i < depth {
            let sibling = siblings[i];
            let (left, right) = if indices[i] {
                (sibling, node)
            } else {
                (node, sibling)
            };
            node = hasher([left, right]);
        }
    }
    node
}

pub fn verify_membership_depth_24(
    leaf: Field,
    root: Field,
    proof_length: u32,
    path_indices: [bool; 24],
    path_elements: [Field; 24],
) {
    let computed = binary_merkle_root(merkle_hash, leaf, proof_length, path_indices, path_elements);
    assert(computed == root, "merkle proof failed (depth 24)");
}

pub fn verify_membership_depth_32(
    leaf: Field,
    root: Field,
    proof_length: u32,
    path_indices: [bool; 32],
    path_elements: [Field; 32],
) {
    let computed = binary_merkle_root(merkle_hash, leaf, proof_length, path_indices, path_elements);
    assert(computed == root, "merkle proof failed (depth 32)");
}

pub fn compute_root_depth_24(
    leaf: Field,
    path_indices: [bool; 24],
    path_elements: [Field; 24],
) -> Field {
    binary_merkle_root(merkle_hash, leaf, 24, path_indices, path_elements)
}

// Decompose `x: u32` into 24 LSB-first bool bits and assert `x < 2^24`.
// Used to bind a leaf_index witness to a `[bool; 24]` path_indices array.
pub fn u32_to_bits_24(x: u32) -> [bool; 24] {
    let limit: u32 = 16777216; // 2^24
    assert(x < limit, "merkle: index >= 2^24");
    let mut bits: [bool; 24] = [false; 24];
    let mut acc: u32 = x;
    for i in 0..24 {
        bits[i] = (acc & 1) == 1;
        acc = acc >> 1;
    }
    bits
}

// Equality check between two [bool; 24] arrays.
pub fn assert_bits_eq_24(a: [bool; 24], b: [bool; 24]) {
    for i in 0..24 {
        assert(a[i] == b[i], "merkle: path-index bit mismatch");
    }
}

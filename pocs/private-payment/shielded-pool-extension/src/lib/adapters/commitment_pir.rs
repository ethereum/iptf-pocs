//! tree-pir layout for the commitment tree.
//!
//! Flattens every LeanIMT node into a level-major array and packs each 32-byte
//! node into 16-bit limbs (records `< 2^17`, SimplePIR's plaintext bound), then
//! builds a [`PirDatabase`]. The server hosts this; the wallet — which knows its
//! own leaf index — computes the sibling-node record offsets with the SAME layout
//! plus `stateless_path`, so it fetches its membership path obliviously (the
//! offset math here is shared with the client adapter in the next slice).
//!
//! The layout is deterministic in the leaf count alone: `level_sizes` mirrors
//! LeanIMT's ceil-halving structure, so the client reproduces every offset
//! without seeing the tree.

use alloy::primitives::B256;

use crate::adapters::{
    merkle_tree::CommitmentTree,
    pir::PirDatabase,
};

/// 16-bit limbs per 32-byte node (256 / 16). Each limb is `< 2^16 < 2^17`, so it
/// fits a SimplePIR record under the `2^17` plaintext modulus.
pub const LIMBS_PER_NODE: usize = 16;

/// Node counts per level of a LeanIMT with `leaf_count` leaves: level 0 =
/// `leaf_count`, each higher level = `ceil(prev / 2)`, down to the single root.
/// Matches LeanIMT's node structure and `stateless_path`'s recurrence, so the
/// client reproduces it from the leaf count alone.
pub fn level_sizes(leaf_count: usize) -> Vec<usize> {
    if leaf_count == 0 {
        return Vec::new();
    }
    let mut sizes = vec![leaf_count];
    let mut size = leaf_count;
    while size > 1 {
        size = size.div_ceil(2);
        sizes.push(size);
    }
    sizes
}

/// Flat (level-major) position of node `(level, index)`: all lower levels' nodes,
/// then `index`. Its 16 limbs occupy records `[offset*16, offset*16 + 16)`.
pub fn node_offset(level_sizes: &[usize], level: usize, index: usize) -> usize {
    level_sizes[..level].iter().sum::<usize>() + index
}

/// PIR record index of limb `limb` of node `(level, index)`.
pub fn record_index(level_sizes: &[usize], level: usize, index: usize, limb: usize) -> usize {
    node_offset(level_sizes, level, index) * LIMBS_PER_NODE + limb
}

/// Split a 32-byte node into 16 big-endian 16-bit limbs.
pub fn node_to_limbs(node: B256) -> [u64; LIMBS_PER_NODE] {
    let mut limbs = [0u64; LIMBS_PER_NODE];
    for (i, limb) in limbs.iter_mut().enumerate() {
        *limb = u16::from_be_bytes([node.0[2 * i], node.0[2 * i + 1]]) as u64;
    }
    limbs
}

/// Reassemble 16 big-endian 16-bit limbs into a 32-byte node.
pub fn limbs_to_node(limbs: &[u64]) -> B256 {
    let mut bytes = [0u8; 32];
    for (i, limb) in limbs.iter().take(LIMBS_PER_NODE).enumerate() {
        let be = (*limb as u16).to_be_bytes();
        bytes[2 * i] = be[0];
        bytes[2 * i + 1] = be[1];
    }
    B256::from(bytes)
}

/// Flatten the commitment tree's nodes (level-major) and pack them into a
/// SimplePIR database of 16-bit-limb records. Records are laid out in exactly the
/// order [`node_offset`] / [`record_index`] address, so a client fetch at
/// `record_index(level_sizes(leaf_count), level, index, limb)` returns the right
/// limb. (Build is the expensive offline step — SimplePIR `setup`.)
pub fn build_commitment_pir_db(tree: &CommitmentTree) -> PirDatabase {
    let mut records = Vec::new();
    for level in tree.nodes() {
        for node in level {
            records.extend_from_slice(&node_to_limbs(B256::from_slice(node)));
        }
    }
    PirDatabase::from_records(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limb_roundtrip() {
        for node in [B256::ZERO, B256::repeat_byte(0xAB), B256::from_slice(&(0u8..32).collect::<Vec<_>>())] {
            assert_eq!(limbs_to_node(&node_to_limbs(node)), node);
        }
    }

    #[test]
    fn level_sizes_follow_ceil_halving() {
        assert_eq!(level_sizes(0), Vec::<usize>::new());
        assert_eq!(level_sizes(1), vec![1]);
        assert_eq!(level_sizes(5), vec![5, 3, 2, 1]);
        assert_eq!(level_sizes(8), vec![8, 4, 2, 1]);
    }

    /// Every commitment-tree node round-trips through the flattened PIR database:
    /// `record_index` + an oblivious `fetch` of its 16 limbs reassembles the node.
    /// Also pins the layout invariant the client relies on: the computed
    /// `level_sizes` equal the tree's actual per-level node counts.
    #[test]
    fn flattened_db_recovers_every_node() {
        let mut tree = CommitmentTree::new();
        for i in 1..=5u8 {
            tree.insert(&[i; 32]);
        }
        let sizes = level_sizes(tree.len());

        let actual: Vec<usize> = tree.nodes().iter().map(|level| level.len()).collect();
        assert_eq!(actual, sizes, "computed level sizes must match the tree's node levels");

        let db = build_commitment_pir_db(&tree);
        for (level, level_nodes) in tree.nodes().iter().enumerate() {
            for index in 0..level_nodes.len() {
                let limbs: Vec<u64> = (0..LIMBS_PER_NODE)
                    .map(|limb| db.fetch(record_index(&sizes, level, index, limb)))
                    .collect();
                assert_eq!(
                    limbs_to_node(&limbs),
                    B256::from_slice(&tree.nodes()[level][index]),
                    "node ({level}, {index}) must round-trip through PIR",
                );
            }
        }
    }
}

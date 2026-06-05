use insertion_core::{NULLIFIER_TREE_DEPTH, run_insertions};

// Insertion circuit (relayer-produced; verified on-chain; need not be zk).
// Instantiates the shared `insertion_core::run_insertions` at N_INSERTS = 2 (a
// 2-in transfer). The single-input withdraw uses the same core at N_INSERTS = 1
// (see `circuits/insertion_withdraw`). See ../../SPEC.md "Insertion Circuit (new)".

global N_INSERTS: u32 = 2;

fn main(
    pre_active_root: pub Field,
    post_active_root: pub Field,
    pre_leaf_count: pub u32,
    nullifiers: pub [Field; N_INSERTS],
    low_value: [Field; N_INSERTS],
    low_next_value: [Field; N_INSERTS],
    low_next_index: [Field; N_INSERTS],
    low_path_bits: [[bool; NULLIFIER_TREE_DEPTH]; N_INSERTS],
    low_siblings: [[Field; NULLIFIER_TREE_DEPTH]; N_INSERTS],
    new_siblings: [[Field; NULLIFIER_TREE_DEPTH]; N_INSERTS],
) {
    run_insertions(
        pre_active_root,
        post_active_root,
        pre_leaf_count,
        nullifiers,
        low_value,
        low_next_value,
        low_next_index,
        low_path_bits,
        low_siblings,
        new_siblings,
    );
}

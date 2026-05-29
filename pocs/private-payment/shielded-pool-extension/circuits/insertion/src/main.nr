// Insertion circuit (new).
//
// Produced by the relayer (state-replica operator), verified on-chain, need
// not be zero-knowledge. Advances the active-epoch indexed Merkle tree by
// chaining `k` sorted-low-leaf insertions of the public `eta_active_1..k` list:
// threads r_0 = pre_active_root -> r_k == post_active_root, mutating two
// leaves per input (predecessor repoint + new leaf at pre_leaf_count + i-1)
// with an empty-slot check. Public inputs:
// (pre_active_root, post_active_root, pre_leaf_count, eta_active_1..k).
//
// The contract binds this list element-wise to the spend proof's emitted
// eta_active_i values (cross-proof binding). See ../../SPEC.md "Insertion
// Circuit (new)" and "Cross-proof binding".
//
// TODO: implement.

fn main() {}

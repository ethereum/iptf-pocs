// Witness assembly for the extended deposit / spend / chain-update / insertion
// circuits. The spend witness carries per-input chain proofs + commitment
// membership (no active-tree insertion). The insertion witness (per input:
// low_leaf, low_leaf_index, low_leaf_path, new_leaf_path) is built by the
// relayer and consumed by the insertion circuit.
//
// TODO: implement.

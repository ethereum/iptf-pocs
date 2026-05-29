// Transfer spend circuit (extended).
//
// Diff vs parent: per-input chain proof verified recursively, commitment-tree
// membership against `commitment_root`, per-input nullifier derivation
// `η_active_i = poseidon(commitment_in_i, sk, current_epoch)` emitted publicly,
// `epoch_created` bound into the output commitments. Performs NO active-tree
// work — the active-epoch indexed-tree insertion lives in the separate
// insertion circuit (relayer-produced). See ../../SPEC.md "Spend Circuit
// (Transfer / Withdraw, diff)".
//
// TODO: implement.

fn main() {}

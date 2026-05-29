// Chain-update circuit (new).
//
// IVC step over per-note non-spend history. Recursively verifies the
// prior chain proof, asserts sorted-low-leaf non-membership of the
// per-epoch nullifier in the frozen tree for the next epoch, and folds
// the epoch's frozen root into the running accumulator. A base-case
// branch handles note genesis (`epoch_validated_through == epoch_created`,
// `accumulator == 0`). See ../../SPEC.md "Chain-Update Circuit (new)".
//
// TODO: implement.

fn main() {}

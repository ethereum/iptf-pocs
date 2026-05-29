// Indexed Merkle tree (sorted-low-leaf pattern). Used for active and frozen
// nullifier trees. Insertion mutates predecessor + writes a new leaf at the
// next free slot; a valid sorted-low-leaf insertion doubles as a non-membership
// proof of the inserted value. The insertion circuit uses this over the active
// tree; the chain-update circuit uses the non-membership half over frozen trees.
//
// TODO: implement.

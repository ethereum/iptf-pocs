// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// Extension shielded pool (research prototype).
//
// Adds:
//  - currentEpoch / EpochRollover()
//  - active-epoch indexed nullifier tree (activeNullifierRoot + activeLeafCount)
//  - frozenNullifierRoots[e] for past epochs
//  - expectedChainAccumulator(epochCreated) view
//  - spend path verifies TWO proofs (spend + insertion), asserts their ordered
//    η_active_1..k lists are identical (cross-proof binding), checks
//    accumulator/epoch_created per input and pre_active_root/pre_leaf_count,
//    then advances activeNullifierRoot/activeLeafCount.
//
// See ../../SPEC.md "On-Chain State", "Insertion Circuit (new)", and
// "Cross-proof binding" for the full surface.

contract ShieldedPoolExt {
    // TODO: implement.
}

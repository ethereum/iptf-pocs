//! Per-note IVC chain-proof state.
//!
//! Mirrors the public inputs of the chain-update circuit (see
//! `circuits/chain_update`): a [`ChainProof`] attests that a note is unspent
//! from `epoch_created` through `epoch_validated_through - 1`, with the folded
//! frozen roots committed in `accumulator`. The wallet maintains one per owned
//! note, extending it one frozen epoch per rollover.

use alloy::primitives::B256;
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    crypto::poseidon::poseidon2,
    domain::{
        commitment::Commitment,
        epoch::Epoch,
    },
};

/// Chain-proof state (the chain-update circuit's logical public inputs, minus
/// the recursion's `fixed_vk_hash`, which is a prover-side artifact).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainProof {
    /// The note this chain attests about.
    pub commitment: Commitment,
    /// Epoch the note was created in (bound into the commitment).
    pub epoch_created: Epoch,
    /// Next epoch needing non-membership; equals `currentEpoch` when fully
    /// caught up (`epoch_created <= epoch_validated_through <= currentEpoch`).
    pub epoch_validated_through: Epoch,
    /// Running Poseidon hash over the frozen roots folded so far.
    pub accumulator: B256,
}

impl ChainProof {
    /// Genesis (base case): nothing folded yet.
    pub fn genesis(commitment: Commitment, epoch_created: Epoch) -> Self {
        Self {
            commitment,
            epoch_created,
            epoch_validated_through: epoch_created,
            accumulator: B256::ZERO,
        }
    }

    /// Whether this is the genesis (base-case) state.
    pub fn is_genesis(&self) -> bool {
        self.epoch_validated_through == self.epoch_created && self.accumulator == B256::ZERO
    }

    /// Fold the frozen root of `epoch_validated_through` into the chain,
    /// advancing one epoch: `accumulator' = poseidon2(accumulator, frozen_root)`.
    pub fn extend(&self, frozen_root: B256) -> Self {
        Self {
            commitment: self.commitment,
            epoch_created: self.epoch_created,
            epoch_validated_through: self.epoch_validated_through.next(),
            accumulator: poseidon2(self.accumulator, frozen_root),
        }
    }
}

/// The accumulator the on-chain `expectedChainAccumulator` recomputes: a
/// sequential `poseidon2` fold of `frozen_roots` starting from zero. A genesis
/// chain proof extended over these same roots reaches this value.
pub fn expected_accumulator(frozen_roots: &[B256]) -> B256 {
    frozen_roots
        .iter()
        .fold(B256::ZERO, |acc, root| poseidon2(acc, *root))
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;

    use super::*;

    fn c(n: u64) -> Commitment {
        Commitment(B256::from(U256::from(n)))
    }

    fn r(n: u64) -> B256 {
        B256::from(U256::from(n))
    }

    #[test]
    fn genesis_is_empty() {
        let g = ChainProof::genesis(c(42), Epoch(3));
        assert!(g.is_genesis());
        assert_eq!(g.epoch_validated_through, Epoch(3));
        assert_eq!(g.accumulator, B256::ZERO);
    }

    #[test]
    fn extend_advances_epoch_and_folds() {
        let g = ChainProof::genesis(c(42), Epoch(0));
        let s1 = g.extend(r(10));
        assert_eq!(s1.epoch_validated_through, Epoch(1));
        assert_eq!(s1.accumulator, poseidon2(B256::ZERO, r(10)));
        assert!(!s1.is_genesis());

        let s2 = s1.extend(r(20));
        assert_eq!(s2.epoch_validated_through, Epoch(2));
        assert_eq!(s2.accumulator, poseidon2(poseidon2(B256::ZERO, r(10)), r(20)));
        // commitment / epoch_created are invariant across extension.
        assert_eq!(s2.commitment, c(42));
        assert_eq!(s2.epoch_created, Epoch(0));
    }

    #[test]
    fn extension_matches_on_chain_expected_accumulator() {
        let roots = [r(10), r(20), r(30)];
        let mut proof = ChainProof::genesis(c(7), Epoch(0));
        for root in roots {
            proof = proof.extend(root);
        }
        assert_eq!(proof.accumulator, expected_accumulator(&roots));
        assert_eq!(proof.epoch_validated_through, Epoch(3));
    }
}

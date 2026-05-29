use alloy::primitives::{
    B256,
    U256,
};
use serde::{
    Deserialize,
    Serialize,
};

/// An epoch counter. `currentEpoch` on-chain is advanced by `rolloverEpoch()`;
/// distinct epoch values yield distinct nullifiers for the same note.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct Epoch(pub u64);

impl Epoch {
    /// The first epoch; notes minted before any rollover are created here.
    pub const GENESIS: Epoch = Epoch(0);

    /// Field encoding used in Poseidon preimages and circuit inputs.
    ///
    /// This is the integer value of the epoch as a field element, matching the
    /// Noir-side `epoch as Field` cast (the same convention the parent uses for
    /// `amount` and timestamp fields).
    pub fn as_field(self) -> B256 {
        B256::from(U256::from(self.0))
    }

    /// The next epoch after a rollover.
    pub fn next(self) -> Epoch {
        Epoch(self.0 + 1)
    }
}

impl From<u64> for Epoch {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<Epoch> for u64 {
    fn from(value: Epoch) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_field_is_zero() {
        assert_eq!(Epoch::GENESIS.as_field(), B256::ZERO);
    }

    #[test]
    fn test_next_increments() {
        assert_eq!(Epoch(4).next(), Epoch(5));
    }

    #[test]
    fn test_ordering() {
        assert!(Epoch(2) < Epoch(3));
    }
}

//! Typed journal structs for parsing guest circuit public outputs.
//!
//! Guest circuits commit raw bytes via `env::commit_slice` for on-chain
//! compatibility (Solidity uses `abi.encodePacked` with the same layout).
//! These structs provide typed parsing on the host side, replacing manual
//! byte slicing with structured access.

use anyhow::{ensure, Result};

/// Transfer circuit public outputs: old_root || new_root || nullifier (96 bytes).
pub struct TransferJournal {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub nullifier: [u8; 32],
}

/// Withdrawal circuit public outputs:
/// old_root || new_root || nullifier || amount_be || recipient (124 bytes).
pub struct WithdrawalJournal {
    pub old_root: [u8; 32],
    pub new_root: [u8; 32],
    pub nullifier: [u8; 32],
    pub amount: u64,
    pub recipient: [u8; 20],
}

/// Disclosure circuit public outputs:
/// merkle_root || threshold_be || disclosure_key_hash (72 bytes).
pub struct DisclosureJournal {
    pub merkle_root: [u8; 32],
    pub threshold: u64,
    pub disclosure_key_hash: [u8; 32],
}

impl TransferJournal {
    /// Expected journal size in bytes: 32 + 32 + 32 = 96.
    pub const SIZE: usize = 96;

    /// Parse a transfer journal from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::SIZE,
            "Transfer journal should be {} bytes, got {}",
            Self::SIZE,
            bytes.len()
        );
        Ok(Self {
            old_root: bytes[..32].try_into()?,
            new_root: bytes[32..64].try_into()?,
            nullifier: bytes[64..96].try_into()?,
        })
    }
}

impl WithdrawalJournal {
    /// Expected journal size in bytes: 32 + 32 + 32 + 8 + 20 = 124.
    pub const SIZE: usize = 124;

    /// Parse a withdrawal journal from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::SIZE,
            "Withdrawal journal should be {} bytes, got {}",
            Self::SIZE,
            bytes.len()
        );
        Ok(Self {
            old_root: bytes[..32].try_into()?,
            new_root: bytes[32..64].try_into()?,
            nullifier: bytes[64..96].try_into()?,
            amount: u64::from_be_bytes(bytes[96..104].try_into()?),
            recipient: bytes[104..124].try_into()?,
        })
    }
}

impl DisclosureJournal {
    /// Expected journal size in bytes: 32 + 8 + 32 = 72.
    pub const SIZE: usize = 72;

    /// Parse a disclosure journal from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() == Self::SIZE,
            "Disclosure journal should be {} bytes, got {}",
            Self::SIZE,
            bytes.len()
        );
        Ok(Self {
            merkle_root: bytes[..32].try_into()?,
            threshold: u64::from_be_bytes(bytes[32..40].try_into()?),
            disclosure_key_hash: bytes[40..72].try_into()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transfer_journal_round_trip() {
        let mut bytes = vec![0u8; TransferJournal::SIZE];
        bytes[0] = 0xAA; // old_root first byte
        bytes[32] = 0xBB; // new_root first byte
        bytes[64] = 0xCC; // nullifier first byte

        let journal = TransferJournal::from_bytes(&bytes).unwrap();
        assert_eq!(journal.old_root[0], 0xAA);
        assert_eq!(journal.new_root[0], 0xBB);
        assert_eq!(journal.nullifier[0], 0xCC);
    }

    #[test]
    fn test_transfer_journal_wrong_size() {
        let bytes = vec![0u8; 95];
        assert!(TransferJournal::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_withdrawal_journal_round_trip() {
        let mut bytes = vec![0u8; WithdrawalJournal::SIZE];
        bytes[0] = 0xAA; // old_root
        bytes[32] = 0xBB; // new_root
        bytes[64] = 0xCC; // nullifier
        bytes[96..104].copy_from_slice(&500u64.to_be_bytes()); // amount
        bytes[104] = 0xDD; // recipient first byte

        let journal = WithdrawalJournal::from_bytes(&bytes).unwrap();
        assert_eq!(journal.old_root[0], 0xAA);
        assert_eq!(journal.new_root[0], 0xBB);
        assert_eq!(journal.nullifier[0], 0xCC);
        assert_eq!(journal.amount, 500);
        assert_eq!(journal.recipient[0], 0xDD);
    }

    #[test]
    fn test_withdrawal_journal_wrong_size() {
        let bytes = vec![0u8; 123];
        assert!(WithdrawalJournal::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_disclosure_journal_round_trip() {
        let mut bytes = vec![0u8; DisclosureJournal::SIZE];
        bytes[0] = 0xAA; // merkle_root
        bytes[32..40].copy_from_slice(&2000u64.to_be_bytes()); // threshold
        bytes[40] = 0xBB; // disclosure_key_hash first byte

        let journal = DisclosureJournal::from_bytes(&bytes).unwrap();
        assert_eq!(journal.merkle_root[0], 0xAA);
        assert_eq!(journal.threshold, 2000);
        assert_eq!(journal.disclosure_key_hash[0], 0xBB);
    }

    #[test]
    fn test_disclosure_journal_wrong_size() {
        let bytes = vec![0u8; 71];
        assert!(DisclosureJournal::from_bytes(&bytes).is_err());
    }
}

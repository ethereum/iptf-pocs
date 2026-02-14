//! In-memory account store for the diy-validium operator.
//!
//! Holds `Account` records (pubkey, balance, salt) and provides
//! convenience methods for computing commitments and building
//! Merkle trees. No persistence — see SPEC.md Limitations section.

use crate::merkle::{account_commitment, MerkleTree};

/// An account in the operator's off-chain store.
pub struct Account {
    pub pubkey: [u8; 32],
    pub balance: u64,
    pub salt: [u8; 32],
}

/// A simple `Vec<Account>` wrapper that the operator uses to manage
/// off-chain state and rebuild Merkle trees from account commitments.
pub struct AccountStore {
    accounts: Vec<Account>,
}

impl Default for AccountStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AccountStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            accounts: Vec::new(),
        }
    }

    /// Number of accounts in the store.
    pub fn len(&self) -> usize {
        self.accounts.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Add an account and return its index.
    pub fn add_account(&mut self, account: Account) -> usize {
        let idx = self.accounts.len();
        self.accounts.push(account);
        idx
    }

    /// Get a reference to the account at `index`.
    pub fn get_account(&self, index: usize) -> &Account {
        &self.accounts[index]
    }

    /// Update an account's balance and salt.
    pub fn update_balance(&mut self, index: usize, new_balance: u64, new_salt: [u8; 32]) {
        self.accounts[index].balance = new_balance;
        self.accounts[index].salt = new_salt;
    }

    /// Compute the commitment for every account:
    /// `SHA256(pubkey || balance_le || salt)`.
    pub fn commitments(&self) -> Vec<[u8; 32]> {
        self.accounts
            .iter()
            .map(|a| account_commitment(&a.pubkey, a.balance, &a.salt))
            .collect()
    }

    /// Build a Merkle tree of the given `depth` from account commitments.
    pub fn build_tree(&self, depth: usize) -> MerkleTree {
        let commitments = self.commitments();
        MerkleTree::from_leaves(&commitments, depth)
    }
}

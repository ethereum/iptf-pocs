//! ZK proof outputs and their public-input layouts.
//!
//! Each `public_inputs_as_array()` returns the public inputs in the exact order
//! the matching circuit declares them in `main` — which is the same order
//! `ShieldedPoolExt` marshals them for on-chain verification. Epochs are
//! field-encoded (`Epoch::as_field`), addresses as left-padded B256, matching
//! the contract.

use alloy::primitives::{
    Address,
    B256,
    Bytes,
    U256,
};
use serde::{
    Deserialize,
    Serialize,
};

use super::epoch::Epoch;

fn addr_field(addr: Address) -> B256 {
    B256::left_padding_from(addr.as_slice())
}

// ===== Deposit =====

/// Public inputs for the deposit circuit: `[commitment, token, amount, current_epoch]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositPublicInputs {
    pub commitment: B256,
    pub token: Address,
    pub amount: U256,
    pub current_epoch: Epoch,
}

/// A deposit proof and its public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositProof {
    pub proof: Bytes,
    pub public_inputs: DepositPublicInputs,
}

impl DepositProof {
    pub fn new(
        proof: Bytes,
        commitment: B256,
        token: Address,
        amount: U256,
        current_epoch: Epoch,
    ) -> Self {
        Self {
            proof,
            public_inputs: DepositPublicInputs { commitment, token, amount, current_epoch },
        }
    }

    /// `[commitment, token, amount, current_epoch]` (matches `ShieldedPoolExt.deposit`).
    pub fn public_inputs_as_array(&self) -> [B256; 4] {
        [
            self.public_inputs.commitment,
            addr_field(self.public_inputs.token),
            self.public_inputs.amount.into(),
            self.public_inputs.current_epoch.as_field(),
        ]
    }
}

// ===== Transfer (2-in-2-out spend) =====

/// Public inputs for the transfer spend circuit (11 fields, circuit order).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferPublicInputs {
    pub nullifiers: [B256; 2],
    pub output_commitments: [B256; 2],
    pub commitment_root: B256,
    pub current_epoch: Epoch,
    pub chain_vk_hash: B256,
    pub epoch_created_in: [Epoch; 2],
    pub chain_accumulator_in: [B256; 2],
}

/// A transfer spend proof and its public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferProof {
    pub proof: Bytes,
    pub public_inputs: TransferPublicInputs,
}

impl TransferProof {
    /// `[η0, η1, out0, out1, root, current_epoch, chain_vk_hash, ec0, ec1, acc0, acc1]`
    /// — matches `circuits/transfer` and `ShieldedPoolExt.transfer`.
    pub fn public_inputs_as_array(&self) -> [B256; 11] {
        let p = &self.public_inputs;
        [
            p.nullifiers[0],
            p.nullifiers[1],
            p.output_commitments[0],
            p.output_commitments[1],
            p.commitment_root,
            p.current_epoch.as_field(),
            p.chain_vk_hash,
            p.epoch_created_in[0].as_field(),
            p.epoch_created_in[1].as_field(),
            p.chain_accumulator_in[0],
            p.chain_accumulator_in[1],
        ]
    }

    pub fn nullifiers(&self) -> [B256; 2] {
        self.public_inputs.nullifiers
    }

    pub fn output_commitments(&self) -> [B256; 2] {
        self.public_inputs.output_commitments
    }
}

// ===== Withdraw (single-input spend) =====

/// Public inputs for the withdraw spend circuit (9 fields, circuit order).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawPublicInputs {
    pub nullifier: B256,
    pub token: Address,
    pub amount: U256,
    pub recipient: Address,
    pub commitment_root: B256,
    pub current_epoch: Epoch,
    pub chain_vk_hash: B256,
    pub epoch_created_in: Epoch,
    pub chain_accumulator_in: B256,
}

/// A withdraw spend proof and its public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawProof {
    pub proof: Bytes,
    pub public_inputs: WithdrawPublicInputs,
}

impl WithdrawProof {
    /// `[η, token, amount, recipient, root, current_epoch, chain_vk_hash, ec, acc]`
    /// — matches `circuits/withdraw` and `ShieldedPoolExt.withdraw`.
    pub fn public_inputs_as_array(&self) -> [B256; 9] {
        let p = &self.public_inputs;
        [
            p.nullifier,
            addr_field(p.token),
            p.amount.into(),
            addr_field(p.recipient),
            p.commitment_root,
            p.current_epoch.as_field(),
            p.chain_vk_hash,
            p.epoch_created_in.as_field(),
            p.chain_accumulator_in,
        ]
    }
}

// ===== Insertion (relayer; k = number of spent nullifiers) =====

/// Public inputs for the insertion circuit: `[pre_active_root, post_active_root,
/// pre_leaf_count, η_1..k]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionPublicInputs {
    pub pre_active_root: B256,
    pub post_active_root: B256,
    pub pre_leaf_count: u64,
    pub nullifiers: Vec<B256>,
}

/// An insertion proof and its public inputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertionProof {
    pub proof: Bytes,
    pub public_inputs: InsertionPublicInputs,
}

impl InsertionProof {
    /// `[pre_active_root, post_active_root, pre_leaf_count, η_1..k]` — matches
    /// `circuits/insertion` and the insertion inputs in `ShieldedPoolExt`.
    pub fn public_inputs_as_array(&self) -> Vec<B256> {
        let p = &self.public_inputs;
        let mut inputs = Vec::with_capacity(3 + p.nullifiers.len());
        inputs.push(p.pre_active_root);
        inputs.push(p.post_active_root);
        inputs.push(B256::from(U256::from(p.pre_leaf_count)));
        inputs.extend_from_slice(&p.nullifiers);
        inputs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b(n: u64) -> B256 {
        B256::from(U256::from(n))
    }

    #[test]
    fn deposit_inputs_in_circuit_order() {
        let p = DepositProof::new(Bytes::new(), b(1), Address::ZERO, U256::from(50u64), Epoch(3));
        let arr = p.public_inputs_as_array();
        assert_eq!(arr[0], b(1)); // commitment
        assert_eq!(arr[2], b(50)); // amount
        assert_eq!(arr[3], Epoch(3).as_field()); // current_epoch
    }

    #[test]
    fn transfer_inputs_in_circuit_order() {
        let p = TransferProof {
            proof: Bytes::new(),
            public_inputs: TransferPublicInputs {
                nullifiers: [b(10), b(11)],
                output_commitments: [b(20), b(21)],
                commitment_root: b(30),
                current_epoch: Epoch(5),
                chain_vk_hash: b(99),
                epoch_created_in: [Epoch(2), Epoch(3)],
                chain_accumulator_in: [b(40), b(41)],
            },
        };
        let arr = p.public_inputs_as_array();
        assert_eq!(arr.len(), 11);
        assert_eq!(arr[0], b(10)); // η0
        assert_eq!(arr[5], Epoch(5).as_field()); // current_epoch
        assert_eq!(arr[6], b(99)); // chain_vk_hash
        assert_eq!(arr[7], Epoch(2).as_field()); // epoch_created_in_0
        assert_eq!(arr[10], b(41)); // chain_accumulator_in_1
    }

    #[test]
    fn insertion_inputs_prepend_roots_and_count() {
        let p = InsertionProof {
            proof: Bytes::new(),
            public_inputs: InsertionPublicInputs {
                pre_active_root: b(1),
                post_active_root: b(2),
                pre_leaf_count: 7,
                nullifiers: vec![b(10), b(11)],
            },
        };
        let arr = p.public_inputs_as_array();
        assert_eq!(arr, vec![b(1), b(2), b(7), b(10), b(11)]);
    }
}

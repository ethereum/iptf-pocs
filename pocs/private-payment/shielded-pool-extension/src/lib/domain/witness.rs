//! Witness (prover-input) types for the extended deposit / spend circuits.
//!
//! These carry only domain data — notes, keys, commitment-membership proofs, and
//! per-input chain-proof *state*. The recursive chain-proof *artifacts* (bb proof
//! bytes / field-encoded public inputs) and the insertion witness are prover- and
//! relayer-side concerns wired where their adapters live, not here. No attestation
//! data: the extension's deposit circuit does not enforce KYC attestation (see
//! README "Implementation shortcuts").

use alloy::primitives::{
    Address,
    B256,
};
use serde::{
    Deserialize,
    Serialize,
};

use super::{
    chain_proof::ChainProof,
    epoch::Epoch,
    keys::SpendingKey,
    merkle::CommitmentMerkleProof,
    note::Note,
};

/// Inputs for the deposit circuit. The note's `epoch_created` is the epoch the
/// deposit mints into; the contract pins it as the proof's `current_epoch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositWitness {
    pub note: Note,
}

impl DepositWitness {
    pub fn new(note: Note) -> Self {
        Self { note }
    }

    /// The note commitment (the deposit's public commitment).
    pub fn commitment(&self) -> B256 {
        self.note.commitment().0
    }

    /// The epoch the deposit mints into (`= note.epoch_created`).
    pub fn current_epoch(&self) -> Epoch {
        self.note.epoch_created
    }
}

/// Inputs for the transfer spend circuit (2-in-2-out). Carries the per-input
/// chain-proof state; the spend is valid only when each chain proof is caught up
/// to `current_epoch` (`validate_chain_proofs`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferWitness {
    pub spending_key: SpendingKey,
    pub input_notes: [Note; 2],
    pub output_notes: [Note; 2],
    pub input_proofs: [CommitmentMerkleProof; 2],
    pub chain_proofs: [ChainProof; 2],
    pub commitment_root: B256,
    pub current_epoch: Epoch,
}

impl TransferWitness {
    pub fn new(
        spending_key: SpendingKey,
        input_notes: [Note; 2],
        output_notes: [Note; 2],
        input_proofs: [CommitmentMerkleProof; 2],
        chain_proofs: [ChainProof; 2],
        commitment_root: B256,
        current_epoch: Epoch,
    ) -> Self {
        Self {
            spending_key,
            input_notes,
            output_notes,
            input_proofs,
            chain_proofs,
            commitment_root,
            current_epoch,
        }
    }

    /// Per-input active nullifiers `η = poseidon3(commitment, sk, current_epoch)`.
    pub fn nullifiers(&self) -> [B256; 2] {
        [
            self.input_notes[0].nullifier(&self.spending_key, self.current_epoch).0,
            self.input_notes[1].nullifier(&self.spending_key, self.current_epoch).0,
        ]
    }

    /// Output-note commitments (minted at `current_epoch`).
    pub fn output_commitments(&self) -> [B256; 2] {
        [self.output_notes[0].commitment().0, self.output_notes[1].commitment().0]
    }

    /// Input value equals output value (zero/padding inputs contribute 0).
    pub fn validate_amounts(&self) -> bool {
        let input_sum = self.input_notes[0].amount + self.input_notes[1].amount;
        let output_sum = self.output_notes[0].amount + self.output_notes[1].amount;
        input_sum == output_sum
    }

    /// All notes share one token.
    pub fn validate_token_consistency(&self) -> bool {
        let token = self.input_notes[0].token;
        self.input_notes[1].token == token
            && self.output_notes[0].token == token
            && self.output_notes[1].token == token
    }

    /// Each non-padding input's chain proof is about that note and caught up to
    /// `current_epoch` (a zero/padding input carries no real chain proof — the
    /// circuit skips its recursive verify).
    pub fn validate_chain_proofs(&self) -> bool {
        (0..2).all(|i| {
            self.input_notes[i].is_zero() || {
                let cp = &self.chain_proofs[i];
                cp.commitment == self.input_notes[i].commitment()
                    && cp.epoch_created == self.input_notes[i].epoch_created
                    && cp.epoch_validated_through == self.current_epoch
            }
        })
    }
}

/// Inputs for the withdraw spend circuit (single input, full-value exit).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawWitness {
    pub spending_key: SpendingKey,
    pub note: Note,
    pub commitment_proof: CommitmentMerkleProof,
    pub chain_proof: ChainProof,
    pub commitment_root: B256,
    pub current_epoch: Epoch,
    pub recipient: Address,
}

impl WithdrawWitness {
    pub fn new(
        spending_key: SpendingKey,
        note: Note,
        commitment_proof: CommitmentMerkleProof,
        chain_proof: ChainProof,
        commitment_root: B256,
        current_epoch: Epoch,
        recipient: Address,
    ) -> Self {
        Self {
            spending_key,
            note,
            commitment_proof,
            chain_proof,
            commitment_root,
            current_epoch,
            recipient,
        }
    }

    /// The active nullifier `η = poseidon3(commitment, sk, current_epoch)`.
    pub fn nullifier(&self) -> B256 {
        self.note.nullifier(&self.spending_key, self.current_epoch).0
    }

    /// The chain proof is about this note and caught up to `current_epoch`.
    pub fn validate_chain_proof(&self) -> bool {
        self.chain_proof.commitment == self.note.commitment()
            && self.chain_proof.epoch_created == self.note.epoch_created
            && self.chain_proof.epoch_validated_through == self.current_epoch
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::U256;

    use super::*;

    fn caught_up_chain(note: &Note, current_epoch: Epoch) -> ChainProof {
        // A chain proof about `note`, reported as validated through `current_epoch`.
        let mut cp = ChainProof::genesis(note.commitment(), note.epoch_created);
        cp.epoch_validated_through = current_epoch;
        cp
    }

    #[test]
    fn transfer_validations_pass_for_consistent_witness() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;
        let inputs = [
            Note::new(token, U256::from(600u64), pk, Epoch(0)),
            Note::new(token, U256::from(400u64), pk, Epoch(1)),
        ];
        let outputs = [
            Note::new(token, U256::from(700u64), pk, Epoch(2)),
            Note::new(token, U256::from(300u64), pk, Epoch(2)),
        ];
        let proof = CommitmentMerkleProof::new(vec![], vec![], 0);
        let chains = [caught_up_chain(&inputs[0], Epoch(2)), caught_up_chain(&inputs[1], Epoch(2))];
        let w = TransferWitness::new(
            sk,
            inputs,
            outputs,
            [proof.clone(), proof],
            chains,
            B256::ZERO,
            Epoch(2),
        );

        assert!(w.validate_amounts());
        assert!(w.validate_token_consistency());
        assert!(w.validate_chain_proofs());
        assert_eq!(w.output_commitments()[0], w.output_notes[0].commitment().0);
    }

    #[test]
    fn transfer_rejects_stale_chain_proof() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let token = Address::ZERO;
        let inputs = [
            Note::new(token, U256::from(1000u64), pk, Epoch(0)),
            Note::zero(token, pk, Epoch(2)),
        ];
        let outputs = [
            Note::new(token, U256::from(1000u64), pk, Epoch(2)),
            Note::zero(token, pk, Epoch(2)),
        ];
        let proof = CommitmentMerkleProof::new(vec![], vec![], 0);
        // Input 0's chain proof only validated through epoch 1, but spending in 2.
        let stale = caught_up_chain(&inputs[0], Epoch(1));
        let chains = [stale, ChainProof::genesis(inputs[1].commitment(), Epoch(2))];
        let w = TransferWitness::new(sk, inputs, outputs, [proof.clone(), proof], chains, B256::ZERO, Epoch(2));

        assert!(!w.validate_chain_proofs(), "stale chain proof must be rejected");
    }

    #[test]
    fn withdraw_nullifier_and_chain_validation() {
        let sk = SpendingKey::random();
        let pk = sk.derive_owner_pubkey();
        let note = Note::new(Address::ZERO, U256::from(500u64), pk, Epoch(1));
        let chain = caught_up_chain(&note, Epoch(3));
        let w = WithdrawWitness::new(
            sk.clone(),
            note.clone(),
            CommitmentMerkleProof::new(vec![], vec![], 0),
            chain,
            B256::ZERO,
            Epoch(3),
            Address::repeat_byte(0xBB),
        );

        assert!(w.validate_chain_proof());
        assert_eq!(w.nullifier(), note.nullifier(&sk, Epoch(3)).0);
    }
}

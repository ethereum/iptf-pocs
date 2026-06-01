//! Barretenberg prover adapter.
//!
//! Slice 1.4 wires the **chain-update** recursion (the IVC inner artifact):
//! `bb ... -t noir-recursive` for recursion-friendly proofs, reading the raw
//! `vk` / `vk_hash` / `proof` / `public_inputs` binaries and chunking them into
//! Fr field-decimals (the segfaulting `proof_as_fields_honk` is avoided). The
//! EVM-targeted spend/insertion proving (keccak/`-t evm`) lands in later slices.
//!
//! Requires `nargo` 1.0.0-beta.21 + `bb` 5.0.0-nightly on PATH (see the
//! `noir-recursion-recipe` memory). The recursion test is `#[ignore]`d (it
//! shells out and proves real circuits — minutes); run with
//! `cargo test --lib -- --ignored bb_prover`.

use std::{
    path::PathBuf,
    process::Command,
};

use alloy::primitives::B256;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::Serialize;

/// UltraHonk VK length in field elements (bb 5.0-nightly).
pub const ULTRA_VK_LENGTH_IN_FIELDS: usize = 115;
/// UltraHonk ZK recursive-proof length in field elements.
pub const RECURSIVE_PROOF_LENGTH: usize = 458;
/// ChainProof public-input count.
pub const CHAIN_PROOF_PUB_LEN: usize = 5;

#[derive(Debug, thiserror::Error)]
pub enum BbError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("nargo {0} failed: {1}")]
    Nargo(String, String),
    #[error("bb {0} failed: {1}")]
    Bb(String, String),
    #[error("unexpected artifact size: {0}")]
    Size(String),
}

fn fr_from_be(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn fr_to_decimal(f: Fr) -> String {
    f.into_bigint().to_string()
}

/// Field element (32 bytes, big-endian) as the decimal string Noir's `Prover.toml`
/// expects.
pub fn field_to_decimal(value: B256) -> String {
    fr_to_decimal(fr_from_be(&value.0))
}

/// Chunk a binary artifact into field-decimals (32 bytes each, big-endian).
fn bytes_to_decimals(bytes: &[u8], expect: usize) -> Result<Vec<String>, BbError> {
    if bytes.len() != expect * 32 {
        return Err(BbError::Size(format!(
            "{} bytes; expected {} fields ({} bytes)",
            bytes.len(),
            expect,
            expect * 32
        )));
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|c| fr_to_decimal(fr_from_be(c)))
        .collect())
}

/// A produced chain-update proof and its public inputs, field-encoded for use as
/// the recursive witness of the next chain-update proof.
#[derive(Debug, Clone)]
pub struct ChainUpdateArtifact {
    pub proof: Vec<String>,
    pub public_inputs: Vec<String>,
}

/// `Prover.toml` shape for the chain-update circuit (field names match the
/// circuit's `main` parameters).
#[derive(Serialize)]
pub struct ChainUpdateInput {
    pub commitment: String,
    pub epoch_created: String,
    pub epoch_validated_through: String,
    pub accumulator: String,
    pub fixed_vk_hash: String,
    pub is_base_case: bool,
    pub prior_vk: Vec<String>,
    pub prior_proof: Vec<String>,
    pub prior_public_inputs: Vec<String>,
    pub frozen_root_next: String,
    pub spending_key: String,
    pub token: String,
    pub amount: String,
    pub salt: String,
    pub low_value: String,
    pub low_next_value: String,
    pub low_next_index: String,
    pub path_bits: Vec<bool>,
    pub siblings: Vec<String>,
}

/// Transfer spend-proof public-input count.
pub const TRANSFER_PUB_LEN: usize = 11;

/// `Prover.toml` shape for the transfer spend circuit (field names match the
/// circuit's `main` parameters). The two `chain_*` recursion witnesses are the
/// inner chain-update proof + VK produced by [`BbProver::prove_chain_update`] /
/// [`BbProver::write_chain_update_vk`]; a zero/padding input note leaves its
/// `chain_proof_i` / `chain_pub_i` zeroed (the circuit skips its recursive verify).
#[derive(Serialize)]
pub struct TransferInput {
    pub nullifier_active_0: String,
    pub nullifier_active_1: String,
    pub commitment_out_0: String,
    pub commitment_out_1: String,
    pub commitment_root: String,
    pub current_epoch: String,
    pub chain_vk_hash: String,
    pub epoch_created_in_0: String,
    pub epoch_created_in_1: String,
    pub chain_accumulator_in_0: String,
    pub chain_accumulator_in_1: String,
    pub spending_key: String,
    pub token_in_0: String,
    pub amount_in_0: u64,
    pub salt_in_0: String,
    pub token_in_1: String,
    pub amount_in_1: u64,
    pub salt_in_1: String,
    pub token_out_0: String,
    pub amount_out_0: u64,
    pub owner_out_0: String,
    pub salt_out_0: String,
    pub token_out_1: String,
    pub amount_out_1: u64,
    pub owner_out_1: String,
    pub salt_out_1: String,
    pub proof_length: u32,
    pub path_0: Vec<String>,
    pub indices_0: Vec<bool>,
    pub path_1: Vec<String>,
    pub indices_1: Vec<bool>,
    pub chain_vk: Vec<String>,
    pub chain_proof_0: Vec<String>,
    pub chain_pub_0: Vec<String>,
    pub chain_proof_1: Vec<String>,
    pub chain_pub_1: Vec<String>,
}

/// A produced EVM-target proof and its public inputs, as raw bytes (the form the
/// Solidity `HonkVerifier` consumes: `proof` and the `bytes32[]` public inputs).
#[derive(Debug, Clone)]
pub struct EvmProof {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<u8>,
}

/// Shells `nargo` + `bb` to produce chain-update (recursive) proofs.
pub struct BbProver {
    /// Extension root (the Noir workspace root; `target/` and `circuits/` live here).
    project_root: PathBuf,
}

impl BbProver {
    pub fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }

    fn circuit_json(&self) -> PathBuf {
        self.project_root.join("target").join("chain_update.json")
    }

    fn workspace_witness(&self) -> PathBuf {
        self.project_root.join("target").join("witness.gz")
    }

    fn circuit_dir(&self) -> PathBuf {
        self.project_root.join("circuits").join("chain_update")
    }

    /// Per-circuit dir holding `vk` / `vk_hash` / `proof` / `public_inputs`.
    fn artifact_dir(&self) -> PathBuf {
        self.circuit_dir().join("target")
    }

    /// Compile + write the chain-update VK (recursion target). Returns
    /// `(vk_fields[115], vk_hash_decimal)`. `vk_hash` is the circuit's
    /// `fixed_vk_hash` (the value the spend circuit pins).
    pub fn write_chain_update_vk(&self) -> Result<(Vec<String>, String), BbError> {
        let compile = Command::new("nargo")
            .args(["compile", "--package", "chain_update"])
            .current_dir(&self.project_root)
            .output()?;
        if !compile.status.success() {
            return Err(BbError::Nargo(
                "compile".into(),
                String::from_utf8_lossy(&compile.stderr).into(),
            ));
        }

        std::fs::create_dir_all(self.artifact_dir())?;
        let out = Command::new("bb")
            .args([
                "write_vk",
                "-b",
                self.circuit_json().to_str().unwrap(),
                "-o",
                self.artifact_dir().to_str().unwrap(),
                "-t",
                "noir-recursive",
            ])
            .output()?;
        if !out.status.success() {
            return Err(BbError::Bb(
                "write_vk".into(),
                String::from_utf8_lossy(&out.stderr).into(),
            ));
        }

        let vk = bytes_to_decimals(
            &std::fs::read(self.artifact_dir().join("vk"))?,
            ULTRA_VK_LENGTH_IN_FIELDS,
        )?;
        let vk_hash_bytes = std::fs::read(self.artifact_dir().join("vk_hash"))?;
        let vk_hash = fr_to_decimal(fr_from_be(&vk_hash_bytes));
        Ok((vk, vk_hash))
    }

    /// Prove the chain-update circuit for the given inputs. Returns the recursive
    /// proof + its public inputs. The recursive verify of any prior proof runs
    /// during `nargo execute`, so a successful return is itself proof that the
    /// prior chain proof recursively verified.
    pub fn prove_chain_update(
        &self,
        input: &ChainUpdateInput,
    ) -> Result<ChainUpdateArtifact, BbError> {
        let toml = toml::to_string(input).expect("serialize chain-update input");
        std::fs::write(self.circuit_dir().join("Prover.toml"), toml)?;

        let exec = Command::new("nargo")
            .args(["execute", "witness"])
            .current_dir(self.circuit_dir())
            .output()?;
        if !exec.status.success() {
            return Err(BbError::Nargo(
                "execute".into(),
                String::from_utf8_lossy(&exec.stderr).into(),
            ));
        }

        let prove = Command::new("bb")
            .args([
                "prove",
                "-b",
                self.circuit_json().to_str().unwrap(),
                "-w",
                self.workspace_witness().to_str().unwrap(),
                "-k",
                self.artifact_dir().join("vk").to_str().unwrap(),
                "-o",
                self.artifact_dir().to_str().unwrap(),
                "-t",
                "noir-recursive",
            ])
            .output()?;
        if !prove.status.success() {
            return Err(BbError::Bb(
                "prove".into(),
                String::from_utf8_lossy(&prove.stderr).into(),
            ));
        }

        let proof = bytes_to_decimals(
            &std::fs::read(self.artifact_dir().join("proof"))?,
            RECURSIVE_PROOF_LENGTH,
        )?;
        let public_inputs = bytes_to_decimals(
            &std::fs::read(self.artifact_dir().join("public_inputs"))?,
            CHAIN_PROOF_PUB_LEN,
        )?;
        Ok(ChainUpdateArtifact {
            proof,
            public_inputs,
        })
    }

    fn transfer_circuit_json(&self) -> PathBuf {
        self.project_root.join("target").join("transfer.json")
    }

    fn transfer_circuit_dir(&self) -> PathBuf {
        self.project_root.join("circuits").join("transfer")
    }

    fn transfer_artifact_dir(&self) -> PathBuf {
        self.transfer_circuit_dir().join("target")
    }

    /// Compile the transfer circuit and write its EVM-target (keccak) VK — the
    /// same VK `scripts/generate-verifiers.sh` turns into `TransferVerifier.sol`.
    pub fn write_transfer_vk(&self) -> Result<(), BbError> {
        let compile = Command::new("nargo")
            .args(["compile", "--package", "transfer"])
            .current_dir(&self.project_root)
            .output()?;
        if !compile.status.success() {
            return Err(BbError::Nargo(
                "compile".into(),
                String::from_utf8_lossy(&compile.stderr).into(),
            ));
        }

        std::fs::create_dir_all(self.transfer_artifact_dir())?;
        let out = Command::new("bb")
            .args([
                "write_vk",
                "-b",
                self.transfer_circuit_json().to_str().unwrap(),
                "-o",
                self.transfer_artifact_dir().to_str().unwrap(),
                "-t",
                "evm",
            ])
            .output()?;
        if !out.status.success() {
            return Err(BbError::Bb(
                "write_vk".into(),
                String::from_utf8_lossy(&out.stderr).into(),
            ));
        }
        Ok(())
    }

    /// Prove the transfer spend circuit (EVM target). The in-circuit recursive
    /// verify of each input's chain proof runs during `nargo execute`, so a
    /// successful return is itself evidence the chain proofs recursively verified
    /// under an EVM-targeted outer proof. Requires [`Self::write_transfer_vk`] first.
    pub fn prove_transfer(&self, input: &TransferInput) -> Result<EvmProof, BbError> {
        let toml = toml::to_string(input).expect("serialize transfer input");
        std::fs::write(self.transfer_circuit_dir().join("Prover.toml"), toml)?;

        let exec = Command::new("nargo")
            .args(["execute", "witness"])
            .current_dir(self.transfer_circuit_dir())
            .output()?;
        if !exec.status.success() {
            return Err(BbError::Nargo(
                "execute".into(),
                String::from_utf8_lossy(&exec.stderr).into(),
            ));
        }

        let prove = Command::new("bb")
            .args([
                "prove",
                "-b",
                self.transfer_circuit_json().to_str().unwrap(),
                "-w",
                self.workspace_witness().to_str().unwrap(),
                "-k",
                self.transfer_artifact_dir().join("vk").to_str().unwrap(),
                "-o",
                self.transfer_artifact_dir().to_str().unwrap(),
                "-t",
                "evm",
            ])
            .output()?;
        if !prove.status.success() {
            return Err(BbError::Bb(
                "prove".into(),
                String::from_utf8_lossy(&prove.stderr).into(),
            ));
        }

        Ok(EvmProof {
            proof: std::fs::read(self.transfer_artifact_dir().join("proof"))?,
            public_inputs: std::fs::read(self.transfer_artifact_dir().join("public_inputs"))?,
        })
    }

    /// Verify the last transfer proof (EVM target) against its VK via `bb verify`,
    /// reading the `vk` / `proof` / `public_inputs` left in the artifact dir.
    pub fn verify_transfer_evm(&self) -> Result<bool, BbError> {
        let dir = self.transfer_artifact_dir();
        let out = Command::new("bb")
            .args([
                "verify",
                "-k",
                dir.join("vk").to_str().unwrap(),
                "-p",
                dir.join("proof").to_str().unwrap(),
                "-i",
                dir.join("public_inputs").to_str().unwrap(),
                "-t",
                "evm",
            ])
            .output()?;
        Ok(out.status.success())
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{
        Address,
        U256,
    };

    use super::*;
    use crate::{
        adapters::indexed_merkle_tree::IndexedMerkleTree,
        domain::{
            chain_proof::ChainProof,
            epoch::Epoch,
            indexed_merkle::NonMembershipWitness,
            keys::SpendingKey,
            note::Note,
        },
    };

    fn project_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn zeros(n: usize) -> Vec<String> {
        vec!["0".to_string(); n]
    }

    // Field-encode the note's commitment-preimage inputs exactly as
    // `Note::commitment` does, so the circuit's key-binding check matches.
    fn token_field(token: Address) -> String {
        field_to_decimal(B256::left_padding_from(token.as_slice()))
    }

    fn path_bits_of(index: u64) -> Vec<bool> {
        (0..32).map(|i| (index >> i) & 1 == 1).collect()
    }

    fn siblings_of(w: &NonMembershipWitness) -> Vec<String> {
        w.siblings.iter().map(|s| field_to_decimal(*s)).collect()
    }

    /// Genesis → step1 → step2 across two (empty) frozen epochs. Each step
    /// recursively verifies the prior chain-update proof; success across both
    /// steps validates self-recursion + the on-chain-consistent accumulator fold
    /// + IMT non-membership + key binding (and the poseidon2/3/1 cross-impl).
    #[test]
    #[ignore = "shells nargo+bb and proves real circuits (minutes)"]
    fn chain_extends_across_two_frozen_epochs() {
        let prover = BbProver::new(project_root());
        let (vk_fields, vk_hash) = prover.write_chain_update_vk().expect("write_vk");

        // Deterministic note.
        let sk = SpendingKey::from_bytes([7u8; 32]);
        let owner = sk.derive_owner_pubkey();
        let token = Address::repeat_byte(0x11);
        let amount = U256::from(100u64);
        let salt = B256::repeat_byte(0x05);
        let note = Note::with_salt(token, amount, owner, salt, Epoch(0));
        let commitment = note.commitment();

        // Empty frozen tree (the note was never spent, so its phantom nullifiers
        // are absent). Both epochs reuse the empty root for this test.
        let frozen = IndexedMerkleTree::new();
        let frozen_root = frozen.root();

        let note_fields = |i: &mut ChainUpdateInput| {
            i.spending_key = field_to_decimal(sk.0);
            i.token = token_field(token);
            i.amount = field_to_decimal(B256::from(amount));
            i.salt = field_to_decimal(salt);
        };

        // --- Genesis (base case) ---
        let genesis = ChainProof::genesis(commitment, Epoch(0));
        let mut g = ChainUpdateInput {
            commitment: field_to_decimal(commitment.0),
            epoch_created: "0".into(),
            epoch_validated_through: "0".into(),
            accumulator: "0".into(),
            fixed_vk_hash: vk_hash.clone(),
            is_base_case: true,
            prior_vk: zeros(ULTRA_VK_LENGTH_IN_FIELDS),
            prior_proof: zeros(RECURSIVE_PROOF_LENGTH),
            prior_public_inputs: zeros(CHAIN_PROOF_PUB_LEN),
            frozen_root_next: "0".into(),
            spending_key: "0".into(),
            token: "0".into(),
            amount: "0".into(),
            salt: "0".into(),
            low_value: "0".into(),
            low_next_value: "0".into(),
            low_next_index: "0".into(),
            path_bits: vec![false; 32],
            siblings: zeros(32),
        };
        note_fields(&mut g);
        let genesis_art = prover.prove_chain_update(&g).expect("prove genesis");

        // --- Step builder: fold one frozen epoch, recursively verifying `prior`. ---
        let step = |prior_state: ChainProof, prior_art: &ChainUpdateArtifact| {
            let next = prior_state.extend(frozen_root);
            // Phantom nullifier for the just-folded epoch (= prior evt).
            let eta = commitment
                .nullifier(&sk, prior_state.epoch_validated_through)
                .0;
            let w = frozen.non_membership_witness(eta).expect("non-membership");
            let mut i = ChainUpdateInput {
                commitment: field_to_decimal(commitment.0),
                epoch_created: "0".into(),
                epoch_validated_through: field_to_decimal(next.epoch_validated_through.as_field()),
                accumulator: field_to_decimal(next.accumulator),
                fixed_vk_hash: vk_hash.clone(),
                is_base_case: false,
                prior_vk: vk_fields.clone(),
                prior_proof: prior_art.proof.clone(),
                prior_public_inputs: prior_art.public_inputs.clone(),
                frozen_root_next: field_to_decimal(frozen_root),
                spending_key: "0".into(),
                token: "0".into(),
                amount: "0".into(),
                salt: "0".into(),
                low_value: field_to_decimal(w.low_leaf.value),
                low_next_value: field_to_decimal(w.low_leaf.next_value),
                low_next_index: w.low_leaf.next_index.to_string(),
                path_bits: path_bits_of(w.low_leaf_index),
                siblings: siblings_of(&w),
            };
            note_fields(&mut i);
            (next, i)
        };

        // --- Step 1: verify genesis, fold epoch 0 (evt 0 -> 1) ---
        let (state1, in1) = step(genesis, &genesis_art);
        let art1 = prover.prove_chain_update(&in1).expect("prove step1 (verifies genesis)");

        // --- Step 2: verify step1, fold epoch 1 (evt 1 -> 2) ---
        let (state2, in2) = step(state1, &art1);
        let _art2 = prover.prove_chain_update(&in2).expect("prove step2 (verifies step1)");

        assert_eq!(state2.epoch_validated_through, Epoch(2));
    }

    /// The crux de-risk: an EVM-targeted `transfer` proof that *recursively
    /// verifies* a real chain proof. Builds a genesis chain proof for the real
    /// input note, then a 2-in-2-out transfer at epoch 0 (input_0 in a
    /// single-leaf tree so `commitment_root = commitment_in_0` with no siblings;
    /// input_1 a zero/padding note whose recursive verify the circuit skips),
    /// proves it with `-t evm`, and verifies the proof. Success means the
    /// spend-recursion-through-an-EVM-verifier path works end-to-end.
    #[test]
    #[ignore = "shells nargo+bb; proves the recursive transfer circuit end-to-end (minutes)"]
    fn transfer_proof_verifies_with_recursive_chain_proof() {
        let prover = BbProver::new(project_root());

        // --- Inner: chain-update VK + a genesis chain proof for the real input. ---
        let (vk_fields, vk_hash) = prover.write_chain_update_vk().expect("chain vk");

        let sk = SpendingKey::from_bytes([7u8; 32]);
        let owner = sk.derive_owner_pubkey();
        let token = Address::repeat_byte(0x11);
        let salt0 = B256::repeat_byte(0x05);
        let note0 = Note::with_salt(token, U256::from(100u64), owner, salt0, Epoch(0));
        let commitment0 = note0.commitment();

        let genesis = ChainUpdateInput {
            commitment: field_to_decimal(commitment0.0),
            epoch_created: "0".into(),
            epoch_validated_through: "0".into(),
            accumulator: "0".into(),
            fixed_vk_hash: vk_hash.clone(),
            is_base_case: true,
            prior_vk: zeros(ULTRA_VK_LENGTH_IN_FIELDS),
            prior_proof: zeros(RECURSIVE_PROOF_LENGTH),
            prior_public_inputs: zeros(CHAIN_PROOF_PUB_LEN),
            frozen_root_next: "0".into(),
            spending_key: field_to_decimal(sk.0),
            token: token_field(token),
            amount: field_to_decimal(B256::from(U256::from(100u64))),
            salt: field_to_decimal(salt0),
            low_value: "0".into(),
            low_next_value: "0".into(),
            low_next_index: "0".into(),
            path_bits: vec![false; 32],
            siblings: zeros(32),
        };
        let chain0 = prover.prove_chain_update(&genesis).expect("genesis chain proof");

        // --- Outer: a 2-in-2-out transfer at epoch 0, verifying chain0 recursively. ---
        prover.write_transfer_vk().expect("transfer vk");

        let salt1 = B256::repeat_byte(0x09);
        let note1 = Note::with_salt(token, U256::ZERO, owner, salt1, Epoch(0));
        let commitment1 = note1.commitment();
        let out0 = Note::with_salt(token, U256::from(60u64), owner, B256::repeat_byte(0x01), Epoch(0));
        let out1 = Note::with_salt(token, U256::from(40u64), owner, B256::repeat_byte(0x02), Epoch(0));

        let input = TransferInput {
            nullifier_active_0: field_to_decimal(commitment0.nullifier(&sk, Epoch(0)).0),
            nullifier_active_1: field_to_decimal(commitment1.nullifier(&sk, Epoch(0)).0),
            commitment_out_0: field_to_decimal(out0.commitment().0),
            commitment_out_1: field_to_decimal(out1.commitment().0),
            commitment_root: field_to_decimal(commitment0.0),
            current_epoch: "0".into(),
            chain_vk_hash: vk_hash.clone(),
            epoch_created_in_0: "0".into(),
            epoch_created_in_1: "0".into(),
            chain_accumulator_in_0: "0".into(),
            chain_accumulator_in_1: "0".into(),
            spending_key: field_to_decimal(sk.0),
            token_in_0: token_field(token),
            amount_in_0: 100,
            salt_in_0: field_to_decimal(salt0),
            token_in_1: token_field(token),
            amount_in_1: 0,
            salt_in_1: field_to_decimal(salt1),
            token_out_0: token_field(token),
            amount_out_0: 60,
            owner_out_0: field_to_decimal(owner.0),
            salt_out_0: field_to_decimal(B256::repeat_byte(0x01)),
            token_out_1: token_field(token),
            amount_out_1: 40,
            owner_out_1: field_to_decimal(owner.0),
            salt_out_1: field_to_decimal(B256::repeat_byte(0x02)),
            proof_length: 0,
            path_0: zeros(32),
            indices_0: vec![false; 32],
            path_1: zeros(32),
            indices_1: vec![false; 32],
            chain_vk: vk_fields.clone(),
            chain_proof_0: chain0.proof.clone(),
            chain_pub_0: chain0.public_inputs.clone(),
            chain_proof_1: zeros(RECURSIVE_PROOF_LENGTH),
            chain_pub_1: zeros(CHAIN_PROOF_PUB_LEN),
        };

        let proof = prover.prove_transfer(&input).expect("prove transfer (recursive)");
        assert_eq!(proof.public_inputs.len(), TRANSFER_PUB_LEN * 32, "11 public inputs");
        assert!(prover.verify_transfer_evm().expect("verify"), "transfer proof must verify");
    }
}

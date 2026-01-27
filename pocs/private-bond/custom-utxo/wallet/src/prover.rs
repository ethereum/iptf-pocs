use ff::PrimeField;
use poseidon_rs::Fr;
use std::fs;
use std::process::Command;

use crate::merkle::{CircuitMerklePath, TREE_HEIGHT};

/// Represents a single note for circuit input
#[derive(Clone, Debug)]
pub struct CircuitNote {
    pub value: u64,
    pub salt: u64,
    pub owner: Fr, // Public spending key as Fr
    pub asset_id: u64,
    pub maturity_date: u64,
}

impl CircuitNote {
    /// Create a dummy note (value=0) for padding
    pub fn dummy(owner: Fr, asset_id: u64, maturity_date: u64) -> Self {
        CircuitNote {
            value: 0,
            salt: 0,
            owner,
            asset_id,
            maturity_date,
        }
    }
    
    /// Compute the note commitment (matches circuit's note_commit function)
    /// commitment = poseidon::hash_5([value, salt, owner, asset_id, maturity_date])
    pub fn commitment(&self) -> Fr {
        use poseidon_rs::Poseidon;
        let hasher = Poseidon::new();
        hasher.hash(vec![
            Fr::from_str(&self.value.to_string()).unwrap(),
            Fr::from_str(&self.salt.to_string()).unwrap(),
            self.owner.clone(),
            Fr::from_str(&self.asset_id.to_string()).unwrap(),
            Fr::from_str(&self.maturity_date.to_string()).unwrap(),
        ]).unwrap()
    }
}

/// Re-export MerklePath as alias for compatibility
pub type MerklePath = CircuitMerklePath;

/// Witness data for generating a ZK proof
pub struct WitnessBuilder {
    // Public inputs
    pub root: Fr,
    pub nullifiers: [Fr; 2],
    pub commitments_out: [Fr; 2],

    // Input notes
    pub input_notes: [CircuitNote; 2],
    pub merkle_paths: [MerklePath; 2],

    // Output notes
    pub output_notes: [CircuitNote; 2],

    // Private key
    pub private_key: Fr,
}

impl WitnessBuilder {
    /// Create a new witness builder with all required data
    pub fn new(
        root: Fr,
        nullifiers: [Fr; 2],
        commitments_out: [Fr; 2],
        input_notes: [CircuitNote; 2],
        merkle_paths: [MerklePath; 2],
        output_notes: [CircuitNote; 2],
        private_key: Fr,
    ) -> Self {
        WitnessBuilder {
            root,
            nullifiers,
            commitments_out,
            input_notes,
            merkle_paths,
            output_notes,
            private_key,
        }
    }

    /// Convert Fr to hex string format for Prover.toml
    fn fr_to_hex(fr: &Fr) -> String {
        // Fr's repr is [u64; 4] in little-endian limb order
        let repr = fr.into_repr();
        let limbs: &[u64] = repr.as_ref();

        // Convert limbs to bytes (little-endian limbs, little-endian bytes within each limb)
        let mut bytes = [0u8; 32];
        for (i, limb) in limbs.iter().enumerate() {
            let limb_bytes = limb.to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }

        // Convert to big-endian hex string
        let mut hex = String::from("0x");
        for &byte in bytes.iter().rev() {
            hex.push_str(&format!("{:02x}", byte));
        }

        // Remove leading zeros but keep at least one digit
        let trimmed = hex.trim_start_matches("0x").trim_start_matches('0');
        if trimmed.is_empty() {
            "0x0".to_string()
        } else {
            format!("0x{}", trimmed)
        }
    }

    /// Convert Fr to plain string (for private_key which doesn't use hex format)
    fn fr_to_string(fr: &Fr) -> String {
        format!("{}", fr)
    }

    /// Generate Prover.toml content
    pub fn to_prover_toml(&self) -> String {
        let mut toml = String::new();

        // Public inputs
        toml.push_str("# Public inputs (witnesses to be proven on-chain)\n");
        toml.push_str(&format!("root = \"{}\"\n", Self::fr_to_hex(&self.root)));
        toml.push_str(&format!(
            "nullifiers = [\"{}\", \"{}\"]\n",
            Self::fr_to_hex(&self.nullifiers[0]),
            Self::fr_to_hex(&self.nullifiers[1])
        ));
        toml.push_str(&format!(
            "commitments_out = [\"{}\", \"{}\"]\n",
            Self::fr_to_hex(&self.commitments_out[0]),
            Self::fr_to_hex(&self.commitments_out[1])
        ));
        toml.push('\n');

        // Input notes - use hex strings for salts (large u64 values overflow Noir's parser)
        toml.push_str("# Input notes (private)\n");
        toml.push_str(&format!(
            "input_values = [{}, {}]\n",
            self.input_notes[0].value,
            self.input_notes[1].value
        ));
        toml.push_str(&format!(
            "input_salts = [\"0x{:x}\", \"0x{:x}\"]\n",
            self.input_notes[0].salt,
            self.input_notes[1].salt
        ));
        toml.push_str(&format!(
            "input_owner = \"{}\"\n",
            Self::fr_to_hex(&self.input_notes[0].owner)
        ));
        toml.push_str(&format!(
            "input_asset_id = {}\n",
            self.input_notes[0].asset_id
        ));
        toml.push_str(&format!(
            "input_maturity_date = {}\n",
            self.input_notes[0].maturity_date
        ));
        toml.push('\n');

        // Merkle paths
        toml.push_str("# Merkle proof paths for each input note\n");
        toml.push_str(&format!(
            "path_indices = [[{}], [{}]]\n",
            self.merkle_paths[0]
                .indices
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", "),
            self.merkle_paths[1]
                .indices
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        toml.push_str(&format!(
            "path_elements = [[{}], [{}]]\n",
            self.merkle_paths[0]
                .elements
                .iter()
                .map(|e| format!("\"{}\"", Self::fr_to_hex(e)))
                .collect::<Vec<_>>()
                .join(", "),
            self.merkle_paths[1]
                .elements
                .iter()
                .map(|e| format!("\"{}\"", Self::fr_to_hex(e)))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        toml.push('\n');

        // Output notes - use hex strings for salts (large u64 values overflow Noir's parser)
        toml.push_str("# Output notes (private)\n");
        toml.push_str(&format!(
            "output_values = [{}, {}]\n",
            self.output_notes[0].value,
            self.output_notes[1].value
        ));
        toml.push_str(&format!(
            "output_salts = [\"0x{:x}\", \"0x{:x}\"]\n",
            self.output_notes[0].salt,
            self.output_notes[1].salt
        ));
        toml.push_str(&format!(
            "output_owners = [\"{}\", \"{}\"]\n",
            Self::fr_to_hex(&self.output_notes[0].owner),
            Self::fr_to_hex(&self.output_notes[1].owner)
        ));
        toml.push_str(&format!(
            "output_asset_ids = [{}, {}]\n",
            self.output_notes[0].asset_id,
            self.output_notes[1].asset_id
        ));
        toml.push_str(&format!(
            "output_maturity_date = {}\n",
            self.output_notes[0].maturity_date
        ));
        toml.push('\n');

        // Private key - use decimal format like the working example
        toml.push_str("# Private key\n");
        toml.push_str(&format!(
            "private_key = \"{}\"\n",
            Self::fr_to_hex(&self.private_key)
        ));

        toml
    }

    /// Write Prover.toml to the circuit directory
    pub fn write_prover_toml(&self, circuit_dir: &str) -> Result<(), String> {
        let content = self.to_prover_toml();
        let path = format!("{}/Prover.toml", circuit_dir);

        fs::write(&path, content).map_err(|e| format!("Failed to write Prover.toml: {}", e))?;

        println!("   📝 Wrote witness to {}", path);
        Ok(())
    }
}

/// Generate a proof for a bond using nargo and bb
pub async fn generate_proof(circuit_dir: &str, witness_name: &str) -> Result<String, String> {
    println!("   🔄 Generating witness...");

    // Step 1: nargo execute to generate witness
    let output = Command::new("nargo")
        .arg("execute")
        .arg(witness_name)
        .current_dir(circuit_dir)
        .output()
        .map_err(|e| format!("Failed to run nargo: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "nargo execute failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    println!("   ✅ Witness generated");
    println!("   🔄 Generating proof with bb...");

    // Step 2: bb prove to generate actual proof
    let bb_output = Command::new("bb")
        .arg("prove")
        .arg("-b")
        .arg(&format!("./target/{}.json", witness_name))
        .arg("-w")
        .arg(&format!("./target/{}", witness_name))
        .arg("-o")
        .arg("./target")
        .arg("--oracle_hash")
        .arg("keccak")
        .current_dir(circuit_dir)
        .output()
        .map_err(|e| format!("Failed to run bb prove: {}", e))?;

    if !bb_output.status.success() {
        return Err(format!(
            "bb prove failed: {}",
            String::from_utf8_lossy(&bb_output.stderr)
        ));
    }

    println!("   ✅ Proof generated!");

    // Return path to proof
    Ok(format!("{}/target/proof", circuit_dir))
}

/// Helper: Build a witness for a single-input operation (buy, redeem)
/// Uses dummy notes for the second input/output slots
pub fn build_single_note_witness(
    root: Fr,
    input_note: CircuitNote,
    input_merkle_path: MerklePath,
    input_nullifier: Fr,
    output_note: CircuitNote,
    output_commitment: Fr,
    private_key: Fr,
) -> WitnessBuilder {
    // Create dummy for second input (same owner, zero value)
    let dummy_input = CircuitNote::dummy(
        input_note.owner.clone(),
        input_note.asset_id,
        input_note.maturity_date,
    );
    let dummy_path = MerklePath::dummy();

    // Compute dummy nullifier (Poseidon(0, private_key))
    let dummy_nullifier = {
        use poseidon_rs::Poseidon;
        let hasher = Poseidon::new();
        hasher
            .hash(vec![Fr::from_str("0").unwrap(), private_key.clone()])
            .unwrap()
    };

    // Create dummy for second output
    let dummy_output = CircuitNote::dummy(
        output_note.owner.clone(),
        output_note.asset_id,
        output_note.maturity_date,
    );

    // Compute dummy output commitment
    let dummy_commitment = {
        use poseidon_rs::Poseidon;
        let hasher = Poseidon::new();
        hasher
            .hash(vec![
                Fr::from_str("0").unwrap(), // value
                Fr::from_str("0").unwrap(), // salt
                dummy_output.owner.clone(),
                Fr::from_str(&dummy_output.asset_id.to_string()).unwrap(),
                Fr::from_str(&dummy_output.maturity_date.to_string()).unwrap(),
            ])
            .unwrap()
    };

    WitnessBuilder::new(
        root,
        [input_nullifier, dummy_nullifier],
        [output_commitment, dummy_commitment],
        [input_note, dummy_input],
        [input_merkle_path, dummy_path],
        [output_note, dummy_output],
        private_key,
    )
}

/// Helper: Build a witness for a JoinSplit (buy) operation
/// 1 real input with merkle proof, 1 dummy input (value=0) also in tree, 2 real outputs
pub fn build_joinsplit_witness(
    root: Fr,
    input_note: CircuitNote,
    input_merkle_path: MerklePath,
    input_nullifier: Fr,
    dummy_input: CircuitNote,           // Dummy note (value=0, salt=0) - must also be in tree
    dummy_merkle_path: MerklePath,      // Merkle path for the dummy note
    output_notes: [CircuitNote; 2],     // [buyer_note, change_note]
    output_commitments: [Fr; 2],        // [buyer_commitment, change_commitment]
    private_key: Fr,
) -> WitnessBuilder {
    // Compute dummy nullifier (Poseidon(salt=0, private_key))
    let dummy_nullifier = {
        use poseidon_rs::Poseidon;
        let hasher = Poseidon::new();
        let salt_zero = Fr::from_str("0").unwrap();
        hasher.hash(vec![salt_zero, private_key.clone()]).unwrap()
    };

    WitnessBuilder::new(
        root,
        [input_nullifier, dummy_nullifier],
        output_commitments,
        [input_note, dummy_input],
        [input_merkle_path, dummy_merkle_path],
        output_notes,
        private_key,
    )
}

/// Helper: Build a witness for a trade operation (two inputs, two outputs)
pub fn build_trade_witness(
    root: Fr,
    input_notes: [CircuitNote; 2],
    merkle_paths: [MerklePath; 2],
    nullifiers: [Fr; 2],
    output_notes: [CircuitNote; 2],
    output_commitments: [Fr; 2],
    private_key: Fr,
) -> WitnessBuilder {
    WitnessBuilder::new(
        root,
        nullifiers,
        output_commitments,
        input_notes,
        merkle_paths,
        output_notes,
        private_key,
    )
}

/// Helper: Build a witness for a redemption (input notes, zero-value outputs)
pub fn build_redeem_witness(
    root: Fr,
    input_note: CircuitNote,
    input_merkle_path: MerklePath,
    input_nullifier: Fr,
    private_key: Fr,
) -> WitnessBuilder {
    // For redemption, outputs have value=0
    let zero_output = CircuitNote {
        value: 0,
        salt: 0,
        owner: input_note.owner.clone(),
        asset_id: input_note.asset_id,
        maturity_date: input_note.maturity_date,
    };

    // Compute zero output commitment
    let zero_commitment = {
        use poseidon_rs::Poseidon;
        let hasher = Poseidon::new();
        hasher
            .hash(vec![
                Fr::from_str("0").unwrap(), // value
                Fr::from_str("0").unwrap(), // salt
                zero_output.owner.clone(),
                Fr::from_str(&zero_output.asset_id.to_string()).unwrap(),
                Fr::from_str(&zero_output.maturity_date.to_string()).unwrap(),
            ])
            .unwrap()
    };

    // Create dummy for second input
    let dummy_input = CircuitNote::dummy(
        input_note.owner.clone(),
        input_note.asset_id,
        input_note.maturity_date,
    );
    let dummy_path = MerklePath::dummy();

    // Compute dummy nullifier
    let dummy_nullifier = {
        use poseidon_rs::Poseidon;
        let hasher = Poseidon::new();
        hasher
            .hash(vec![Fr::from_str("0").unwrap(), private_key.clone()])
            .unwrap()
    };

    // Second dummy output
    let dummy_output = CircuitNote::dummy(
        input_note.owner.clone(),
        input_note.asset_id,
        input_note.maturity_date,
    );

    let dummy_commitment = {
        use poseidon_rs::Poseidon;
        let hasher = Poseidon::new();
        hasher
            .hash(vec![
                Fr::from_str("0").unwrap(),
                Fr::from_str("0").unwrap(),
                dummy_output.owner.clone(),
                Fr::from_str(&dummy_output.asset_id.to_string()).unwrap(),
                Fr::from_str(&dummy_output.maturity_date.to_string()).unwrap(),
            ])
            .unwrap()
    };

    WitnessBuilder::new(
        root,
        [input_nullifier, dummy_nullifier],
        [zero_commitment.clone(), dummy_commitment],
        [input_note, dummy_input],
        [input_merkle_path, dummy_path],
        [zero_output, dummy_output],
        private_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_to_hex() {
        let fr = Fr::from_str("999").unwrap();
        let hex = WitnessBuilder::fr_to_hex(&fr);
        // Should produce a valid hex string
        assert!(hex.starts_with("0x"));
    }

    #[test]
    fn test_witness_builder_toml() {
        let owner = Fr::from_str("12345").unwrap();
        let root = Fr::from_str("999").unwrap();
        let nullifier = Fr::from_str("111").unwrap();
        let commitment = Fr::from_str("222").unwrap();

        let input_note = CircuitNote {
            value: 100,
            salt: 123,
            owner: owner.clone(),
            asset_id: 1,
            maturity_date: 1893456000,
        };

        let output_note = CircuitNote {
            value: 100,
            salt: 456,
            owner: owner.clone(),
            asset_id: 1,
            maturity_date: 1893456000,
        };

        let path = MerklePath::dummy();
        let private_key = Fr::from_str("999").unwrap();

        let witness = build_single_note_witness(
            root,
            input_note,
            path,
            nullifier,
            output_note,
            commitment,
            private_key,
        );

        let toml = witness.to_prover_toml();

        // Check that TOML contains expected fields
        assert!(toml.contains("root = "));
        assert!(toml.contains("nullifiers = "));
        assert!(toml.contains("input_values = "));
        assert!(toml.contains("output_values = "));
        assert!(toml.contains("private_key = "));

        println!("Generated TOML:\n{}", toml);
    }
}

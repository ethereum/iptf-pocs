use std::{
    path::PathBuf,
    process::Command,
};

use ark_bn254::{
    Fr,
    G1Affine,
};
use ark_ff::{
    BigInteger,
    PrimeField,
};
use serde::Serialize;

use crate::{
    error::ProofError,
    ports::proof::{
        LinkProofVerifier,
        ProofBackend,
    },
    poseidon::{
        hash_attr,
        hash_enrollment_nullifier,
        hash_leaf,
        hash_nullifier,
    },
    types::{
        DleqProof,
        MerklePath,
        Predicate,
        SvdwWitnesses,
    },
};

/// Convert a BN254 base field element (Fq) to a scalar field element (Fr)
/// by going through the big integer representation.
fn fq_to_fr(fq: ark_bn254::Fq) -> Fr {
    let bytes = fq.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

const MERKLE_DEPTH: usize = 20;

/// Format an Fr element as a decimal string for Noir's Prover.toml.
fn fr_to_decimal(f: Fr) -> String {
    f.into_bigint().to_string()
}

/// Format a base field coordinate (Fq) embedded in an Fr context.
/// Since G1Affine coordinates are Fq and Noir reads them as Field (Fr),
/// we serialize the raw coordinate bytes as a decimal.
fn fq_to_decimal(point: &G1Affine, coord: Coord) -> String {
    use ark_bn254::Fq;
    use ark_ff::PrimeField as _;
    let fq: Fq = match coord {
        Coord::X => point.x,
        Coord::Y => point.y,
    };
    fq.into_bigint().to_string()
}

enum Coord {
    X,
    Y,
}

/// Format a standalone Fq element as a decimal string for Noir's Prover.toml.
fn fq_raw_to_decimal(fq: ark_bn254::Fq) -> String {
    fq.into_bigint().to_string()
}

// Prover input structs -- field names MUST match Noir circuit parameters

#[derive(Serialize)]
struct MembershipProverInput {
    root: String,
    nullifier: String,
    external_nullifier: String,
    version: String,
    predicate_type: String,
    predicate_attr_index: String,
    predicate_value: String,
    predicate_result: String,
    identity_secret: String,
    attr0: String,
    attr1: String,
    attr2: String,
    attr3: String,
    proof_length: String,
    leaf_index_bits: Vec<String>,
    merkle_path: Vec<String>,
}

#[derive(Serialize)]
struct EnrollmentProverInput {
    leaf: String,
    enrollment_nullifier: String,
    mpc_public_key_x: String,
    mpc_public_key_y: String,
    g_id_x: String,
    g_id_y: String,
    identity_secret: String,
    version: String,
    attr0: String,
    attr1: String,
    attr2: String,
    attr3: String,
    raw_nullifier_x: String,
    raw_nullifier_y: String,
    chaum_pedersen_c: String,
    chaum_pedersen_z: String,
}

#[derive(Serialize)]
struct LinkProofProverInput {
    identity_commitment: String,
    blinded_request_x: String,
    blinded_request_y: String,
    g_id_x: String,
    g_id_y: String,
    user_id_hash: String,
    salt: String,
    r: String,
    svdw_index: String,
    svdw_w: String,
    svdw_inv_w2: String,
    non_qr_witness_0: String,
    non_qr_witness_1: String,
}

// BBProver

/// BBProver generates ZK proofs by shelling out to `nargo` and `bb` (Barretenberg CLI).
///
/// Flow for each circuit:
/// 1. Serialize witness values to Prover.toml in the circuit directory
/// 2. Run `nargo execute witness` to compile witness
/// 3. Run `bb prove` to generate the proof from the compiled circuit JSON + witness
/// 4. Read proof bytes from the output file
pub struct BBProver {
    project_root: PathBuf,
}

impl BBProver {
    pub fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }

    /// Execute a circuit: write Prover.toml, run nargo, run bb, read proof.
    fn prove_circuit(
        &self,
        circuit_name: &str,
        prover_toml_content: &str,
    ) -> Result<Vec<u8>, ProofError> {
        let circuit_dir = self.project_root.join("circuits").join(circuit_name);

        if !circuit_dir.exists() {
            return Err(ProofError::Generation(format!(
                "Circuit directory not found: {}",
                circuit_dir.display()
            )));
        }

        // 1. Write Prover.toml
        let prover_toml_path = circuit_dir.join("Prover.toml");
        std::fs::write(&prover_toml_path, prover_toml_content).map_err(|e| {
            ProofError::Generation(format!("Failed to write Prover.toml: {e}"))
        })?;

        // 2. Run nargo execute witness
        let nargo_output = Command::new("nargo")
            .args(["execute", "witness"])
            .current_dir(&circuit_dir)
            .output()
            .map_err(|e| ProofError::Generation(format!("Failed to run nargo: {e}")))?;

        if !nargo_output.status.success() {
            let stderr = String::from_utf8_lossy(&nargo_output.stderr);
            return Err(ProofError::Generation(format!(
                "nargo execute failed: {stderr}"
            )));
        }

        // 3. Run bb prove
        //    Circuit JSON: <project_root>/target/<package_name>.json
        //    Witness: <project_root>/target/witness.gz (nargo puts it at workspace root)
        let package_name = match circuit_name {
            "membership" => "rpi_membership",
            "enrollment" => "rpi_enrollment",
            "link_proof" => "rpi_link_proof",
            _ => {
                return Err(ProofError::Generation(format!(
                    "Unknown circuit: {circuit_name}"
                )));
            }
        };

        let circuit_json = self
            .project_root
            .join("target")
            .join(format!("{package_name}.json"));
        let witness_path = self.project_root.join("target").join("witness.gz");
        let output_dir = self.project_root.join("target");

        // 3a. Generate VK (required by bb prove -t evm)
        let vk_output = Command::new("bb")
            .args([
                "write_vk",
                "-b",
                circuit_json.to_str().unwrap(),
                "-t",
                "evm",
                "-o",
                output_dir.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| {
                ProofError::Generation(format!("Failed to run bb write_vk: {e}"))
            })?;

        if !vk_output.status.success() {
            let stderr = String::from_utf8_lossy(&vk_output.stderr);
            return Err(ProofError::Generation(format!(
                "bb write_vk failed: {stderr}"
            )));
        }

        // 3b. Generate proof
        let bb_output = Command::new("bb")
            .args([
                "prove",
                "-b",
                circuit_json.to_str().unwrap(),
                "-w",
                witness_path.to_str().unwrap(),
                "-t",
                "evm",
                "-o",
                output_dir.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| ProofError::Generation(format!("Failed to run bb: {e}")))?;

        if !bb_output.status.success() {
            let stderr = String::from_utf8_lossy(&bb_output.stderr);
            return Err(ProofError::Generation(format!("bb prove failed: {stderr}")));
        }

        // 4. Read proof bytes
        let proof_path = output_dir.join("proof");
        let proof = std::fs::read(&proof_path).map_err(|e| {
            ProofError::Generation(format!(
                "Failed to read proof at {}: {e}",
                proof_path.display()
            ))
        })?;

        Ok(proof)
    }
}

impl LinkProofVerifier for BBProver {
    fn verify_link_proof(
        &self,
        proof: &[u8],
        _identity_commitment: Fr,
        _blinded_request: G1Affine,
        _g_id: G1Affine,
    ) -> Result<bool, ProofError> {
        let output_dir = self.project_root.join("target");
        let proof_path = output_dir.join("proof");
        let vk_path = output_dir.join("vk");

        // Write proof bytes to file for bb verify
        std::fs::write(&proof_path, proof).map_err(|e| {
            ProofError::Verification(format!("Failed to write proof: {e}"))
        })?;

        // VK must already exist from a prior prove_circuit("link_proof", ...) call.
        if !vk_path.exists() {
            return Err(ProofError::Verification(
                "VK not found — link proof must be generated before verification".into(),
            ));
        }

        let bb_output = Command::new("bb")
            .args([
                "verify",
                "-p",
                proof_path.to_str().unwrap(),
                "-t",
                "evm",
                "-k",
                vk_path.to_str().unwrap(),
            ])
            .output()
            .map_err(|e| {
                ProofError::Verification(format!("Failed to run bb verify: {e}"))
            })?;

        Ok(bb_output.status.success())
    }
}

impl ProofBackend for BBProver {
    fn generate_membership_proof(
        &self,
        identity_secret: Fr,
        attrs: &[Fr; 4],
        version: u32,
        merkle_path: &MerklePath,
        root: Fr,
        external_nullifier: Fr,
        predicate: &Predicate,
    ) -> Result<Vec<u8>, ProofError> {
        // Compute derived values
        let version_fr = Fr::from(version as u64);
        let attr_hash = hash_attr(version_fr, attrs);
        let _leaf = hash_leaf(identity_secret, attr_hash);
        let nullifier = hash_nullifier(identity_secret, external_nullifier);

        // Compute predicate result
        let selected = if predicate.attr_index == 0 {
            attrs[0]
        } else {
            attrs[1]
        };
        let predicate_result = match predicate.predicate_type {
            0 => {
                // equality
                if selected == predicate.value {
                    Fr::from(1u64)
                } else {
                    Fr::from(0u64)
                }
            }
            1 => {
                // boolean
                if selected == Fr::from(1u64) {
                    Fr::from(1u64)
                } else {
                    Fr::from(0u64)
                }
            }
            _ => {
                return Err(ProofError::Generation(
                    "Unsupported predicate type".to_string(),
                ));
            }
        };

        // Actual proof depth from LeanIMT (may be < MERKLE_DEPTH)
        let proof_length = merkle_path.siblings.len();

        // Pad merkle path to MERKLE_DEPTH
        let mut padded_siblings = merkle_path.siblings.clone();
        padded_siblings.resize(MERKLE_DEPTH, Fr::from(0u64));

        let mut padded_indices = merkle_path.indices.clone();
        padded_indices.resize(MERKLE_DEPTH, 0u8);

        // leaf_index_bits: the Noir circuit expects [u1; 20] as string "0" or "1"
        let leaf_index_bits: Vec<String> =
            padded_indices.iter().map(|&b| b.to_string()).collect();

        let merkle_path_strs: Vec<String> =
            padded_siblings.iter().map(|s| fr_to_decimal(*s)).collect();

        let input = MembershipProverInput {
            root: fr_to_decimal(root),
            nullifier: fr_to_decimal(nullifier),
            external_nullifier: fr_to_decimal(external_nullifier),
            version: fr_to_decimal(version_fr),
            predicate_type: fr_to_decimal(Fr::from(predicate.predicate_type as u64)),
            predicate_attr_index: fr_to_decimal(Fr::from(predicate.attr_index as u64)),
            predicate_value: fr_to_decimal(predicate.value),
            predicate_result: fr_to_decimal(predicate_result),
            identity_secret: fr_to_decimal(identity_secret),
            attr0: fr_to_decimal(attrs[0]),
            attr1: fr_to_decimal(attrs[1]),
            attr2: fr_to_decimal(attrs[2]),
            attr3: fr_to_decimal(attrs[3]),
            proof_length: proof_length.to_string(),
            leaf_index_bits,
            merkle_path: merkle_path_strs,
        };

        let toml_content = toml::to_string(&input).map_err(|e| {
            ProofError::Generation(format!("Failed to serialize membership input: {e}"))
        })?;

        self.prove_circuit("membership", &toml_content)
    }

    fn generate_enrollment_proof(
        &self,
        identity_secret: Fr,
        attrs: &[Fr; 4],
        version: u32,
        g_id: G1Affine,
        raw_nullifier: G1Affine,
        mpc_public_key: G1Affine,
        dleq_proof: &DleqProof,
    ) -> Result<Vec<u8>, ProofError> {
        let version_fr = Fr::from(version as u64);
        let attr_hash = hash_attr(version_fr, attrs);
        let leaf = hash_leaf(identity_secret, attr_hash);
        let enrollment_nullifier = hash_enrollment_nullifier(
            fq_to_fr(raw_nullifier.x),
            fq_to_fr(raw_nullifier.y),
        );

        let input = EnrollmentProverInput {
            leaf: fr_to_decimal(leaf),
            enrollment_nullifier: fr_to_decimal(enrollment_nullifier),
            mpc_public_key_x: fq_to_decimal(&mpc_public_key, Coord::X),
            mpc_public_key_y: fq_to_decimal(&mpc_public_key, Coord::Y),
            g_id_x: fq_to_decimal(&g_id, Coord::X),
            g_id_y: fq_to_decimal(&g_id, Coord::Y),
            identity_secret: fr_to_decimal(identity_secret),
            version: fr_to_decimal(version_fr),
            attr0: fr_to_decimal(attrs[0]),
            attr1: fr_to_decimal(attrs[1]),
            attr2: fr_to_decimal(attrs[2]),
            attr3: fr_to_decimal(attrs[3]),
            raw_nullifier_x: fq_to_decimal(&raw_nullifier, Coord::X),
            raw_nullifier_y: fq_to_decimal(&raw_nullifier, Coord::Y),
            chaum_pedersen_c: fr_to_decimal(dleq_proof.c),
            chaum_pedersen_z: fr_to_decimal(dleq_proof.z),
        };

        let toml_content = toml::to_string(&input).map_err(|e| {
            ProofError::Generation(format!("Failed to serialize enrollment input: {e}"))
        })?;

        self.prove_circuit("enrollment", &toml_content)
    }

    fn generate_link_proof(
        &self,
        user_id_hash: Fr,
        salt: Fr,
        r: Fr,
        g_id: G1Affine,
        identity_commitment: Fr,
        blinded_request: G1Affine,
        svdw: &SvdwWitnesses,
    ) -> Result<Vec<u8>, ProofError> {
        let input = LinkProofProverInput {
            identity_commitment: fr_to_decimal(identity_commitment),
            blinded_request_x: fq_to_decimal(&blinded_request, Coord::X),
            blinded_request_y: fq_to_decimal(&blinded_request, Coord::Y),
            g_id_x: fq_to_decimal(&g_id, Coord::X),
            g_id_y: fq_to_decimal(&g_id, Coord::Y),
            user_id_hash: fr_to_decimal(user_id_hash),
            salt: fr_to_decimal(salt),
            r: fr_to_decimal(r),
            svdw_index: svdw.index.to_string(),
            svdw_w: fq_raw_to_decimal(svdw.w),
            svdw_inv_w2: fq_raw_to_decimal(svdw.inv_w2),
            non_qr_witness_0: fq_raw_to_decimal(svdw.non_qr_witnesses[0]),
            non_qr_witness_1: fq_raw_to_decimal(svdw.non_qr_witnesses[1]),
        };

        let toml_content = toml::to_string(&input).map_err(|e| {
            ProofError::Generation(format!("Failed to serialize link_proof input: {e}"))
        })?;

        self.prove_circuit("link_proof", &toml_content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_to_decimal() {
        assert_eq!(fr_to_decimal(Fr::from(0u64)), "0");
        assert_eq!(fr_to_decimal(Fr::from(42u64)), "42");
        assert_eq!(fr_to_decimal(Fr::from(1000000u64)), "1000000");
    }

    #[test]
    fn test_link_proof_toml_serialization() {
        let input = LinkProofProverInput {
            identity_commitment: "123".to_string(),
            blinded_request_x: "456".to_string(),
            blinded_request_y: "789".to_string(),
            g_id_x: "111".to_string(),
            g_id_y: "222".to_string(),
            user_id_hash: "333".to_string(),
            salt: "444".to_string(),
            r: "555".to_string(),
            svdw_index: "0".to_string(),
            svdw_w: "666".to_string(),
            svdw_inv_w2: "777".to_string(),
            non_qr_witness_0: "0".to_string(),
            non_qr_witness_1: "0".to_string(),
        };

        let toml_str = toml::to_string(&input).unwrap();
        assert!(toml_str.contains("identity_commitment"));
        assert!(toml_str.contains("blinded_request_x"));
        assert!(toml_str.contains("g_id_x"));
        assert!(toml_str.contains("user_id_hash"));
        assert!(toml_str.contains("salt"));
        assert!(toml_str.contains("r = "));
    }

    #[test]
    fn test_membership_toml_serialization() {
        let input = MembershipProverInput {
            root: "1".to_string(),
            nullifier: "2".to_string(),
            external_nullifier: "3".to_string(),
            version: "1".to_string(),
            predicate_type: "0".to_string(),
            predicate_attr_index: "0".to_string(),
            predicate_value: "42".to_string(),
            predicate_result: "1".to_string(),
            identity_secret: "99".to_string(),
            attr0: "42".to_string(),
            attr1: "1".to_string(),
            attr2: "100".to_string(),
            attr3: "200".to_string(),
            proof_length: "20".to_string(),
            leaf_index_bits: vec!["0".to_string(); 20],
            merkle_path: vec!["0".to_string(); 20],
        };

        let toml_str = toml::to_string(&input).unwrap();
        assert!(toml_str.contains("root"));
        assert!(toml_str.contains("nullifier"));
        assert!(toml_str.contains("identity_secret"));
        assert!(toml_str.contains("leaf_index_bits"));
        assert!(toml_str.contains("merkle_path"));
    }

    #[test]
    fn test_enrollment_toml_serialization() {
        let input = EnrollmentProverInput {
            leaf: "1".to_string(),
            enrollment_nullifier: "2".to_string(),
            mpc_public_key_x: "3".to_string(),
            mpc_public_key_y: "4".to_string(),
            g_id_x: "5".to_string(),
            g_id_y: "6".to_string(),
            identity_secret: "7".to_string(),
            version: "1".to_string(),
            attr0: "10".to_string(),
            attr1: "20".to_string(),
            attr2: "30".to_string(),
            attr3: "40".to_string(),
            raw_nullifier_x: "50".to_string(),
            raw_nullifier_y: "60".to_string(),
            chaum_pedersen_c: "70".to_string(),
            chaum_pedersen_z: "80".to_string(),
        };

        let toml_str = toml::to_string(&input).unwrap();
        assert!(toml_str.contains("leaf"));
        assert!(toml_str.contains("enrollment_nullifier"));
        assert!(toml_str.contains("mpc_public_key_x"));
        assert!(toml_str.contains("chaum_pedersen_c"));
        assert!(toml_str.contains("chaum_pedersen_z"));
    }
}

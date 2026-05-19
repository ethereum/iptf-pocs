//! `BBProver`: shells `nargo` + `bb` for signer (recursive), batch, and resolution proofs.

use std::{
    path::PathBuf,
    process::Command,
};

use ark_bn254::Fr;
use ark_ff::PrimeField;
use serde::Serialize;

use crate::{
    error::ProofError,
    ports::proof::{
        BatchPositionWitness,
        ProofBackend,
    },
    poseidon::fr_from_be_bytes,
    types::{
        BatchPublicInputs,
        ResolutionPrivateInputs,
        ResolutionPublicInputs,
        SignerPrivateInputs,
        SignerPublicInputs,
    },
};

use crate::{
    BATCH_SIZE_MAX as BATCH_SIZE,
    RESOLUTION_CLASS_MAX as CLASS_MAX,
};

const RECURSIVE_PROOF_LENGTH: usize = 458;
const ULTRA_VK_LENGTH_IN_FIELDS: usize = 115;
const N_SIGNER_PUB: usize = 8;
const LEAF_MAX: usize = 200;
const IMT_PATH_LEN: usize = 24;

fn fr_to_decimal(f: Fr) -> String {
    f.into_bigint().to_string()
}

fn bytes_to_fr_fields(bytes: &[u8]) -> Result<Vec<String>, ProofError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(ProofError::WitnessSerialization(format!(
            "input must be a multiple of 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes
        .chunks_exact(32)
        .map(|chunk| fr_to_decimal(fr_from_be_bytes(chunk)))
        .collect())
}

/// RAII guard that wipes Prover.toml and witness.gz on drop. Ensures private
/// witness material does not persist on the filesystem after a proof attempt
/// completes (success or failure). Does NOT cover SIGKILL / process abort;
/// production signers should hold witness materials in tmpfs / mlock-pinned memory.
struct WitnessCleanup {
    prover_toml: std::path::PathBuf,
    witness_gz: std::path::PathBuf,
}

impl Drop for WitnessCleanup {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_file(&self.prover_toml)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.prover_toml.display(),
                error = %e,
                "WitnessCleanup: failed to remove Prover.toml; private witness material may persist"
            );
        }
        if let Err(e) = std::fs::remove_file(&self.witness_gz)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.witness_gz.display(),
                error = %e,
                "WitnessCleanup: failed to remove witness.gz"
            );
        }
    }
}

#[derive(Serialize)]
struct SignerProverInput {
    r_root: String,
    petition_id: String,
    predicate_hash: String,
    class_index: String,
    class_tag: String,
    slot: String,
    nullifier: String,
    identity_tag: String,
    identity_secret: String,
    attrs: Vec<String>,
    attr_version: String,
    chain_root: String,
    ri_path_indices: Vec<bool>,
    ri_path_elements: Vec<String>,
    ri_proof_length: String,
    s_slot: String,
    chain_path_indices: Vec<bool>,
    chain_path_elements: Vec<String>,
    salt: String,
    op_codes: Vec<String>,
    op_operands: Vec<String>,
    op_count: String,
    tuple_claim_index: Vec<String>,
    tuple_operand: Vec<String>,
    tuple_type_tag: Vec<String>,
    tuple_comparator: Vec<String>,
    tuple_count: String,
}

#[derive(Serialize)]
struct BatchProverInput {
    petition_id: String,
    r_root: String,
    predicate_hash: String,
    class_index: String,
    slot: String,
    prior_running_root: String,
    new_running_root: String,
    prior_identity_tag_set_root: String,
    new_identity_tag_set_root: String,
    prior_leaf_count: String,
    new_leaf_count: String,
    batch_versioned_hash: String,
    bls_fields: Vec<String>,
    signer_vk: Vec<String>,
    signer_vk_hash: String,
    signer_proofs: Vec<Vec<String>>,
    signer_public_inputs: Vec<Vec<String>>,
    running_imt_low_leaf_indices: Vec<String>,
    running_imt_low_indices: Vec<Vec<bool>>,
    running_imt_low_elements: Vec<Vec<String>>,
    running_imt_low_values: Vec<String>,
    running_imt_low_next_indices: Vec<String>,
    running_imt_low_next_values: Vec<String>,
    running_imt_new_indices: Vec<Vec<bool>>,
    running_imt_new_elements: Vec<Vec<String>>,
    running_imt_new_low_next_indices: Vec<String>,
    running_imt_intermediate_roots: Vec<String>,
    idtag_imt_low_leaf_indices: Vec<String>,
    idtag_imt_low_indices: Vec<Vec<bool>>,
    idtag_imt_low_elements: Vec<Vec<String>>,
    idtag_imt_low_values: Vec<String>,
    idtag_imt_low_next_indices: Vec<String>,
    idtag_imt_low_next_values: Vec<String>,
    idtag_imt_new_indices: Vec<Vec<bool>>,
    idtag_imt_new_elements: Vec<Vec<String>>,
    idtag_imt_new_low_next_indices: Vec<String>,
    idtag_imt_intermediate_roots: Vec<String>,
}

#[derive(Serialize)]
struct ResolutionProverInput {
    predicate_hash: String,
    r_root: String,
    running_root: String,
    leaf_count: String,
    class_set: Vec<String>,
    class_set_len: String,
    class_thresholds: Vec<String>,
    b: String,
    b_per_class: Vec<String>,
    class_index: String,
    nullifier: Vec<String>,
    class_tag: Vec<String>,
    imt_next_index: Vec<String>,
    imt_next_value: Vec<String>,
    imt_path_indices: Vec<Vec<bool>>,
    imt_path_elements: Vec<Vec<String>>,
}

pub struct BBProver {
    project_root: PathBuf,
}

impl BBProver {
    pub fn new(project_root: PathBuf) -> Self {
        Self { project_root }
    }

    fn circuit_dir(&self, circuit_name: &str) -> PathBuf {
        self.project_root.join("circuits").join(circuit_name)
    }

    fn circuit_json(&self, package_name: &str) -> PathBuf {
        self.project_root
            .join("circuits")
            .join("target")
            .join(format!("{package_name}.json"))
    }

    fn shell_out(
        &self,
        circuit_name: &str,
        prover_toml_content: &str,
        verifier_target: &str,
    ) -> Result<Vec<u8>, ProofError> {
        let dir = self.circuit_dir(circuit_name);
        let prover_toml = dir.join("Prover.toml");
        std::fs::write(&prover_toml, prover_toml_content)
            .map_err(|e| ProofError::Generation(format!("write Prover.toml: {e}")))?;

        // RAII cleanup of witness materials: even on panic / proof
        // failure / process unwinding, `Drop` runs and removes
        // `Prover.toml` (containing s_slot + attr_vector + RI/chain
        // paths) and the bb witness file. The
        // guard does not survive SIGKILL or process abort; a
        // production-grade signer should additionally hold these
        // materials in tmpfs or mlock-pinned memory.
        let pkg = format!("rcp_{circuit_name}");
        let bytecode = self.circuit_json(&pkg);
        let workspace_target = self.project_root.join("circuits").join("target");
        let witness = workspace_target.join("witness.gz");
        let target_dir = dir.join("target");
        std::fs::create_dir_all(&target_dir)
            .map_err(|e| ProofError::Generation(format!("mkdir target: {e}")))?;

        let _cleanup = WitnessCleanup {
            prover_toml: prover_toml.clone(),
            witness_gz: witness.clone(),
        };

        let exec = Command::new("nargo")
            .args(["execute", "witness"])
            .current_dir(&dir)
            .output()
            .map_err(|e| ProofError::Generation(format!("spawn nargo: {e}")))?;
        if !exec.status.success() {
            return Err(ProofError::Generation(format!(
                "nargo execute ({circuit_name}) failed: {}",
                String::from_utf8_lossy(&exec.stderr)
            )));
        }

        let prove = Command::new("bb")
            .args([
                "prove",
                "-b",
                bytecode.to_str().unwrap(),
                "-w",
                witness.to_str().unwrap(),
                "-k",
                target_dir.join("vk").to_str().unwrap(),
                "-o",
                target_dir.to_str().unwrap(),
                "-t",
                verifier_target,
            ])
            .output()
            .map_err(|e| ProofError::Generation(format!("spawn bb prove: {e}")))?;
        if !prove.status.success() {
            return Err(ProofError::Generation(format!(
                "bb prove ({circuit_name}) failed: {}",
                String::from_utf8_lossy(&prove.stderr)
            )));
        }

        std::fs::read(target_dir.join("proof"))
            .map_err(|e| ProofError::Generation(format!("read proof: {e}")))
    }

    /// Read `circuits/signer/target/{vk, vk_hash}`; returns `(vk_fields, vk_hash_decimal)`.
    fn read_signer_vk(&self) -> Result<(Vec<String>, String), ProofError> {
        let vk_path = self.circuit_dir("signer").join("target").join("vk");
        let vk_hash_path = self.circuit_dir("signer").join("target").join("vk_hash");
        let vk_bytes = std::fs::read(&vk_path)
            .map_err(|e| ProofError::Generation(format!("read signer vk: {e}")))?;
        if vk_bytes.len() != ULTRA_VK_LENGTH_IN_FIELDS * 32 {
            return Err(ProofError::Generation(format!(
                "signer vk has {} bytes; expected {}",
                vk_bytes.len(),
                ULTRA_VK_LENGTH_IN_FIELDS * 32
            )));
        }
        let vk_fields = bytes_to_fr_fields(&vk_bytes)?;
        let vk_hash_bytes = std::fs::read(&vk_hash_path)
            .map_err(|e| ProofError::Generation(format!("read signer vk_hash: {e}")))?;
        if vk_hash_bytes.len() != 32 {
            return Err(ProofError::Generation(format!(
                "signer vk_hash has {} bytes; expected 32",
                vk_hash_bytes.len()
            )));
        }
        let vk_hash_decimal = fr_to_decimal(fr_from_be_bytes(&vk_hash_bytes));
        Ok((vk_fields, vk_hash_decimal))
    }

    /// Ensure signer VK + vk_hash exist (one-time `bb write_vk -t noir-recursive`).
    pub fn ensure_signer_vk(&self) -> Result<(), ProofError> {
        let dir = self.circuit_dir("signer");
        std::fs::create_dir_all(dir.join("target"))
            .map_err(|e| ProofError::Generation(format!("mkdir signer target: {e}")))?;
        let out = Command::new("bb")
            .args([
                "write_vk",
                "-b",
                self.circuit_json("rcp_signer").to_str().unwrap(),
                "-o",
                dir.join("target").to_str().unwrap(),
                "-t",
                "noir-recursive",
            ])
            .output()
            .map_err(|e| ProofError::Generation(format!("spawn bb write_vk: {e}")))?;
        if !out.status.success() {
            return Err(ProofError::Generation(format!(
                "bb write_vk (signer) failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        Ok(())
    }
}

fn pad_bool_to(arr: &[u8], n: usize) -> Result<Vec<bool>, ProofError> {
    if arr.len() > n {
        return Err(ProofError::WitnessSerialization(format!(
            "pad_bool_to: input length {} exceeds cap {n}",
            arr.len()
        )));
    }
    let mut out: Vec<bool> = arr.iter().map(|b| *b != 0).collect();
    out.resize(n, false);
    Ok(out)
}

fn pad_fr_to(arr: &[Fr], n: usize) -> Result<Vec<String>, ProofError> {
    if arr.len() > n {
        return Err(ProofError::WitnessSerialization(format!(
            "pad_fr_to: input length {} exceeds cap {n}",
            arr.len()
        )));
    }
    let mut out: Vec<String> = arr.iter().map(|f| fr_to_decimal(*f)).collect();
    out.resize(n, "0".to_string());
    Ok(out)
}

fn fr_array_to_decimals(arr: &[Fr]) -> Vec<String> {
    arr.iter().map(|f| fr_to_decimal(*f)).collect()
}

fn imt_path_indices_bool(
    p: &crate::ports::imt::ImtPath,
) -> Result<Vec<bool>, ProofError> {
    pad_bool_to(&p.indices, IMT_PATH_LEN)
}

fn imt_path_elements(p: &crate::ports::imt::ImtPath) -> Result<Vec<String>, ProofError> {
    if p.siblings.len() > IMT_PATH_LEN {
        return Err(ProofError::WitnessSerialization(format!(
            "imt_path_elements: {} siblings exceeds depth {IMT_PATH_LEN}",
            p.siblings.len()
        )));
    }
    let mut out: Vec<String> = p
        .siblings
        .iter()
        .map(|s| fr_to_decimal(fr_from_be_bytes(s)))
        .collect();
    out.resize(IMT_PATH_LEN, "0".to_string());
    Ok(out)
}

fn signer_to_input(
    public: &SignerPublicInputs,
    private: &SignerPrivateInputs,
) -> Result<SignerProverInput, ProofError> {
    let pdef = &private.predicate_def;
    if pdef.ops.len() > 20 || pdef.tuples.len() > 20 {
        return Err(ProofError::WitnessSerialization(format!(
            "predicate ops {} or tuples {} exceeds 20",
            pdef.ops.len(),
            pdef.tuples.len()
        )));
    }
    let mut op_codes: Vec<String> = pdef
        .ops
        .iter()
        .map(|o| (o.code as u8).to_string())
        .collect();
    let mut op_operands: Vec<String> =
        pdef.ops.iter().map(|o| o.operand.to_string()).collect();
    while op_codes.len() < 20 {
        op_codes.push("255".to_string()); // NOP
        op_operands.push("0".to_string());
    }
    let mut tuple_claim_index: Vec<String> = pdef
        .tuples
        .iter()
        .map(|t| t.claim_index.to_string())
        .collect();
    let mut tuple_operand: Vec<String> = pdef
        .tuples
        .iter()
        .map(|t| fr_to_decimal(fr_from_be_bytes(&t.operand)))
        .collect();
    let mut tuple_type_tag: Vec<String> = pdef
        .tuples
        .iter()
        .map(|t| (t.type_tag as u8).to_string())
        .collect();
    let mut tuple_comparator: Vec<String> = pdef
        .tuples
        .iter()
        .map(|t| (t.comparator as u8).to_string())
        .collect();
    while tuple_claim_index.len() < 20 {
        tuple_claim_index.push("0".to_string());
        tuple_operand.push("0".to_string());
        tuple_type_tag.push("1".to_string()); // INT64 sentinel
        tuple_comparator.push("16".to_string()); // == sentinel
    }

    let attrs: Vec<String> = private
        .attr_vector
        .iter()
        .take(4)
        .map(|a| fr_to_decimal(*a))
        .collect::<Vec<_>>();
    let mut attrs = attrs;
    while attrs.len() < 4 {
        attrs.push("0".to_string());
    }

    let ri_proof_length = private.ri_path_siblings.len() as u32;
    let ri_path_indices = pad_bool_to(&private.ri_path_indices, 32)?;
    let ri_path_elements = pad_fr_to(&private.ri_path_siblings, 32)?;

    let chain_path_indices = pad_bool_to(&private.chain_path_indices, IMT_PATH_LEN)?;
    let chain_path_elements = pad_fr_to(&private.chain_path_siblings, IMT_PATH_LEN)?;

    Ok(SignerProverInput {
        r_root: fr_to_decimal(public.r_root),
        petition_id: fr_to_decimal(public.petition_id),
        predicate_hash: fr_to_decimal(public.predicate_hash),
        class_index: fr_to_decimal(public.class_index),
        class_tag: fr_to_decimal(public.class_tag),
        slot: fr_to_decimal(public.slot),
        nullifier: fr_to_decimal(public.nullifier),
        identity_tag: fr_to_decimal(public.identity_tag),
        identity_secret: fr_to_decimal(private.identity_secret),
        attrs,
        attr_version: private.attr_version.to_string(),
        chain_root: fr_to_decimal(private.chain_root),
        ri_path_indices,
        ri_path_elements,
        ri_proof_length: ri_proof_length.to_string(),
        s_slot: fr_to_decimal(private.s_slot),
        chain_path_indices,
        chain_path_elements,
        salt: fr_to_decimal(private.salt),
        op_codes,
        op_operands,
        op_count: pdef.ops.len().to_string(),
        tuple_claim_index,
        tuple_operand,
        tuple_type_tag,
        tuple_comparator,
        tuple_count: pdef.tuples.len().to_string(),
    })
}

impl ProofBackend for BBProver {
    fn generate_signer_proof(
        &self,
        public: &SignerPublicInputs,
        private: &SignerPrivateInputs,
    ) -> Result<Vec<u8>, ProofError> {
        let input = signer_to_input(public, private)?;
        let toml = toml::to_string(&input)
            .map_err(|e| ProofError::WitnessSerialization(format!("signer toml: {e}")))?;
        self.shell_out("signer", &toml, "noir-recursive")
    }

    fn generate_batch_proof(
        &self,
        public: &BatchPublicInputs,
        positions: &[BatchPositionWitness],
    ) -> Result<Vec<u8>, ProofError> {
        if positions.len() != BATCH_SIZE {
            return Err(ProofError::WitnessSerialization(format!(
                "BBProver: batch must contain exactly {BATCH_SIZE} positions (PoC cap); got {}",
                positions.len()
            )));
        }
        let (signer_vk, signer_vk_hash) = self.read_signer_vk()?;

        let mut signer_proofs: Vec<Vec<String>> = Vec::with_capacity(BATCH_SIZE);
        let mut signer_public_inputs: Vec<Vec<String>> = Vec::with_capacity(BATCH_SIZE);
        let mut running_low_leaf_indices: Vec<String> = Vec::with_capacity(BATCH_SIZE);
        let mut running_low_indices = Vec::with_capacity(BATCH_SIZE);
        let mut running_low_elements = Vec::with_capacity(BATCH_SIZE);
        let mut running_low_values = Vec::with_capacity(BATCH_SIZE);
        let mut running_low_next_indices = Vec::with_capacity(BATCH_SIZE);
        let mut running_low_next_values = Vec::with_capacity(BATCH_SIZE);
        let mut running_new_indices = Vec::with_capacity(BATCH_SIZE);
        let mut running_new_elements = Vec::with_capacity(BATCH_SIZE);
        let mut running_new_low_next_indices = Vec::with_capacity(BATCH_SIZE);
        let mut running_intermediate_roots = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_low_leaf_indices: Vec<String> = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_low_indices = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_low_elements = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_low_values = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_low_next_indices = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_low_next_values = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_new_indices = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_new_elements = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_new_low_next_indices = Vec::with_capacity(BATCH_SIZE);
        let mut idtag_intermediate_roots = Vec::with_capacity(BATCH_SIZE);

        for (i, p) in positions.iter().enumerate() {
            if p.submission.proof_bytes.len() != RECURSIVE_PROOF_LENGTH * 32 {
                return Err(ProofError::WitnessSerialization(format!(
                    "position {i}: signer proof has {} bytes; expected {}",
                    p.submission.proof_bytes.len(),
                    RECURSIVE_PROOF_LENGTH * 32
                )));
            }
            signer_proofs.push(bytes_to_fr_fields(&p.submission.proof_bytes)?);

            let pi = &p.public_inputs;
            let pi_fields: [Fr; N_SIGNER_PUB] = [
                pi.r_root,
                pi.petition_id,
                pi.predicate_hash,
                pi.class_index,
                pi.class_tag,
                pi.slot,
                pi.nullifier,
                pi.identity_tag,
            ];
            signer_public_inputs
                .push(pi_fields.iter().map(|f| fr_to_decimal(*f)).collect());

            let running = p.running_insert.as_ref().ok_or_else(|| {
                ProofError::WitnessSerialization(format!(
                    "position {i}: BBProver requires running_insert (IMT witness)"
                ))
            })?;
            let idtag = p.idtag_insert.as_ref().ok_or_else(|| {
                ProofError::WitnessSerialization(format!(
                    "position {i}: BBProver requires idtag_insert (IMT witness)"
                ))
            })?;

            running_low_leaf_indices.push(running.low_leaf_index.to_string());
            running_low_indices.push(imt_path_indices_bool(&running.low_leaf_path)?);
            running_low_elements.push(imt_path_elements(&running.low_leaf_path)?);
            running_low_values.push(fr_to_decimal(fr_from_be_bytes(
                &running.low_leaf_before.value,
            )));
            running_low_next_indices.push(running.low_leaf_before.next_index.to_string());
            running_low_next_values.push(fr_to_decimal(fr_from_be_bytes(
                &running.low_leaf_before.next_value,
            )));
            running_new_indices.push(imt_path_indices_bool(&running.new_leaf_path)?);
            running_new_elements.push(imt_path_elements(&running.new_leaf_path)?);
            // new_low_next_index is the UPDATED low leaf's next-pointer, which
            // is the absolute index of the new leaf.
            running_new_low_next_indices.push(running.new_leaf_index.to_string());
            running_intermediate_roots
                .push(fr_to_decimal(fr_from_be_bytes(&running.new_root)));

            idtag_low_leaf_indices.push(idtag.low_leaf_index.to_string());
            idtag_low_indices.push(imt_path_indices_bool(&idtag.low_leaf_path)?);
            idtag_low_elements.push(imt_path_elements(&idtag.low_leaf_path)?);
            idtag_low_values.push(fr_to_decimal(fr_from_be_bytes(
                &idtag.low_leaf_before.value,
            )));
            idtag_low_next_indices.push(idtag.low_leaf_before.next_index.to_string());
            idtag_low_next_values.push(fr_to_decimal(fr_from_be_bytes(
                &idtag.low_leaf_before.next_value,
            )));
            idtag_new_indices.push(imt_path_indices_bool(&idtag.new_leaf_path)?);
            idtag_new_elements.push(imt_path_elements(&idtag.new_leaf_path)?);
            idtag_new_low_next_indices.push(idtag.new_leaf_index.to_string());
            idtag_intermediate_roots
                .push(fr_to_decimal(fr_from_be_bytes(&idtag.new_root)));
        }

        let input = BatchProverInput {
            petition_id: fr_to_decimal(public.petition_id),
            r_root: fr_to_decimal(public.r_root),
            predicate_hash: fr_to_decimal(public.predicate_hash),
            class_index: fr_to_decimal(public.class_index),
            slot: fr_to_decimal(public.slot),
            prior_running_root: fr_to_decimal(public.prior_running_root),
            new_running_root: fr_to_decimal(public.new_running_root),
            prior_identity_tag_set_root: fr_to_decimal(
                public.prior_identity_tag_set_root,
            ),
            new_identity_tag_set_root: fr_to_decimal(public.new_identity_tag_set_root),
            prior_leaf_count: fr_to_decimal(public.prior_leaf_count),
            new_leaf_count: fr_to_decimal(public.new_leaf_count),
            batch_versioned_hash: fr_to_decimal(public.batch_versioned_hash),
            bls_fields: public
                .bls_fields
                .iter()
                .map(|f| fr_to_decimal(*f))
                .collect(),
            signer_vk,
            signer_vk_hash,
            signer_proofs,
            signer_public_inputs,
            running_imt_low_leaf_indices: running_low_leaf_indices,
            running_imt_low_indices: running_low_indices,
            running_imt_low_elements: running_low_elements,
            running_imt_low_values: running_low_values,
            running_imt_low_next_indices: running_low_next_indices,
            running_imt_low_next_values: running_low_next_values,
            running_imt_new_indices: running_new_indices,
            running_imt_new_elements: running_new_elements,
            running_imt_new_low_next_indices: running_new_low_next_indices,
            running_imt_intermediate_roots: running_intermediate_roots,
            idtag_imt_low_leaf_indices: idtag_low_leaf_indices,
            idtag_imt_low_indices: idtag_low_indices,
            idtag_imt_low_elements: idtag_low_elements,
            idtag_imt_low_values: idtag_low_values,
            idtag_imt_low_next_indices: idtag_low_next_indices,
            idtag_imt_low_next_values: idtag_low_next_values,
            idtag_imt_new_indices: idtag_new_indices,
            idtag_imt_new_elements: idtag_new_elements,
            idtag_imt_new_low_next_indices: idtag_new_low_next_indices,
            idtag_imt_intermediate_roots: idtag_intermediate_roots,
        };
        let toml = toml::to_string(&input)
            .map_err(|e| ProofError::WitnessSerialization(format!("batch toml: {e}")))?;
        self.shell_out("batch", &toml, "evm")
    }

    fn generate_resolution_proof(
        &self,
        public: &ResolutionPublicInputs,
        private: &ResolutionPrivateInputs,
    ) -> Result<Vec<u8>, ProofError> {
        if private.witness_pairs.len() != private.leaves.len() {
            return Err(ProofError::WitnessSerialization(
                "resolution: witness_pairs/leaves length mismatch".into(),
            ));
        }
        if private.imt_membership_paths.len() != private.leaves.len() {
            return Err(ProofError::WitnessSerialization(
                "resolution: imt_membership_paths/leaves length mismatch".into(),
            ));
        }
        if private.leaves.len() > LEAF_MAX {
            return Err(ProofError::WitnessSerialization(format!(
                "resolution: leaves {} exceeds LEAF_MAX {LEAF_MAX}",
                private.leaves.len()
            )));
        }
        if public.class_set.len() > CLASS_MAX {
            return Err(ProofError::WitnessSerialization(format!(
                "resolution: class_set {} exceeds CLASS_MAX {CLASS_MAX}",
                public.class_set.len()
            )));
        }

        let mut nullifier = Vec::with_capacity(LEAF_MAX);
        let mut class_tag = Vec::with_capacity(LEAF_MAX);
        let mut imt_next_index = Vec::with_capacity(LEAF_MAX);
        let mut imt_next_value = Vec::with_capacity(LEAF_MAX);
        let mut imt_path_indices = Vec::with_capacity(LEAF_MAX);
        let mut imt_path_elements = Vec::with_capacity(LEAF_MAX);
        for (i, (n, c)) in private.witness_pairs.iter().enumerate() {
            nullifier.push(fr_to_decimal(*n));
            class_tag.push(fr_to_decimal(*c));
            let path = &private.imt_membership_paths[i];
            imt_next_index.push(path.next_index.to_string());
            imt_next_value.push(fr_to_decimal(path.next_value));
            let mut idxs: Vec<bool> = path.indices.iter().map(|b| *b != 0).collect();
            idxs.resize(IMT_PATH_LEN, false);
            let mut els: Vec<String> =
                path.siblings.iter().map(|s| fr_to_decimal(*s)).collect();
            els.resize(IMT_PATH_LEN, "0".to_string());
            imt_path_indices.push(idxs);
            imt_path_elements.push(els);
        }
        while nullifier.len() < LEAF_MAX {
            nullifier.push("0".to_string());
            class_tag.push("0".to_string());
            imt_next_index.push("0".to_string());
            imt_next_value.push("0".to_string());
            imt_path_indices.push(vec![false; IMT_PATH_LEN]);
            imt_path_elements.push(vec!["0".to_string(); IMT_PATH_LEN]);
        }

        let mut class_set = fr_array_to_decimals(&public.class_set);
        while class_set.len() < CLASS_MAX {
            class_set.push("0".to_string());
        }
        let mut class_thresholds = fr_array_to_decimals(&public.class_thresholds);
        while class_thresholds.len() < CLASS_MAX {
            class_thresholds.push("0".to_string());
        }
        let mut b_per_class = fr_array_to_decimals(&public.b_per_class);
        while b_per_class.len() < CLASS_MAX {
            b_per_class.push("0".to_string());
        }

        let input = ResolutionProverInput {
            predicate_hash: fr_to_decimal(public.predicate_hash),
            r_root: fr_to_decimal(public.r_root),
            running_root: fr_to_decimal(public.running_root),
            leaf_count: fr_to_decimal(public.leaf_count),
            class_set,
            class_set_len: public.class_set.len().to_string(),
            class_thresholds,
            b: fr_to_decimal(public.b),
            b_per_class,
            class_index: fr_to_decimal(public.class_index),
            nullifier,
            class_tag,
            imt_next_index,
            imt_next_value,
            imt_path_indices,
            imt_path_elements,
        };
        let toml = toml::to_string(&input).map_err(|e| {
            ProofError::WitnessSerialization(format!("resolution toml: {e}"))
        })?;
        self.shell_out("resolution", &toml, "evm")
    }

    fn verify_signer_proof(
        &self,
        _proof: &[u8],
        _public: &SignerPublicInputs,
    ) -> Result<(), ProofError> {
        // Verification happens on chain or inside the batch SNARK; no local re-verify.
        Ok(())
    }

    fn verify_batch_proof(
        &self,
        _proof: &[u8],
        _public: &BatchPublicInputs,
    ) -> Result<(), ProofError> {
        Ok(())
    }

    fn verify_resolution_proof(
        &self,
        _proof: &[u8],
        _public: &ResolutionPublicInputs,
    ) -> Result<(), ProofError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fr_to_decimal_smoke() {
        assert_eq!(fr_to_decimal(Fr::from(0u64)), "0");
        assert_eq!(fr_to_decimal(Fr::from(42u64)), "42");
    }

    #[test]
    fn test_bytes_to_fr_fields_chunks_correctly() {
        let mut bytes = vec![0u8; 64];
        bytes[31] = 1;
        bytes[63] = 2;
        let fields = bytes_to_fr_fields(&bytes).unwrap();
        assert_eq!(fields, vec!["1".to_string(), "2".to_string()]);
    }

    #[test]
    fn test_bytes_to_fr_fields_rejects_unaligned_input() {
        let err = bytes_to_fr_fields(&[0u8; 33]);
        assert!(matches!(err, Err(ProofError::WitnessSerialization(_))));
    }
}

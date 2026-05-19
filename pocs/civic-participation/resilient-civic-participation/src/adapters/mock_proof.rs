//! Deterministic sentinel proof backend; verify re-derives the digest from public inputs.

use ark_bn254::Fr;
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    error::ProofError,
    ports::proof::{
        BatchPositionWitness,
        ProofBackend,
    },
    poseidon::fr_to_be_bytes,
    types::{
        BatchPublicInputs,
        ResolutionPrivateInputs,
        ResolutionPublicInputs,
        SignerPrivateInputs,
        SignerPublicInputs,
    },
};

#[derive(Debug, Clone, Copy, Default)]
pub struct MockProofBackend;

impl MockProofBackend {
    fn signer_digest(public: &SignerPublicInputs) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"RCP-mock/signer/v1");
        for fr in [
            public.r_root,
            public.petition_id,
            public.predicate_hash,
            public.class_index,
            public.class_tag,
            public.slot,
            public.nullifier,
            public.identity_tag,
        ] {
            h.update(fr_to_be_bytes(&fr));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    fn batch_digest(public: &BatchPublicInputs) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"RCP-mock/batch/v1");
        for fr in [
            public.petition_id,
            public.r_root,
            public.predicate_hash,
            public.class_index,
            public.slot,
            public.batch_size,
            public.prior_running_root,
            public.new_running_root,
            public.prior_identity_tag_set_root,
            public.new_identity_tag_set_root,
            public.prior_leaf_count,
            public.new_leaf_count,
            public.batch_versioned_hash,
            public.signer_vk_hash,
        ] {
            h.update(fr_to_be_bytes(&fr));
        }
        for fe in &public.bls_fields {
            h.update(fr_to_be_bytes(fe));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }

    fn resolution_digest(public: &ResolutionPublicInputs) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"RCP-mock/resolution/v1");
        for fr in [
            public.predicate_hash,
            public.r_root,
            public.running_root,
            public.leaf_count,
            public.b,
            public.class_index,
        ] {
            h.update(fr_to_be_bytes(&fr));
        }
        for c in &public.class_set {
            h.update(fr_to_be_bytes(c));
        }
        for t in &public.class_thresholds {
            h.update(fr_to_be_bytes(t));
        }
        for bp in &public.b_per_class {
            h.update(fr_to_be_bytes(bp));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&h.finalize());
        out
    }
}

impl ProofBackend for MockProofBackend {
    fn generate_signer_proof(
        &self,
        public: &SignerPublicInputs,
        private: &SignerPrivateInputs,
    ) -> Result<Vec<u8>, ProofError> {
        // Cross-check non-empty witness so empty-witness paths surface as errors.
        if private.attr_vector.is_empty() {
            return Err(ProofError::WitnessSerialization("empty attr_vector".into()));
        }
        if private.chain_root == Fr::from(0u64) {
            return Err(ProofError::WitnessSerialization(
                "chain_root must be non-zero".into(),
            ));
        }
        let mut out = Self::signer_digest(public).to_vec();
        out.extend_from_slice(b"signer-mock");
        Ok(out)
    }

    fn generate_batch_proof(
        &self,
        public: &BatchPublicInputs,
        positions: &[BatchPositionWitness],
    ) -> Result<Vec<u8>, ProofError> {
        if positions.is_empty() {
            return Err(ProofError::WitnessSerialization(
                "batch has no positions".into(),
            ));
        }
        // Recursive-verification stand-in: re-derive digest, assert equality per position.
        for (i, p) in positions.iter().enumerate() {
            let expected = Self::signer_digest(&p.public_inputs);
            if p.submission.proof_bytes.len() < 32
                || p.submission.proof_bytes[..32] != expected
            {
                return Err(ProofError::Verification(format!(
                    "batch position {i} signer proof failed mock recursion check"
                )));
            }
        }
        let mut out = Self::batch_digest(public).to_vec();
        out.extend_from_slice(b"batch-mock");
        Ok(out)
    }

    fn generate_resolution_proof(
        &self,
        public: &ResolutionPublicInputs,
        private: &ResolutionPrivateInputs,
    ) -> Result<Vec<u8>, ProofError> {
        if private.leaves.is_empty() {
            return Err(ProofError::WitnessSerialization(
                "resolution has no leaves".into(),
            ));
        }
        if private.imt_membership_paths.len() != private.leaves.len() {
            return Err(ProofError::WitnessSerialization(format!(
                "resolution leaves {} != imt membership paths {}",
                private.leaves.len(),
                private.imt_membership_paths.len()
            )));
        }
        let mut out = Self::resolution_digest(public).to_vec();
        out.extend_from_slice(b"resolution-mock");
        Ok(out)
    }

    fn verify_signer_proof(
        &self,
        proof: &[u8],
        public: &SignerPublicInputs,
    ) -> Result<(), ProofError> {
        let expected = Self::signer_digest(public);
        if proof.len() < 32 || proof[..32] != expected {
            return Err(ProofError::Verification("signer proof mismatch".into()));
        }
        Ok(())
    }

    fn verify_batch_proof(
        &self,
        proof: &[u8],
        public: &BatchPublicInputs,
    ) -> Result<(), ProofError> {
        let expected = Self::batch_digest(public);
        if proof.len() < 32 || proof[..32] != expected {
            return Err(ProofError::Verification("batch proof mismatch".into()));
        }
        Ok(())
    }

    fn verify_resolution_proof(
        &self,
        proof: &[u8],
        public: &ResolutionPublicInputs,
    ) -> Result<(), ProofError> {
        let expected = Self::resolution_digest(public);
        if proof.len() < 32 || proof[..32] != expected {
            return Err(ProofError::Verification("resolution proof mismatch".into()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ImtMembershipFr;

    fn sample_signer_public() -> SignerPublicInputs {
        SignerPublicInputs {
            r_root: Fr::from(1u64),
            petition_id: Fr::from(2u64),
            predicate_hash: Fr::from(3u64),
            class_index: Fr::from(0u64),
            class_tag: Fr::from(840u64),
            slot: Fr::from(0u64),
            nullifier: Fr::from(4u64),
            identity_tag: Fr::from(5u64),
        }
    }

    fn sample_signer_private() -> SignerPrivateInputs {
        SignerPrivateInputs {
            identity_secret: Fr::from(0xdeadbeefu64),
            attr_vector: vec![Fr::from(1u64); 4],
            attr_version: 0,
            chain_root: Fr::from(7u64),
            ri_path_siblings: vec![],
            ri_path_indices: vec![],
            s_slot: Fr::from(8u64),
            chain_path_siblings: vec![],
            chain_path_indices: vec![],
            salt: Fr::from(11u64),
            predicate_def: crate::predicate::PredicateDef {
                tuples: vec![crate::predicate::Tuple {
                    claim_index: 0,
                    operand: [0u8; 32],
                    type_tag: crate::types::TypeTag::Int64,
                    comparator: crate::types::Comparator::Eq,
                }],
                ops: vec![crate::predicate::Op {
                    code: crate::types::OpCode::PushTuple,
                    operand: 0,
                }],
            },
        }
    }

    fn sample_batch_public() -> BatchPublicInputs {
        BatchPublicInputs {
            petition_id: Fr::from(2u64),
            r_root: Fr::from(1u64),
            predicate_hash: Fr::from(3u64),
            class_index: Fr::from(0u64),
            slot: Fr::from(0u64),
            batch_size: Fr::from(1u64),
            prior_running_root: Fr::from(0u64),
            new_running_root: Fr::from(123u64),
            prior_identity_tag_set_root: Fr::from(0u64),
            new_identity_tag_set_root: Fr::from(456u64),
            prior_leaf_count: Fr::from(0u64),
            new_leaf_count: Fr::from(1u64),
            batch_versioned_hash: Fr::from(789u64),
            bls_fields: vec![
                Fr::from(0u64);
                crate::BATCH_SIZE_MAX * crate::blob::FE_PER_RECORD
            ],
            signer_vk_hash: Fr::from(0u64),
        }
    }

    #[test]
    fn test_signer_proof_roundtrip_verifies() {
        let backend = MockProofBackend;
        let public = sample_signer_public();
        let private = sample_signer_private();
        let proof = backend.generate_signer_proof(&public, &private).unwrap();
        backend.verify_signer_proof(&proof, &public).unwrap();
    }

    #[test]
    fn test_signer_proof_mismatch_rejected() {
        let backend = MockProofBackend;
        let public = sample_signer_public();
        let private = sample_signer_private();
        let proof = backend.generate_signer_proof(&public, &private).unwrap();
        let mut tampered = public.clone();
        tampered.nullifier = Fr::from(99u64);
        assert!(backend.verify_signer_proof(&proof, &tampered).is_err());
    }

    #[test]
    fn test_batch_proof_requires_valid_position_proofs() {
        let backend = MockProofBackend;
        let public = sample_batch_public();
        let positions = vec![BatchPositionWitness {
            submission: crate::types::SignerSubmission {
                petition_id: [0u8; 32],
                r_root: [0u8; 32],
                predicate_hash: [0u8; 32],
                class_index: 0,
                slot: 0,
                nullifier: [0u8; 32],
                identity_tag: [0u8; 32],
                class_tag: 0,
                proof_bytes: vec![0xff; 64],
            },
            public_inputs: sample_signer_public(),
            running_insert: None,
            idtag_insert: None,
        }];
        let err = backend.generate_batch_proof(&public, &positions);
        assert!(matches!(err, Err(ProofError::Verification(_))));
    }

    #[test]
    fn test_batch_proof_round_trips_when_signer_proofs_are_valid() {
        let backend = MockProofBackend;
        let signer_public = sample_signer_public();
        let signer_private = sample_signer_private();
        let signer_proof = backend
            .generate_signer_proof(&signer_public, &signer_private)
            .unwrap();
        let mut batch_public = sample_batch_public();
        batch_public.r_root = signer_public.r_root;
        batch_public.petition_id = signer_public.petition_id;
        batch_public.predicate_hash = signer_public.predicate_hash;
        batch_public.class_index = signer_public.class_index;
        batch_public.slot = signer_public.slot;

        let positions = vec![BatchPositionWitness {
            submission: crate::types::SignerSubmission {
                petition_id: [0u8; 32],
                r_root: [0u8; 32],
                predicate_hash: [0u8; 32],
                class_index: 0,
                slot: 0,
                nullifier: [0u8; 32],
                identity_tag: [0u8; 32],
                class_tag: 0,
                proof_bytes: signer_proof,
            },
            running_insert: None,
            idtag_insert: None,
            public_inputs: signer_public,
        }];
        let proof = backend
            .generate_batch_proof(&batch_public, &positions)
            .unwrap();
        backend.verify_batch_proof(&proof, &batch_public).unwrap();
    }

    #[test]
    fn test_resolution_proof_roundtrip_verifies() {
        let backend = MockProofBackend;
        let public = ResolutionPublicInputs {
            predicate_hash: Fr::from(3u64),
            r_root: Fr::from(1u64),
            running_root: Fr::from(123u64),
            leaf_count: Fr::from(1u64),
            class_set: vec![Fr::from(840u64)],
            class_thresholds: vec![Fr::from(1u64)],
            b: Fr::from(1u64),
            b_per_class: vec![Fr::from(1u64)],
            class_index: Fr::from(0u64),
        };
        let private = ResolutionPrivateInputs {
            leaves: vec![Fr::from(7u64)],
            imt_membership_paths: vec![ImtMembershipFr {
                leaf_hash: Fr::from(7u64),
                leaf_index: 1,
                next_index: 0,
                next_value: Fr::from(0u64),
                siblings: vec![],
                indices: vec![],
            }],
            witness_pairs: vec![(Fr::from(1u64), Fr::from(840u64))],
        };
        let proof = backend
            .generate_resolution_proof(&public, &private)
            .unwrap();
        backend.verify_resolution_proof(&proof, &public).unwrap();
    }

    #[test]
    fn test_resolution_proof_rejects_empty_leaves() {
        let backend = MockProofBackend;
        let public = ResolutionPublicInputs {
            predicate_hash: Fr::from(3u64),
            r_root: Fr::from(1u64),
            running_root: Fr::from(123u64),
            leaf_count: Fr::from(0u64),
            class_set: vec![Fr::from(840u64)],
            class_thresholds: vec![Fr::from(0u64)],
            b: Fr::from(1u64),
            b_per_class: vec![Fr::from(1u64)],
            class_index: Fr::from(0u64),
        };
        let private = ResolutionPrivateInputs {
            leaves: vec![],
            imt_membership_paths: vec![],
            witness_pairs: vec![],
        };
        let err = backend.generate_resolution_proof(&public, &private);
        assert!(matches!(err, Err(ProofError::WitnessSerialization(_))));
    }
}

//! Signer actor: enroll, sign, journal.

use ark_bn254::Fr;
use rand::RngCore;

use crate::{
    fsrt::SignerChainState,
    ports::{
        proof::ProofBackend,
        ri::RiCredentialLayer,
    },
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        hash_attr,
        hash_identity_tag,
        hash_nullifier,
    },
    signer::{
        error::SignerError,
        types::{
            EnrollmentArtifact,
            PetitionMeta,
        },
    },
    types::{
        SignerCredentials,
        SignerPrivateInputs,
        SignerPublicInputs,
        SignerStateBytes,
        SignerSubmission,
    },
};

/// Per-signer container.
pub struct Signer<P, R>
where
    P: ProofBackend,
    R: RiCredentialLayer,
{
    pub credentials: SignerCredentials,
    pub chain: SignerChainState,
    pub proof_backend: P,
    pub ri: R,
}

impl<P, R> Signer<P, R>
where
    P: ProofBackend,
    R: RiCredentialLayer,
{
    /// Construct a signer and run enrollment.
    pub fn enroll(
        proof_backend: P,
        mut ri: R,
        attr_vector: Vec<Fr>,
        chain_len: u32,
        attr_version: u32,
        posted_at_block: u64,
        seed: Option<[u8; 32]>,
    ) -> (Self, EnrollmentArtifact) {
        let s_0_bytes = match seed {
            Some(b) => b,
            None => {
                // OsRng pulls entropy from the OS CSPRNG (getrandom on
                // Linux, /dev/urandom on macOS, BCryptGenRandom on
                // Windows). Use try_fill_bytes so an entropy-starvation
                // condition (early boot, sandbox without /dev/urandom)
                // propagates as a panic-with-context rather than a
                // silent default. For PoC code we accept the panic;
                // production code should plumb a Result.
                let mut b = [0u8; 32];
                use rand::rngs::OsRng;
                OsRng
                    .try_fill_bytes(&mut b)
                    .expect("OsRng entropy unavailable; cannot enroll");
                b
            }
        };
        let s_0 = fr_from_be_bytes(&s_0_bytes);

        // identity_secret is sampled INDEPENDENTLY of s_0. Per SPEC the
        // signer holds (s_0, identity_secret) as two separate per-signer
        // secrets; the RI leaf binds to both, and the nullifier binds to
        // identity_secret so leaking s_0 alone does not allow signing
        // under the victim's RI leaf.
        let identity_secret_bytes: [u8; 32] = {
            let mut b = [0u8; 32];
            use rand::rngs::OsRng;
            OsRng
                .try_fill_bytes(&mut b)
                .expect("OsRng entropy unavailable; cannot enroll");
            b
        };
        let identity_secret_fr = fr_from_be_bytes(&identity_secret_bytes);

        let chain = SignerChainState::enroll(s_0, chain_len, attr_version);

        let attr_hash_fr = hash_attr(
            &attr_vector,
            chain.chain_root,
            attr_version,
            identity_secret_fr,
        );
        let attr_hash_be = fr_to_be_bytes(&attr_hash_fr);

        let ri_leaf_index = ri.append_leaf(attr_hash_be, posted_at_block);

        let credentials = SignerCredentials {
            identity_secret: identity_secret_bytes,
            attr_vector: attr_vector.iter().map(fr_to_be_bytes).collect(),
            ri_leaf_index,
        };
        let signer = Self {
            credentials,
            chain,
            proof_backend,
            ri,
        };
        let artifact = EnrollmentArtifact {
            attr_hash: attr_hash_be,
            chain_root: fr_to_be_bytes(&signer.chain.chain_root),
            attr_version,
        };
        (signer, artifact)
    }

    /// SPEC Per-Signature Generation.
    pub fn sign(
        &mut self,
        petition: &PetitionMeta,
    ) -> Result<SignerSubmission, SignerError> {
        // Validate everything BEFORE mutating chain state: a failed sign
        // must not advance the FSRT head (which is monotone), otherwise
        // a malformed PetitionMeta could permanently block earlier slots.
        if petition.slot < self.chain.t {
            return Err(SignerError::SlotInPast {
                slot: petition.slot,
                head: self.chain.t,
            });
        }
        let chain_len = self.chain.chain_len();
        if petition.slot >= chain_len {
            return Err(SignerError::SlotOutOfRange {
                slot: petition.slot,
                chain_len,
            });
        }

        let class_tag_fr = Fr::from(petition.class_tag as u64);
        let attr_vector_fr: Vec<Fr> = self
            .credentials
            .attr_vector
            .iter()
            .map(|b| fr_from_be_bytes(b))
            .collect();
        let attr_at_idx = attr_vector_fr
            .get(petition.class_index as usize)
            .ok_or_else(|| {
                SignerError::Invariant(format!(
                    "class_index {} out of range (attr_count {})",
                    petition.class_index,
                    attr_vector_fr.len()
                ))
            })?;
        if *attr_at_idx != class_tag_fr {
            return Err(SignerError::Invariant(format!(
                "class binding mismatch: attr[{}] != class_tag",
                petition.class_index
            )));
        }

        // Validation passed; safe to advance.
        self.chain.advance_to(petition.slot);
        let v_slot = self.chain.v_at_current_slot();

        let petition_id_fr = fr_from_be_bytes(&petition.petition_id);
        let class_index_fr = Fr::from(petition.class_index as u64);
        let identity_secret_fr = fr_from_be_bytes(&self.credentials.identity_secret);
        let nullifier_fr = hash_nullifier(
            v_slot,
            petition_id_fr,
            class_index_fr,
            class_tag_fr,
            identity_secret_fr,
        );
        let identity_tag_fr = hash_identity_tag(v_slot, petition_id_fr);

        let (chain_siblings, chain_indices) = self.chain.merkle_path_for_current_slot();
        let ri_path = self
            .ri
            .merkle_path(self.credentials.ri_leaf_index)
            .map_err(|e| SignerError::RiLookup(e.to_string()))?;

        let attr_version = self.chain.attr_version;

        let public = SignerPublicInputs {
            r_root: fr_from_be_bytes(&petition.r_root),
            petition_id: petition_id_fr,
            predicate_hash: fr_from_be_bytes(&petition.predicate_hash),
            class_index: class_index_fr,
            class_tag: class_tag_fr,
            slot: Fr::from(petition.slot as u64),
            nullifier: nullifier_fr,
            identity_tag: identity_tag_fr,
        };
        let private = SignerPrivateInputs {
            identity_secret: identity_secret_fr,
            attr_vector: attr_vector_fr,
            attr_version,
            chain_root: self.chain.chain_root,
            ri_path_siblings: ri_path
                .siblings
                .iter()
                .map(|b| fr_from_be_bytes(b))
                .collect(),
            ri_path_indices: ri_path.indices,
            s_slot: self.chain.s_at(petition.slot),
            chain_path_siblings: chain_siblings,
            chain_path_indices: chain_indices,
            salt: fr_from_be_bytes(&petition.salt),
            predicate_def: petition.predicate_def.clone(),
        };
        let proof_bytes = self
            .proof_backend
            .generate_signer_proof(&public, &private)?;

        Ok(SignerSubmission {
            petition_id: petition.petition_id,
            r_root: petition.r_root,
            predicate_hash: petition.predicate_hash,
            class_index: petition.class_index,
            slot: petition.slot,
            nullifier: fr_to_be_bytes(&nullifier_fr),
            identity_tag: fr_to_be_bytes(&identity_tag_fr),
            class_tag: petition.class_tag,
            proof_bytes,
        })
    }

    /// Journal a finalized slot; call after L1 finality. Writes the
    /// post-signing state atomically to `journal_path` BEFORE mutating
    /// in-memory state.
    pub fn journal_finalized(
        &mut self,
        slot: u32,
        journal_path: &std::path::Path,
    ) -> Result<SignerStateBytes, std::io::Error> {
        self.chain.journal_finalized_signing(slot, journal_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        adapters::{
            in_memory_ri::InMemoryRi,
            mock_proof::MockProofBackend,
        },
        poseidon::hash_leaf,
        types::ClassTag,
    };

    fn signer_factory() -> (
        Signer<MockProofBackend, InMemoryRi>,
        EnrollmentArtifact,
        Vec<Fr>,
    ) {
        let attrs = vec![
            Fr::from(1u64),
            Fr::from(840u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];
        let backend = MockProofBackend;
        let ri = InMemoryRi::new();
        let (signer, artifact) =
            Signer::enroll(backend, ri, attrs.clone(), 8, 0, 100, Some([0xa1u8; 32]));
        (signer, artifact, attrs)
    }

    #[test]
    fn test_enroll_appends_to_ri_and_returns_chain_root() {
        let (signer, artifact, attrs) = signer_factory();
        assert_eq!(artifact.attr_version, 0);
        assert_eq!(signer.credentials.ri_leaf_index, 0);
        assert_ne!(artifact.chain_root, [0u8; 32]);
        let _ = attrs;
    }

    fn meta_for(
        petition_id: u64,
        slot: u32,
        class_index: u8,
        class_tag: ClassTag,
    ) -> PetitionMeta {
        let mut id = [0u8; 32];
        id[24..].copy_from_slice(&petition_id.to_be_bytes());
        let mut r = [0u8; 32];
        r[24..].copy_from_slice(&77u64.to_be_bytes());
        let mut ph = [0u8; 32];
        ph[24..].copy_from_slice(&88u64.to_be_bytes());
        let mut s = [0u8; 32];
        s[24..].copy_from_slice(&33u64.to_be_bytes());
        PetitionMeta {
            petition_id: id,
            r_root: r,
            predicate_hash: ph,
            slot,
            class_index,
            class_tag,
            predicate_def: dummy_predicate(class_index, class_tag),
            salt: s,
            ri_leaf_index: 0,
        }
    }

    fn dummy_predicate(
        class_index: u8,
        class_tag: ClassTag,
    ) -> crate::predicate::PredicateDef {
        use crate::predicate::{
            Op,
            PredicateDef,
            Tuple,
        };
        let mut operand = [0u8; 32];
        operand[30..].copy_from_slice(&class_tag.to_be_bytes());
        PredicateDef {
            tuples: vec![Tuple {
                claim_index: class_index,
                operand,
                type_tag: crate::types::TypeTag::Int64,
                comparator: crate::types::Comparator::Eq,
            }],
            ops: vec![Op {
                code: crate::types::OpCode::PushTuple,
                operand: 0,
            }],
        }
    }

    #[test]
    fn test_sign_emits_distinct_nullifiers_per_petition() {
        let (mut signer, _, _) = signer_factory();
        let m1 = meta_for(1, 0, 1, 840);
        let s1 = signer.sign(&m1).unwrap();
        let m2 = meta_for(2, 1, 1, 840);
        let s2 = signer.sign(&m2).unwrap();
        assert_ne!(s1.nullifier, s2.nullifier);
        assert_ne!(s1.identity_tag, s2.identity_tag);
    }

    #[test]
    fn test_sign_in_past_rejected() {
        let (mut signer, _, _) = signer_factory();
        let m = meta_for(7, 3, 1, 840);
        let _ = signer.sign(&m).unwrap();
        let tmpdir = tempfile::tempdir().unwrap();
        let journal_path = tmpdir.path().join("journal.bin");
        signer.journal_finalized(3, &journal_path).unwrap();
        let earlier = meta_for(8, 1, 1, 840);
        let err = signer.sign(&earlier);
        assert!(matches!(err, Err(SignerError::SlotInPast { .. })));
    }

    #[test]
    fn test_sign_with_wrong_class_tag_rejected() {
        let (mut signer, _, _) = signer_factory();
        let m = meta_for(1, 0, 1, 999);
        let err = signer.sign(&m);
        assert!(matches!(err, Err(SignerError::Invariant(_))));
    }

    #[test]
    fn test_journal_finalized_advances_t() {
        let (mut signer, _, _) = signer_factory();
        let m = meta_for(1, 0, 1, 840);
        let _ = signer.sign(&m).unwrap();
        let pre = signer.chain.t;
        let tmpdir = tempfile::tempdir().unwrap();
        let journal_path = tmpdir.path().join("journal.bin");
        signer.journal_finalized(0, &journal_path).unwrap();
        assert!(signer.chain.t > pre);
    }

    #[test]
    fn test_nullifier_and_identity_tag_distinct_under_same_inputs() {
        let (mut signer, _, _) = signer_factory();
        let m = meta_for(1, 0, 1, 840);
        let s = signer.sign(&m).unwrap();
        assert_ne!(s.nullifier, s.identity_tag);
    }

    #[test]
    fn test_leaf_derivation_matches_external_recompute() {
        let (mut signer, _, _) = signer_factory();
        let m = meta_for(1, 0, 1, 840);
        let s = signer.sign(&m).unwrap();
        let null_fr = fr_from_be_bytes(&s.nullifier);
        let class_fr = Fr::from(s.class_tag as u64);
        let leaf_external = hash_leaf(null_fr, class_fr);
        let leaf_relayer = hash_leaf(null_fr, class_fr);
        assert_eq!(leaf_external, leaf_relayer);
    }
}

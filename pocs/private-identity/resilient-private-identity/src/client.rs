use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use ark_std::UniformRand;
use sha2::{
    Digest,
    Sha256,
};

/// Convert a BN254 base field element (Fq) to a scalar field element (Fr)
/// by going through the big integer representation. This reduces mod r,
/// which is acceptable for the PoC since we only use this for Poseidon hashing
/// of curve coordinates.
fn fq_to_fr(fq: ark_bn254::Fq) -> Fr {
    let bytes = fq.into_bigint().to_bytes_le();
    Fr::from_le_bytes_mod_order(&bytes)
}

use crate::{
    domain::voprf::{
        aggregate,
        blind,
        hash_to_curve,
        unblind,
        verify_dleq,
    },
    error::ClientError,
    ports::{
        merkle::MerkleStore,
        mpc::{
            BlindEvaluateRequest,
            MpcNetwork,
        },
        proof::ProofBackend,
    },
    poseidon::{
        hash_attr,
        hash_enrollment_nullifier,
        hash_leaf,
        hash_link,
        hash_nullifier,
    },
    types::{
        EnrollmentData,
        Identity,
        MembershipProofData,
        Predicate,
    },
};

pub struct IdentityClient<P, M, T> {
    pub proof_backend: P,
    pub mpc_network: M,
    pub merkle_store: T,
}

impl<P, M, T> IdentityClient<P, M, T>
where
    P: ProofBackend,
    M: MpcNetwork,
    T: MerkleStore,
{
    pub fn new(proof_backend: P, mpc_network: M, merkle_store: T) -> Self {
        Self {
            proof_backend,
            mpc_network,
            merkle_store,
        }
    }

    /// Enroll a user identity into the system.
    ///
    /// This executes the full enrollment flow:
    /// 1. Hash user ID and compute identity base point G_id
    /// 2. Generate blinding factor and blind the request
    /// 3. Generate link proof (pi_link)
    /// 4. Submit to MPC network for vOPRF evaluation
    /// 5. Verify DLEQ proofs from MPC nodes
    /// 6. Aggregate threshold-many responses via Lagrange interpolation
    /// 7. Unblind to get raw nullifier
    /// 8. Compute enrollment nullifier and leaf commitment
    /// 9. Generate enrollment ZK proof
    /// 10. Insert leaf into local Merkle store
    ///
    /// Returns the Identity (for future proof generation) and EnrollmentData
    /// (for on-chain submission).
    pub fn enroll(
        &mut self,
        user_id: &str,
        attrs: [Fr; 4],
        version: u32,
    ) -> Result<(Identity, EnrollmentData, Vec<u8>), ClientError> {
        let mut rng = ark_std::rand::thread_rng();

        // 1. Canonicalize user_id, compute user_id_hash = SHA-256(user_id) mod r
        let hash = Sha256::digest(user_id.as_bytes());
        let user_id_hash = Fr::from_be_bytes_mod_order(&hash);

        // 2. G_id = hash_to_curve(user_id_hash) via SVDW (Fouque-Tibouchi)
        let svdw = hash_to_curve(user_id_hash);
        let g_id = svdw.point;

        // 3. Generate random salt and blinding factor r
        let salt = Fr::rand(&mut rng);
        let r = Fr::rand(&mut rng);

        // 4. identity_commitment = hash_link(user_id_hash, salt)
        let identity_commitment = hash_link(user_id_hash, salt);

        // 5. blinded_request = blind(G_id, r)
        let blinded_request = blind(g_id, r);

        // 6. Generate pi_link proof
        let link_proof = self
            .proof_backend
            .generate_link_proof(
                user_id_hash,
                salt,
                r,
                g_id,
                identity_commitment,
                blinded_request,
                &crate::types::SvdwWitnesses {
                    index: svdw.index,
                    w: svdw.w,
                    inv_w2: svdw.inv_w2,
                    non_qr_witnesses: svdw.non_qr_witnesses,
                },
            )
            .map_err(ClientError::Proof)?;

        // 7. Send to MPC network for evaluation (includes pi_link for verification)
        let request = BlindEvaluateRequest {
            blinded_request,
            identity_commitment,
            g_id,
            link_proof,
        };
        let evaluations = self.mpc_network.evaluate(&request);

        // 8. Verify per-node DLEQ proofs
        let mut valid_evals = Vec::new();
        for eval in &evaluations {
            let node_pk = self.mpc_network.node_public_key(eval.node_index);
            if verify_dleq(node_pk, blinded_request, eval.partial, &eval.proof) {
                valid_evals.push(eval.clone());
            }
        }

        let threshold = self.mpc_network.threshold();
        if valid_evals.len() < threshold {
            return Err(ClientError::Mpc(format!(
                "Not enough valid MPC responses: got {}, need {threshold}",
                valid_evals.len()
            )));
        }

        // 9. Pick threshold-many valid responses and aggregate via Lagrange
        let partials: Vec<(usize, ark_bn254::G1Affine)> = valid_evals[..threshold]
            .iter()
            .map(|e| (e.node_index, e.partial))
            .collect();
        let aggregated = aggregate(&partials);

        // 10. Unblind: raw_nullifier = unblind(aggregated, r)
        let raw_nullifier = unblind(aggregated, r);

        // 11. enrollment_nullifier = hash_enrollment_nullifier(raw_nullifier.x, raw_nullifier.y)
        //     The Fq coordinates need to be converted to Fr for Poseidon.
        //     Since Fr < Fq for BN254, we use the coordinate's big integer value mod r.
        let raw_x_fr: Fr = fq_to_fr(raw_nullifier.x);
        let raw_y_fr: Fr = fq_to_fr(raw_nullifier.y);
        let enrollment_nullifier = hash_enrollment_nullifier(raw_x_fr, raw_y_fr);

        // 12. Generate random identity_secret
        let identity_secret = Fr::rand(&mut rng);

        // 13. attr_hash = hash_attr(version, attrs)
        let version_fr = Fr::from(version as u64);
        let attr_hash = hash_attr(version_fr, &attrs);

        // 14. leaf = hash_leaf(identity_secret, attr_hash)
        let leaf = hash_leaf(identity_secret, attr_hash);

        // 15. Get the aggregate DLEQ proof from the MPC network.
        //     This proves log_G(PK) == log_{G_id}(raw_nullifier).
        let chaum_pedersen_proof =
            self.mpc_network.aggregate_dleq_proof(g_id, raw_nullifier);

        // 16. Generate enrollment proof
        let mpc_public_key = self.mpc_network.public_key();
        let enrollment_proof_bytes = self
            .proof_backend
            .generate_enrollment_proof(
                identity_secret,
                &attrs,
                version,
                g_id,
                raw_nullifier,
                mpc_public_key,
                &chaum_pedersen_proof,
            )
            .map_err(ClientError::Proof)?;

        // 17. Insert leaf into local Merkle store
        let leaf_index = self.merkle_store.insert(leaf) as u32;

        let identity = Identity {
            identity_secret,
            attrs,
            version,
            leaf_index,
        };

        let enrollment_data = EnrollmentData {
            leaf,
            enrollment_nullifier,
            raw_nullifier,
            g_id,
            mpc_public_key,
            chaum_pedersen_proof,
        };

        Ok((identity, enrollment_data, enrollment_proof_bytes))
    }

    /// Generate a membership proof for an enrolled identity.
    ///
    /// This generates a ZK proof that the identity is in the Merkle tree
    /// and satisfies the given predicate, without revealing which leaf.
    pub fn generate_membership_proof(
        &self,
        identity: &Identity,
        external_nullifier: Fr,
        predicate: &Predicate,
    ) -> Result<MembershipProofData, ClientError> {
        // 1. Get Merkle proof from store
        let merkle_path = self.merkle_store.get_proof(identity.leaf_index as usize);

        // 2. Get current root
        let root = self
            .merkle_store
            .root()
            .ok_or_else(|| ClientError::Merkle("Empty tree".to_string()))?;

        // 3. Compute nullifier
        let nullifier = hash_nullifier(identity.identity_secret, external_nullifier);

        // 4. Compute predicate result (needed for public inputs)
        let selected = if predicate.attr_index == 0 {
            identity.attrs[0]
        } else {
            identity.attrs[1]
        };
        let predicate_result = match predicate.predicate_type {
            0 => {
                if selected == predicate.value {
                    Fr::from(1u64)
                } else {
                    Fr::from(0u64)
                }
            }
            1 => {
                if selected == Fr::from(1u64) {
                    Fr::from(1u64)
                } else {
                    Fr::from(0u64)
                }
            }
            _ => Fr::from(0u64),
        };

        // 5. Generate membership proof
        let proof_bytes = self
            .proof_backend
            .generate_membership_proof(
                identity.identity_secret,
                &identity.attrs,
                identity.version,
                &merkle_path,
                root,
                external_nullifier,
                predicate,
            )
            .map_err(ClientError::Proof)?;

        Ok(MembershipProofData {
            proof_bytes,
            root,
            nullifier,
            external_nullifier,
            version: identity.version,
            predicate_type: predicate.predicate_type,
            predicate_attr_index: predicate.attr_index,
            predicate_value: predicate.value,
            predicate_result,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::{
        lean_imt_merkle::LeanImtMerkleStore,
        mock_mpc::MockMpcNetwork,
        mock_proof::MockProofBackend,
    };

    #[test]
    fn test_enroll_and_generate_membership_proof() {
        let prover = MockProofBackend;
        let mpc = MockMpcNetwork::new(4, 7, MockProofBackend);
        let merkle = LeanImtMerkleStore::new();
        let mut client = IdentityClient::new(prover, mpc, merkle);

        let attrs = [
            Fr::from(1u64),
            Fr::from(840u64),
            Fr::from(0u64),
            Fr::from(20178u64),
        ];

        let (identity, enrollment_data, enrollment_proof) =
            client.enroll("email:alice@example.com", attrs, 1).unwrap();

        // Verify enrollment data
        assert_ne!(enrollment_data.leaf, Fr::from(0u64));
        assert_ne!(enrollment_data.enrollment_nullifier, Fr::from(0u64));
        assert_eq!(identity.leaf_index, 0);
        assert_eq!(identity.version, 1);
        assert!(!enrollment_proof.is_empty());

        // Generate membership proof
        let external_nullifier = Fr::from(99999u64);
        let predicate = Predicate {
            predicate_type: 1,
            attr_index: 0,
            value: Fr::from(0u64),
        };
        let proof_data = client
            .generate_membership_proof(&identity, external_nullifier, &predicate)
            .unwrap();

        assert_ne!(proof_data.root, Fr::from(0u64));
        assert_ne!(proof_data.nullifier, Fr::from(0u64));
        assert_eq!(proof_data.external_nullifier, external_nullifier);
        assert_eq!(proof_data.version, 1);
    }

    #[test]
    fn test_double_enrollment_different_leaves() {
        let prover = MockProofBackend;
        let mpc = MockMpcNetwork::new(4, 7, MockProofBackend);
        let merkle = LeanImtMerkleStore::new();
        let mut client = IdentityClient::new(prover, mpc, merkle);

        let attrs = [
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];

        let (id1, data1, _) = client.enroll("email:alice@example.com", attrs, 1).unwrap();
        let (id2, data2, _) = client.enroll("email:bob@example.com", attrs, 1).unwrap();

        // Different users get different leaves (different identity_secret)
        assert_ne!(data1.leaf, data2.leaf);
        assert_eq!(id1.leaf_index, 0);
        assert_eq!(id2.leaf_index, 1);
    }

    #[test]
    fn test_membership_proof_different_external_nullifiers() {
        let prover = MockProofBackend;
        let mpc = MockMpcNetwork::new(4, 7, MockProofBackend);
        let merkle = LeanImtMerkleStore::new();
        let mut client = IdentityClient::new(prover, mpc, merkle);

        let attrs = [
            Fr::from(1u64),
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(0u64),
        ];
        let (identity, _, _) =
            client.enroll("email:alice@example.com", attrs, 1).unwrap();

        let predicate = Predicate {
            predicate_type: 0,
            attr_index: 0,
            value: Fr::from(1u64),
        };

        let proof1 = client
            .generate_membership_proof(&identity, Fr::from(100u64), &predicate)
            .unwrap();
        let proof2 = client
            .generate_membership_proof(&identity, Fr::from(200u64), &predicate)
            .unwrap();

        // Different external nullifiers should produce different nullifiers
        assert_ne!(proof1.nullifier, proof2.nullifier);
        // But same root (tree hasn't changed)
        assert_eq!(proof1.root, proof2.root);
    }
}

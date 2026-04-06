/// Mock MPC network using Shamir secret sharing for the vOPRF.
///
/// In production, the MPC nodes would each hold a share of the signing key
/// and produce partial evaluations with DLEQ proofs. Here we simulate
/// the full flow in-process.
use ark_bn254::{
    Fr,
    G1Affine,
    G1Projective,
};
use ark_ec::{
    AffineRepr,
    CurveGroup,
};
use ark_std::UniformRand;

use crate::{
    domain::voprf::{
        prove_dleq,
        share_secret,
    },
    ports::{
        mpc::{
            BlindEvaluateRequest,
            MpcNetwork,
        },
        proof::LinkProofVerifier,
    },
    types::{
        DleqProof,
        PartialEvaluation,
    },
};

/// Mock MPC network holding Shamir shares, generic over a link proof verifier.
pub struct MockMpcNetwork<V: LinkProofVerifier> {
    pub shares: Vec<(usize, Fr)>,
    pub secret: Fr,
    pub pk: G1Affine,
    pub t: usize,
    pub n: usize,
    pub verifier: V,
}

impl<V: LinkProofVerifier> MockMpcNetwork<V> {
    /// Create a new mock MPC network with threshold t, n nodes, and a link proof verifier.
    /// Generates a random secret, splits via Shamir, computes public_key = secret * G.
    pub fn new(t: usize, n: usize, verifier: V) -> Self {
        let mut rng = ark_std::rand::thread_rng();
        let secret = Fr::rand(&mut rng);
        let shares = share_secret(secret, t, n);
        let pk = (G1Projective::from(G1Affine::generator()) * secret).into_affine();
        Self {
            shares,
            secret,
            pk,
            t,
            n,
            verifier,
        }
    }
}

impl<V: LinkProofVerifier> MpcNetwork for MockMpcNetwork<V> {
    /// Each MPC node verifies the link proof, then evaluates the blinded
    /// request with its share and produces a DLEQ proof of correctness.
    fn evaluate(&self, request: &BlindEvaluateRequest) -> Vec<PartialEvaluation> {
        let valid = self
            .verifier
            .verify_link_proof(
                &request.link_proof,
                request.identity_commitment,
                request.blinded_request,
                request.g_id,
            )
            .expect("link proof verification failed");
        assert!(valid, "link proof verification rejected");

        self.shares
            .iter()
            .map(|(idx, share)| {
                let (partial, proof) = prove_dleq(*share, request.blinded_request);
                PartialEvaluation {
                    node_index: *idx,
                    partial,
                    proof,
                }
            })
            .collect()
    }

    fn public_key(&self) -> G1Affine {
        self.pk
    }

    fn threshold(&self) -> usize {
        self.t
    }

    /// Compute the node's public key share from its secret share.
    fn node_public_key(&self, node_index: usize) -> G1Affine {
        let share = self
            .shares
            .iter()
            .find(|(idx, _)| *idx == node_index)
            .expect("node index not found");
        (G1Projective::from(G1Affine::generator()) * share.1).into_affine()
    }

    fn aggregate_dleq_proof(&self, g_id: G1Affine, raw_nullifier: G1Affine) -> DleqProof {
        let (q, proof) = prove_dleq(self.secret, g_id);
        assert_eq!(q, raw_nullifier, "raw_nullifier must equal secret * g_id");
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::PrimeField;
    use sha2::{
        Digest,
        Sha256,
    };

    use crate::{
        adapters::mock_proof::MockProofBackend,
        domain::voprf::{
            aggregate,
            blind,
            hash_to_curve,
            unblind,
            verify_dleq,
        },
        poseidon::hash_link,
    };

    fn test_user_id_hash(input: &[u8]) -> Fr {
        let hash = Sha256::digest(input);
        Fr::from_be_bytes_mod_order(&hash)
    }

    /// Build a BlindEvaluateRequest for testing.
    fn test_request(g_id: G1Affine, blinded: G1Affine) -> BlindEvaluateRequest {
        let user_id_hash = Fr::from(1u64);
        let salt = Fr::from(2u64);
        BlindEvaluateRequest {
            blinded_request: blinded,
            identity_commitment: hash_link(user_id_hash, salt),
            g_id,
            link_proof: vec![0xCA, 0xFE],
        }
    }

    #[test]
    fn test_full_voprf_flow() {
        let mut rng = ark_std::rand::thread_rng();
        let mpc = MockMpcNetwork::new(4, 7, MockProofBackend);

        // Client: hash user ID and blind
        let g_id = hash_to_curve(test_user_id_hash(b"alice@example.com")).point;
        let r = Fr::rand(&mut rng);
        let blinded = blind(g_id, r);

        // MPC: evaluate all nodes
        let request = test_request(g_id, blinded);
        let evals = mpc.evaluate(&request);

        // Client: pick threshold-many partials and aggregate
        let partials: Vec<(usize, G1Affine)> = evals[..mpc.t]
            .iter()
            .map(|e| (e.node_index, e.partial))
            .collect();
        let aggregated = aggregate(&partials);

        // Client: unblind
        let result = unblind(aggregated, r);

        // Verify: result should equal mpc_secret * g_id
        // We can check by doing the same with all n nodes
        let all_partials: Vec<(usize, G1Affine)> =
            evals.iter().map(|e| (e.node_index, e.partial)).collect();
        let agg_all = aggregate(&all_partials);
        let result_all = unblind(agg_all, r);

        assert_eq!(result, result_all);
    }

    #[test]
    fn test_dleq_proofs_verify() {
        let mpc = MockMpcNetwork::new(3, 5, MockProofBackend);
        let g_id = hash_to_curve(test_user_id_hash(b"test-user")).point;
        let blinded = blind(g_id, Fr::from(7u64));

        let request = test_request(g_id, blinded);
        let evals = mpc.evaluate(&request);
        for eval in &evals {
            let node_pk = mpc.node_public_key(eval.node_index);
            assert!(
                verify_dleq(node_pk, blinded, eval.partial, &eval.proof),
                "DLEQ verification failed for node {}",
                eval.node_index
            );
        }
    }

    #[test]
    fn test_different_subsets_same_result() {
        let mut rng = ark_std::rand::thread_rng();
        let mpc = MockMpcNetwork::new(3, 5, MockProofBackend);
        let g_id = hash_to_curve(test_user_id_hash(b"bob@example.com")).point;
        let r = Fr::rand(&mut rng);
        let blinded = blind(g_id, r);

        let request = test_request(g_id, blinded);
        let evals = mpc.evaluate(&request);

        // Subset 1: nodes 1,2,3
        let p1: Vec<(usize, G1Affine)> = evals[..3]
            .iter()
            .map(|e| (e.node_index, e.partial))
            .collect();
        let r1 = unblind(aggregate(&p1), r);

        // Subset 2: nodes 3,4,5
        let p2: Vec<(usize, G1Affine)> = evals[2..5]
            .iter()
            .map(|e| (e.node_index, e.partial))
            .collect();
        let r2 = unblind(aggregate(&p2), r);

        assert_eq!(r1, r2);
    }
}

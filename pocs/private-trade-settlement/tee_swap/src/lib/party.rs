use alloy::primitives::B256;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_grumpkin::{Fr as GrumpkinScalar, Projective};

use crate::crypto::poseidon::{bind_enc, bind_meta, bind_r, bind_swap};
use crate::crypto::salt::{decrypt_salt, encrypt_salt};
use crate::crypto::stealth::{
    affine_x_to_b256, derive_stealth_pubkey, derive_stealth_secret, ecdh_shared_secret_x,
    scalar_to_lo_hi,
};
use crate::domain::merkle::{CommitmentMerkleProof, MAX_COMMITMENT_TREE_DEPTH};
use crate::domain::note::Note;
use crate::domain::stealth::{EphemeralKeyPair, MetaKeyPair};
use crate::domain::swap::{PartySubmission, SwapAnnouncement, SwapTerms};
use crate::ports::TransferWitness;

/// Which side of the swap this party is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartyRole {
    /// Party A: locks value_a/asset_id_a on chain_id_a
    A,
    /// Party B: locks value_b/asset_id_b on chain_id_b
    B,
}

/// Output of `prepare_lock`: everything needed to submit to chain and TEE.
pub struct LockOutput {
    /// The locked note created for the counterparty
    pub locked_note: Note,
    /// Full witness for proof generation
    pub witness: TransferWitness,
    /// Submission to send to the TEE
    pub submission: PartySubmission,
    /// Ephemeral key pair (caller keeps this for the demo; r_pub shared via TEE)
    pub ephemeral_keypair: EphemeralKeyPair,
}

/// Output of `prepare_claim`: everything needed to submit to chain.
pub struct ClaimOutput {
    /// Fresh output note (timeout=0, standard)
    pub output_note: Note,
    /// Full witness for proof generation
    pub witness: TransferWitness,
}

/// Output of `prepare_refund`: everything needed to submit to chain.
pub struct RefundOutput {
    /// Fresh output note (timeout=0, standard)
    pub output_note: Note,
    /// Full witness for proof generation
    pub witness: TransferWitness,
}

/// Prepare a lock transaction: spend an existing note and create a time-locked note
/// for the counterparty with a stealth address.
///
/// This implements Phase 1 of the swap protocol from the party's perspective.
pub fn prepare_lock(
    swap_terms: &SwapTerms,
    own_meta_key: &MetaKeyPair,
    counterparty_pk_meta: &Projective,
    input_note: &Note,
    merkle_proof: &CommitmentMerkleProof,
    merkle_root: B256,
) -> LockOutput {
    let mut rng = rand::thread_rng();

    // 1. Generate ephemeral key pair
    let ephemeral = EphemeralKeyPair::generate(&mut rng);

    // 2. Derive stealth pubkey for counterparty
    let (pk_stealth, _stealth_scalar) =
        derive_stealth_pubkey(counterparty_pk_meta, &ephemeral.r);
    let pk_stealth_x = affine_x_to_b256(&pk_stealth);

    // 3. Create locked output note
    let locked_note = Note::new(
        input_note.chain_id,
        input_note.value,
        input_note.asset_id,
        pk_stealth_x,            // owner = stealth address
        own_meta_key.pk_x(),     // fallback_owner = our key (for refund)
        swap_terms.timeout,
    );

    // 4. Compute ECDH shared secret and encrypt salt
    let shared_x = ecdh_shared_secret_x(counterparty_pk_meta, &ephemeral.r);
    let encrypted_salt = encrypt_salt(locked_note.salt, shared_x);

    // 5. Compute binding commitments
    let h_swap = bind_swap(swap_terms.swap_id, locked_note.salt);
    let h_r = bind_r(ephemeral.r_pub_x());
    let h_meta = bind_meta(affine_x_to_b256(&counterparty_pk_meta.into_affine()), locked_note.salt);
    let h_enc = bind_enc(encrypted_salt);

    // 6. Split keys into lo/hi limbs for circuit witness
    let (sk_lo, sk_hi) = scalar_to_lo_hi(&own_meta_key.sk);
    let (r_lo, r_hi) = scalar_to_lo_hi(&ephemeral.r);

    // 7. Pad merkle proof to MAX_TREE_DEPTH
    let (path_elements, path_indices) = pad_merkle_proof(merkle_proof);

    // 8. Compute nullifier and output commitment
    let nullifier = input_note.nullifier();
    let output_commitment = locked_note.commitment();

    // 9. Build TransferWitness (lock mode)
    let witness = TransferWitness {
        // Public inputs
        nullifier: nullifier.0,
        root: merkle_root,
        new_commitment: output_commitment.0,
        timeout: locked_note.timeout, // lock mode: output timeout
        pk_stealth: pk_stealth_x,
        h_swap,
        h_r,
        h_meta,
        h_enc,

        // Private: input note
        sk_lo,
        sk_hi,
        in_chain_id: input_note.chain_id,
        in_value: input_note.value,
        in_asset_id: input_note.asset_id,
        in_owner: input_note.owner,
        in_fallback_owner: input_note.fallback_owner,
        in_timeout: input_note.timeout,
        in_salt: input_note.salt,
        proof_length: merkle_proof.proof_length as u32,
        path_elements,
        path_indices,

        // Private: output note
        out_chain_id: locked_note.chain_id,
        out_value: locked_note.value,
        out_asset_id: locked_note.asset_id,
        out_owner: locked_note.owner,
        out_fallback_owner: locked_note.fallback_owner,
        out_timeout: locked_note.timeout,
        out_salt: locked_note.salt,

        // Private: lock-mode extras
        swap_id: swap_terms.swap_id,
        r_lo,
        r_hi,
        pk_meta_x: affine_x_to_b256(&counterparty_pk_meta.into_affine()),
        pk_meta_y: {
            let affine = counterparty_pk_meta.into_affine();
            crate::crypto::stealth::affine_y_to_b256(&affine)
        },
        encrypted_salt,
    };

    // 10. Build PartySubmission for TEE
    let submission = PartySubmission {
        swap_id: swap_terms.swap_id,
        nonce: swap_terms.nonce,
        ephemeral_pubkey: ephemeral.r_pub_x(),
        encrypted_salt,
        note_details: locked_note.clone(),
    };

    LockOutput {
        locked_note,
        witness,
        submission,
        ephemeral_keypair: ephemeral,
    }
}

/// Prepare a claim transaction: spend a locked note using the stealth key
/// derived from the TEE announcement.
///
/// This implements Phase 4 (claim path) of the swap protocol.
pub fn prepare_claim(
    announcement: &SwapAnnouncement,
    own_meta_key: &MetaKeyPair,
    counterparty_r_pub: &Projective,
    swap_terms: &SwapTerms,
    role: PartyRole,
    merkle_proof: &CommitmentMerkleProof,
    merkle_root: B256,
) -> ClaimOutput {
    // 1. Select the right parameters based on role
    let (encrypted_salt_value, locked_chain_id, locked_value, locked_asset_id, fallback_owner_x) =
        match role {
            PartyRole::A => {
                // A claims B's note (locked on chain_b with value_b/asset_b)
                (
                    announcement.encrypted_salt_b,
                    swap_terms.chain_id_b,
                    swap_terms.value_b,
                    swap_terms.asset_id_b,
                    swap_terms.pk_meta_b,
                )
            }
            PartyRole::B => {
                // B claims A's note (locked on chain_a with value_a/asset_a)
                (
                    announcement.encrypted_salt_a,
                    swap_terms.chain_id_a,
                    swap_terms.value_a,
                    swap_terms.asset_id_a,
                    swap_terms.pk_meta_a,
                )
            }
        };

    // 2. Compute ECDH shared secret: sk_meta · R_counterparty
    let shared_x = ecdh_shared_secret_x(counterparty_r_pub, &own_meta_key.sk);

    // 3. Decrypt salt
    let decrypted_salt = decrypt_salt(encrypted_salt_value, shared_x);

    // 4. Derive stealth secret key
    let sk_stealth = derive_stealth_secret(&own_meta_key.sk, counterparty_r_pub);

    // 5. Compute pk_stealth (to reconstruct the locked note's owner field)
    let pk_stealth = (Projective::generator() * sk_stealth).into_affine();
    let pk_stealth_x = affine_x_to_b256(&pk_stealth);

    // 6. Reconstruct the locked note
    let locked_note = Note::with_salt(
        locked_chain_id,
        locked_value,
        locked_asset_id,
        pk_stealth_x,    // owner = our stealth address
        fallback_owner_x, // fallback = counterparty's meta pk
        swap_terms.timeout,
        decrypted_salt,
    );

    // 7. Create fresh output note (standard, timeout=0)
    let output_note = Note::new(
        locked_note.chain_id,
        locked_note.value,
        locked_note.asset_id,
        own_meta_key.pk_x(), // owner = our meta pk (standard note)
        B256::ZERO,          // no fallback needed
        B256::ZERO,          // timeout = 0 (standard note)
    );

    // 8. Split stealth key into lo/hi
    let (sk_lo, sk_hi) = scalar_to_lo_hi(&sk_stealth);

    // 9. Pad merkle proof
    let (path_elements, path_indices) = pad_merkle_proof(merkle_proof);

    // 10. Compute commitments and nullifier
    let nullifier = locked_note.nullifier();
    let output_commitment = output_note.commitment();

    // 11. Build TransferWitness (claim mode: pk_stealth = in_owner, h_swap = 0)
    let witness = TransferWitness {
        // Public inputs
        nullifier: nullifier.0,
        root: merkle_root,
        new_commitment: output_commitment.0,
        timeout: locked_note.timeout, // claim mode: input timeout
        pk_stealth: locked_note.owner, // claim: pk_stealth = in_owner
        h_swap: B256::ZERO,
        h_r: B256::ZERO,
        h_meta: B256::ZERO,
        h_enc: B256::ZERO,

        // Private: input note (the locked note we're claiming)
        sk_lo,
        sk_hi,
        in_chain_id: locked_note.chain_id,
        in_value: locked_note.value,
        in_asset_id: locked_note.asset_id,
        in_owner: locked_note.owner,
        in_fallback_owner: locked_note.fallback_owner,
        in_timeout: locked_note.timeout,
        in_salt: locked_note.salt,
        proof_length: merkle_proof.proof_length as u32,
        path_elements,
        path_indices,

        // Private: output note
        out_chain_id: output_note.chain_id,
        out_value: output_note.value,
        out_asset_id: output_note.asset_id,
        out_owner: output_note.owner,
        out_fallback_owner: output_note.fallback_owner,
        out_timeout: output_note.timeout,
        out_salt: output_note.salt,

        // Private: lock-mode extras (all zero in spend mode)
        swap_id: B256::ZERO,
        r_lo: B256::ZERO,
        r_hi: B256::ZERO,
        pk_meta_x: B256::ZERO,
        pk_meta_y: B256::ZERO,
        encrypted_salt: B256::ZERO,
    };

    ClaimOutput {
        output_note,
        witness,
    }
}

/// Prepare a refund transaction: reclaim a locked note after timeout using
/// the fallback owner key.
///
/// This implements Phase 4 (refund path) of the swap protocol.
pub fn prepare_refund(
    locked_note: &Note,
    own_sk: &GrumpkinScalar,
    merkle_proof: &CommitmentMerkleProof,
    merkle_root: B256,
) -> RefundOutput {
    // 1. Create fresh output note (standard, timeout=0)
    //    Owner = our key (same as locked note's fallback_owner)
    let output_note = Note::new(
        locked_note.chain_id,
        locked_note.value,
        locked_note.asset_id,
        locked_note.fallback_owner, // owner = our pk (was fallback)
        B256::ZERO,                 // no fallback needed
        B256::ZERO,                 // timeout = 0 (standard note)
    );

    // 2. Split spending key into lo/hi
    let (sk_lo, sk_hi) = scalar_to_lo_hi(own_sk);

    // 3. Pad merkle proof
    let (path_elements, path_indices) = pad_merkle_proof(merkle_proof);

    // 4. Compute nullifier and output commitment
    let nullifier = locked_note.nullifier();
    let output_commitment = output_note.commitment();

    // 5. Build TransferWitness (refund mode: pk_stealth = 0, timeout = in_timeout)
    let witness = TransferWitness {
        // Public inputs
        nullifier: nullifier.0,
        root: merkle_root,
        new_commitment: output_commitment.0,
        timeout: locked_note.timeout, // refund mode: input timeout
        pk_stealth: B256::ZERO,       // refund: pk_stealth = 0
        h_swap: B256::ZERO,
        h_r: B256::ZERO,
        h_meta: B256::ZERO,
        h_enc: B256::ZERO,

        // Private: input note (the locked note we're refunding)
        sk_lo,
        sk_hi,
        in_chain_id: locked_note.chain_id,
        in_value: locked_note.value,
        in_asset_id: locked_note.asset_id,
        in_owner: locked_note.owner,
        in_fallback_owner: locked_note.fallback_owner,
        in_timeout: locked_note.timeout,
        in_salt: locked_note.salt,
        proof_length: merkle_proof.proof_length as u32,
        path_elements,
        path_indices,

        // Private: output note
        out_chain_id: output_note.chain_id,
        out_value: output_note.value,
        out_asset_id: output_note.asset_id,
        out_owner: output_note.owner,
        out_fallback_owner: output_note.fallback_owner,
        out_timeout: output_note.timeout,
        out_salt: output_note.salt,

        // Private: lock-mode extras (all zero in spend mode)
        swap_id: B256::ZERO,
        r_lo: B256::ZERO,
        r_hi: B256::ZERO,
        pk_meta_x: B256::ZERO,
        pk_meta_y: B256::ZERO,
        encrypted_salt: B256::ZERO,
    };

    RefundOutput {
        output_note,
        witness,
    }
}

/// Pad a merkle proof's path and indices to MAX_COMMITMENT_TREE_DEPTH (32).
fn pad_merkle_proof(proof: &CommitmentMerkleProof) -> (Vec<B256>, Vec<u8>) {
    let mut path_elements = proof.path.clone();
    path_elements.resize(MAX_COMMITMENT_TREE_DEPTH, B256::ZERO);

    let mut path_indices = proof.indices.clone();
    path_indices.resize(MAX_COMMITMENT_TREE_DEPTH, 0);

    (path_elements, path_indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::merkle_tree::LocalMerkleTree;
    use crate::crypto::poseidon::{bind_enc, bind_meta, bind_r, bind_swap};
    use crate::crypto::stealth::affine_x_to_b256;
    use ark_ec::CurveGroup;

    /// Create a funded note for a party and insert it into the tree.
    /// Returns (note, leaf_index).
    fn fund_note(
        tree: &mut LocalMerkleTree,
        chain_id: B256,
        value: u64,
        asset_id: B256,
        owner_pk_x: B256,
    ) -> (Note, u64) {
        let note = Note::new(
            chain_id,
            value,
            asset_id,
            owner_pk_x,
            B256::ZERO, // no fallback for standard notes
            B256::ZERO, // timeout = 0 (standard note)
        );
        let leaf_index = tree.len() as u64;
        tree.insert_commitment(&note.commitment());
        (note, leaf_index)
    }

    fn test_swap_terms(pk_meta_a: B256, pk_meta_b: B256) -> SwapTerms {
        SwapTerms::new(
            B256::left_padding_from(&[1]), // chain_id_a
            B256::left_padding_from(&[2]), // chain_id_b
            1000,                           // value_a (USD)
            50,                             // value_b (BOND)
            B256::repeat_byte(0x01),        // asset_id_a (USD)
            B256::repeat_byte(0x02),        // asset_id_b (BOND)
            B256::left_padding_from(&[0x00, 0x01, 0x51, 0x80]), // timeout (~24h)
            pk_meta_a,
            pk_meta_b,
            B256::repeat_byte(0xFF), // nonce
        )
    }

    #[test]
    fn test_prepare_lock_produces_valid_witness() {
        let mut rng = ark_std::test_rng();
        let meta_a = MetaKeyPair::generate(&mut rng);
        let meta_b = MetaKeyPair::generate(&mut rng);
        let terms = test_swap_terms(meta_a.pk_x(), meta_b.pk_x());

        // Fund Party A
        let mut tree_a = LocalMerkleTree::new();
        let (input_note, leaf_idx) = fund_note(
            &mut tree_a,
            terms.chain_id_a,
            terms.value_a,
            terms.asset_id_a,
            meta_a.pk_x(),
        );
        let proof = tree_a.generate_proof(leaf_idx).unwrap();
        let root = tree_a.current_root().unwrap();

        // Lock
        let lock_output = prepare_lock(
            &terms,
            &meta_a,
            &meta_b.pk.into(),
            &input_note,
            &proof,
            root,
        );

        // Verify witness public inputs
        assert_eq!(lock_output.witness.nullifier, input_note.nullifier().0);
        assert_eq!(lock_output.witness.root, root);
        assert_eq!(
            lock_output.witness.new_commitment,
            lock_output.locked_note.commitment().0
        );
        assert_ne!(lock_output.witness.pk_stealth, B256::ZERO); // stealth addr set
        assert_ne!(lock_output.witness.h_swap, B256::ZERO); // binding set
        assert_ne!(lock_output.witness.h_r, B256::ZERO);
        assert_ne!(lock_output.witness.h_meta, B256::ZERO);
        assert_ne!(lock_output.witness.h_enc, B256::ZERO);

        // Verify locked note structure
        assert_eq!(lock_output.locked_note.chain_id, input_note.chain_id);
        assert_eq!(lock_output.locked_note.value, input_note.value);
        assert_eq!(lock_output.locked_note.asset_id, input_note.asset_id);
        assert_eq!(lock_output.locked_note.fallback_owner, meta_a.pk_x());
        assert_eq!(lock_output.locked_note.timeout, terms.timeout);
    }

    #[test]
    fn test_prepare_lock_stealth_address_correctness() {
        let mut rng = ark_std::test_rng();
        let meta_a = MetaKeyPair::generate(&mut rng);
        let meta_b = MetaKeyPair::generate(&mut rng);
        let terms = test_swap_terms(meta_a.pk_x(), meta_b.pk_x());

        let mut tree = LocalMerkleTree::new();
        let (input_note, leaf_idx) = fund_note(
            &mut tree,
            terms.chain_id_a,
            terms.value_a,
            terms.asset_id_a,
            meta_a.pk_x(),
        );
        let proof = tree.generate_proof(leaf_idx).unwrap();
        let root = tree.current_root().unwrap();

        let lock_output = prepare_lock(
            &terms,
            &meta_a,
            &meta_b.pk.into(),
            &input_note,
            &proof,
            root,
        );

        // Party B should be able to derive the stealth secret key
        let sk_stealth_b =
            derive_stealth_secret(&meta_b.sk, &lock_output.ephemeral_keypair.r_pub.into());
        let pk_derived = (Projective::generator() * sk_stealth_b).into_affine();

        // The derived pk should match the locked note's owner
        assert_eq!(
            affine_x_to_b256(&pk_derived),
            lock_output.locked_note.owner,
            "Stealth key derivation roundtrip failed"
        );
    }

    #[test]
    fn test_prepare_lock_binding_commitments() {
        let mut rng = ark_std::test_rng();
        let meta_a = MetaKeyPair::generate(&mut rng);
        let meta_b = MetaKeyPair::generate(&mut rng);
        let terms = test_swap_terms(meta_a.pk_x(), meta_b.pk_x());

        let mut tree = LocalMerkleTree::new();
        let (input_note, leaf_idx) = fund_note(
            &mut tree,
            terms.chain_id_a,
            terms.value_a,
            terms.asset_id_a,
            meta_a.pk_x(),
        );
        let proof = tree.generate_proof(leaf_idx).unwrap();
        let root = tree.current_root().unwrap();

        let lock_output = prepare_lock(
            &terms,
            &meta_a,
            &meta_b.pk.into(),
            &input_note,
            &proof,
            root,
        );

        // Recompute binding commitments independently
        let expected_h_swap = bind_swap(terms.swap_id, lock_output.locked_note.salt);
        let expected_h_r = bind_r(lock_output.ephemeral_keypair.r_pub_x());
        let expected_h_meta = bind_meta(meta_b.pk_x(), lock_output.locked_note.salt);
        let expected_h_enc = bind_enc(lock_output.submission.encrypted_salt);

        assert_eq!(lock_output.witness.h_swap, expected_h_swap);
        assert_eq!(lock_output.witness.h_r, expected_h_r);
        assert_eq!(lock_output.witness.h_meta, expected_h_meta);
        assert_eq!(lock_output.witness.h_enc, expected_h_enc);
    }

    #[test]
    fn test_prepare_claim_roundtrip() {
        let mut rng = ark_std::test_rng();
        let meta_a = MetaKeyPair::generate(&mut rng);
        let meta_b = MetaKeyPair::generate(&mut rng);
        let terms = test_swap_terms(meta_a.pk_x(), meta_b.pk_x());

        // Party A locks for Party B on chain_a
        let mut tree_a = LocalMerkleTree::new();
        let (input_note_a, leaf_idx_a) = fund_note(
            &mut tree_a,
            terms.chain_id_a,
            terms.value_a,
            terms.asset_id_a,
            meta_a.pk_x(),
        );
        let proof_a = tree_a.generate_proof(leaf_idx_a).unwrap();
        let root_a = tree_a.current_root().unwrap();

        let lock_a = prepare_lock(
            &terms,
            &meta_a,
            &meta_b.pk.into(),
            &input_note_a,
            &proof_a,
            root_a,
        );

        // Insert locked note into tree (simulating on-chain insertion)
        tree_a.insert_commitment(&lock_a.locked_note.commitment());
        let locked_leaf_idx = 1u64; // second leaf
        let locked_proof = tree_a.generate_proof(locked_leaf_idx).unwrap();
        let locked_root = tree_a.current_root().unwrap();

        // Simulate TEE announcement
        let announcement = SwapAnnouncement {
            swap_id: terms.swap_id,
            ephemeral_key_a: lock_a.ephemeral_keypair.r_pub_x(),
            ephemeral_key_b: B256::repeat_byte(0x99), // dummy for B's side
            encrypted_salt_a: lock_a.submission.encrypted_salt,
            encrypted_salt_b: B256::repeat_byte(0x88), // dummy
        };

        // Party B claims A's note
        let claim_b = prepare_claim(
            &announcement,
            &meta_b,
            &lock_a.ephemeral_keypair.r_pub.into(),
            &terms,
            PartyRole::B,
            &locked_proof,
            locked_root,
        );

        // Verify claim witness
        assert_eq!(claim_b.witness.nullifier, lock_a.locked_note.nullifier().0);
        assert_eq!(claim_b.witness.root, locked_root);
        assert_eq!(claim_b.witness.timeout, lock_a.locked_note.timeout);
        assert_eq!(claim_b.witness.pk_stealth, lock_a.locked_note.owner); // claim: pk_stealth = in_owner
        assert_eq!(claim_b.witness.h_swap, B256::ZERO); // no bindings in claim mode
        assert_eq!(claim_b.witness.h_r, B256::ZERO);

        // Verify output note is standard
        assert_eq!(claim_b.output_note.timeout, B256::ZERO);
        assert_eq!(claim_b.output_note.owner, meta_b.pk_x());
        assert_eq!(claim_b.output_note.value, terms.value_a);
    }

    #[test]
    fn test_prepare_refund_produces_valid_witness() {
        let mut rng = ark_std::test_rng();
        let meta_a = MetaKeyPair::generate(&mut rng);
        let meta_b = MetaKeyPair::generate(&mut rng);
        let terms = test_swap_terms(meta_a.pk_x(), meta_b.pk_x());

        // Party A locks
        let mut tree = LocalMerkleTree::new();
        let (input_note, leaf_idx) = fund_note(
            &mut tree,
            terms.chain_id_a,
            terms.value_a,
            terms.asset_id_a,
            meta_a.pk_x(),
        );
        let proof = tree.generate_proof(leaf_idx).unwrap();
        let root = tree.current_root().unwrap();

        let lock = prepare_lock(
            &terms,
            &meta_a,
            &meta_b.pk.into(),
            &input_note,
            &proof,
            root,
        );

        // Insert locked note
        tree.insert_commitment(&lock.locked_note.commitment());
        let locked_leaf_idx = 1u64;
        let locked_proof = tree.generate_proof(locked_leaf_idx).unwrap();
        let locked_root = tree.current_root().unwrap();

        // Refund
        let refund = prepare_refund(
            &lock.locked_note,
            &meta_a.sk,
            &locked_proof,
            locked_root,
        );

        // Verify refund witness
        assert_eq!(refund.witness.nullifier, lock.locked_note.nullifier().0);
        assert_eq!(refund.witness.root, locked_root);
        assert_eq!(refund.witness.timeout, lock.locked_note.timeout);
        assert_eq!(refund.witness.pk_stealth, B256::ZERO); // refund: pk_stealth = 0
        assert_eq!(refund.witness.h_swap, B256::ZERO);

        // Verify output note
        assert_eq!(refund.output_note.timeout, B256::ZERO);
        assert_eq!(refund.output_note.owner, meta_a.pk_x()); // refunded back to us
        assert_eq!(refund.output_note.value, terms.value_a);
    }

    #[test]
    fn test_nullifier_same_for_claim_and_refund() {
        let mut rng = ark_std::test_rng();
        let meta_a = MetaKeyPair::generate(&mut rng);
        let meta_b = MetaKeyPair::generate(&mut rng);
        let terms = test_swap_terms(meta_a.pk_x(), meta_b.pk_x());

        // Lock
        let mut tree = LocalMerkleTree::new();
        let (input_note, leaf_idx) = fund_note(
            &mut tree,
            terms.chain_id_a,
            terms.value_a,
            terms.asset_id_a,
            meta_a.pk_x(),
        );
        let proof = tree.generate_proof(leaf_idx).unwrap();
        let root = tree.current_root().unwrap();

        let lock = prepare_lock(
            &terms,
            &meta_a,
            &meta_b.pk.into(),
            &input_note,
            &proof,
            root,
        );

        // Insert locked note
        tree.insert_commitment(&lock.locked_note.commitment());
        let locked_proof = tree.generate_proof(1).unwrap();
        let locked_root = tree.current_root().unwrap();

        // Claim by B
        let announcement = SwapAnnouncement {
            swap_id: terms.swap_id,
            ephemeral_key_a: lock.ephemeral_keypair.r_pub_x(),
            ephemeral_key_b: B256::ZERO,
            encrypted_salt_a: lock.submission.encrypted_salt,
            encrypted_salt_b: B256::ZERO,
        };

        let claim = prepare_claim(
            &announcement,
            &meta_b,
            &lock.ephemeral_keypair.r_pub.into(),
            &terms,
            PartyRole::B,
            &locked_proof,
            locked_root,
        );

        // Refund by A
        let refund = prepare_refund(
            &lock.locked_note,
            &meta_a.sk,
            &locked_proof,
            locked_root,
        );

        // Core security property: same nullifier regardless of path
        assert_eq!(
            claim.witness.nullifier, refund.witness.nullifier,
            "Nullifier must be canonical (same for claim and refund)"
        );
    }
}

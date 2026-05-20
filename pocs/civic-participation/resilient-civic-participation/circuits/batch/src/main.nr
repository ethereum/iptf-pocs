use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use rcp_lib::blob;
use rcp_lib::cmp;
use rcp_lib::hasher;
use rcp_lib::imt;

// Batch SNARK (SPEC section Batch SNARK).
//
// BATCH_SIZE_MAX = 6 in this PoC (the SPEC permits up to 100). Each
// position recursively verifies one signer UltraHonk proof against a
// pinned signer verification key, then constrains the IMT advance and
// the blob digest binding.
//
// `signer_public_inputs[i]` is `[r_root, petition_id, predicate_hash,
// class_index, class_tag_i, slot, nullifier_i, identity_tag_i]` per
// SPEC section Signer SNARK. The batch circuit re-uses these public
// inputs as the per-position witness for IMT inserts and blob digest
// recomputation.

global N_SIGNER_PUB: u32 = 8;
global BATCH_SIZE: u32 = 6;
global IMT_DEPTH: u32 = 24;
global FE_PER_RECORD: u32 = 4;
// Per-record BLS12-381 field-element decompositions exposed as
// public inputs: `BLS_FIELDS_LEN = BATCH_SIZE * FE_PER_RECORD`.
global BLS_FIELDS_LEN: u32 = BATCH_SIZE * FE_PER_RECORD;

fn main(
    petition_id: pub Field,
    r_root: pub Field,
    predicate_hash: pub Field,
    class_index: pub Field,
    slot: pub Field,
    prior_running_root: pub Field,
    new_running_root: pub Field,
    prior_identity_tag_set_root: pub Field,
    new_identity_tag_set_root: pub Field,
    prior_leaf_count: pub u32,
    new_leaf_count: pub u32,
    batch_versioned_hash: pub Field,
    // Constraint 8: per-position BLS12-381 field-element decomposition
    // of `(nullifier_i, identity_tag_i, class_tag_i)` per SPEC sectionBlob
    // Payload. The contract verifies each `bls_fields[k]` opens at
    // canonical eval point `omega^k` against `batch_versioned_hash`
    // via the `0x0a` KZG point-evaluation precompile.
    bls_fields: pub [Field; BLS_FIELDS_LEN],
    // Pin signer VK by exposing its hash as a public input. The
    // contract asserts equality with the deploy-pinned
    // `pinnedSignerVkHash` immutable.
    signer_vk_hash: pub Field,
    // Recursive verification of N=BATCH_SIZE signer proofs.
    signer_vk: UltraHonkVerificationKey,
    signer_proofs: [UltraHonkZKProof; BATCH_SIZE],
    signer_public_inputs: [[Field; N_SIGNER_PUB]; BATCH_SIZE],
    // Per-position IMT insert witnesses for the running tree.
    running_imt_low_leaf_indices: [u32; BATCH_SIZE],
    running_imt_low_indices: [[bool; IMT_DEPTH]; BATCH_SIZE],
    running_imt_low_elements: [[Field; IMT_DEPTH]; BATCH_SIZE],
    running_imt_low_values: [Field; BATCH_SIZE],
    running_imt_low_next_indices: [Field; BATCH_SIZE],
    running_imt_low_next_values: [Field; BATCH_SIZE],
    running_imt_new_indices: [[bool; IMT_DEPTH]; BATCH_SIZE],
    running_imt_new_elements: [[Field; IMT_DEPTH]; BATCH_SIZE],
    running_imt_new_low_next_indices: [Field; BATCH_SIZE],
    running_imt_intermediate_roots: [Field; BATCH_SIZE],
    // Per-position IMT insert witnesses for the identity-tag tree.
    idtag_imt_low_leaf_indices: [u32; BATCH_SIZE],
    idtag_imt_low_indices: [[bool; IMT_DEPTH]; BATCH_SIZE],
    idtag_imt_low_elements: [[Field; IMT_DEPTH]; BATCH_SIZE],
    idtag_imt_low_values: [Field; BATCH_SIZE],
    idtag_imt_low_next_indices: [Field; BATCH_SIZE],
    idtag_imt_low_next_values: [Field; BATCH_SIZE],
    idtag_imt_new_indices: [[bool; IMT_DEPTH]; BATCH_SIZE],
    idtag_imt_new_elements: [[Field; IMT_DEPTH]; BATCH_SIZE],
    idtag_imt_new_low_next_indices: [Field; BATCH_SIZE],
    idtag_imt_intermediate_roots: [Field; BATCH_SIZE],
) {
    // Constraint 7: leaf-count advance is fixed-batch in this PoC.
    assert(new_leaf_count == prior_leaf_count + BATCH_SIZE, "batch: leaf_count mismatch");

    let mut prev_running = prior_running_root;
    let mut prev_idtag = prior_identity_tag_set_root;
    let mut prev_leaf: Field = 0;

    for i in 0..BATCH_SIZE {
        // Constraint 2: recursively verify signer SNARK for position i.
        // The public inputs must equal the pinned tuple
        // (r_root, petition_id, predicate_hash, class_index, class_tag_i,
        //  slot, nullifier_i, identity_tag_i).
        assert(signer_public_inputs[i][0] == r_root, "batch: signer pi[0] != r_root");
        assert(signer_public_inputs[i][1] == petition_id, "batch: signer pi[1] != petition_id");
        assert(
            signer_public_inputs[i][2] == predicate_hash,
            "batch: signer pi[2] != predicate_hash",
        );
        assert(signer_public_inputs[i][3] == class_index, "batch: signer pi[3] != class_index");
        assert(signer_public_inputs[i][5] == slot, "batch: signer pi[5] != slot");
        verify_honk_proof(
            signer_vk,
            signer_proofs[i],
            signer_public_inputs[i],
            signer_vk_hash,
        );

        let class_tag_i: Field = signer_public_inputs[i][4];
        let nullifier_i: Field = signer_public_inputs[i][6];
        let identity_tag_i: Field = signer_public_inputs[i][7];

        // class_tag is encoded as u16 BE in the blob (SPEC). Range-check
        // in-circuit so blob decode cannot disambiguate duplicate
        // class_tags via hidden high bits.
        let class_tag_u: u32 = class_tag_i as u32;
        assert(class_tag_u < 65536, "batch: class_tag exceeds u16");

        // Constraint 3 (pairwise nullifier distinctness) is enforced
        // by constraint 4's non-membership against the running IMT;
        // identity-tag pairwise distinctness comes from the idtag IMT
        // non-membership. We additionally enforce intra-batch
        // strictly-increasing leaf ordering below (constraint 5),
        // which subsumes pairwise nullifier distinctness within the
        // batch.

        // Constraint 5: leaf_i = Poseidon1(DOMAIN_LEAF, nullifier_i, class_tag_i)
        // strictly increasing in i.
        let leaf_i = hasher::hash_leaf(nullifier_i, class_tag_i);
        // Reject leaf_0 == 0 (Poseidon-improbable; defensive).
        if i == 0 {
            assert(leaf_i != 0, "batch: leaf_0 == 0");
        }
        if i > 0 {
            let lt = cmp::lt_field(prev_leaf, leaf_i);
            assert(lt, "batch: leaves not strictly increasing");
        }
        prev_leaf = leaf_i;

        // Constraint 4 + 6: running IMT non-membership of nullifier_i,
        // and insertion to advance the root.
        let running_witness = imt::ImtInsertWitness {
            low: imt::ImtLowLeafWitness {
                leaf_index: running_imt_low_leaf_indices[i],
                value: running_imt_low_values[i],
                next_index: running_imt_low_next_indices[i],
                next_value: running_imt_low_next_values[i],
                path_indices: running_imt_low_indices[i],
                path_elements: running_imt_low_elements[i],
            },
            new_low_next_index: running_imt_new_low_next_indices[i],
            new_leaf_path_indices: running_imt_new_indices[i],
            new_leaf_path_elements: running_imt_new_elements[i],
        };
        imt::verify_insert(
            leaf_i,
            prev_running,
            running_imt_intermediate_roots[i],
            prior_leaf_count + (i as u32),
            running_witness,
        );
        prev_running = running_imt_intermediate_roots[i];

        // Constraint 4 + 6: identity-tag IMT non-membership and insertion.
        let idtag_witness = imt::ImtInsertWitness {
            low: imt::ImtLowLeafWitness {
                leaf_index: idtag_imt_low_leaf_indices[i],
                value: idtag_imt_low_values[i],
                next_index: idtag_imt_low_next_indices[i],
                next_value: idtag_imt_low_next_values[i],
                path_indices: idtag_imt_low_indices[i],
                path_elements: idtag_imt_low_elements[i],
            },
            new_low_next_index: idtag_imt_new_low_next_indices[i],
            new_leaf_path_indices: idtag_imt_new_indices[i],
            new_leaf_path_elements: idtag_imt_new_elements[i],
        };
        imt::verify_insert(
            identity_tag_i,
            prev_idtag,
            idtag_imt_intermediate_roots[i],
            prior_leaf_count + (i as u32),
            idtag_witness,
        );
        prev_idtag = idtag_imt_intermediate_roots[i];

        // Constraint 8 (cross-field binding): re-derive the 4 BLS
        // field elements from `(nullifier_i, identity_tag_i, class_tag_i)`
        // per SPEC sectionBlob Payload and constrain equality with the public
        // input. The contract closes the loop with a KZG point
        // evaluation against `batch_versioned_hash`.
        let fields = blob::record_to_fields(nullifier_i, identity_tag_i, class_tag_i);
        assert(bls_fields[i * FE_PER_RECORD + 0] == fields.fe0, "batch: fe0 mismatch");
        assert(bls_fields[i * FE_PER_RECORD + 1] == fields.fe1, "batch: fe1 mismatch");
        assert(bls_fields[i * FE_PER_RECORD + 2] == fields.fe2, "batch: fe2 mismatch");
        assert(bls_fields[i * FE_PER_RECORD + 3] == fields.fe3, "batch: fe3 mismatch");
    }

    assert(prev_running == new_running_root, "batch: new_running_root mismatch");
    assert(prev_idtag == new_identity_tag_set_root, "batch: new_idtag_root mismatch");
    // `batch_versioned_hash` is the EIP-4844 versioned hash. The
    // contract enforces `blobhash(0) == batch_versioned_hash` and, per
    // constraint 8, verifies KZG openings against it at canonical
    // evaluation points `omega^k` whose evaluations equal
    // `bls_fields[k]`.
    let _ = batch_versioned_hash;
}

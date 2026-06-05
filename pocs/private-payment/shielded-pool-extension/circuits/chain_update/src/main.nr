use bb_proof_verification::{UltraHonkVerificationKey, UltraHonkZKProof, verify_honk_proof};
use poseidon::poseidon::bn254::{hash_1, hash_2, hash_3, hash_5};

// Chain-Update Circuit (IVC inner artifact). See ../../SPEC.md "Chain-Update
// Circuit (new)". Produces a per-note ChainProof attesting non-spend from
// `epoch_created` through `epoch_validated_through - 1`, extending it one frozen
// epoch per invocation. The inductive step recursively verifies the prior
// ChainProof; the base case (genesis) skips the recursive verify.

// Depth of the (indexed) frozen nullifier trees. MUST match the off-chain
// `NULLIFIER_TREE_DEPTH` in src/lib/domain/indexed_merkle.rs.
global NULLIFIER_TREE_DEPTH: u32 = 32;

// Public-input count of a ChainProof, in declaration order: [commitment,
// epoch_created, epoch_validated_through, accumulator, fixed_vk_hash].
global CHAIN_PROOF_PUB_LEN: u32 = 5;

// Sorted-low-leaf non-membership of `nullifier` against an indexed-Merkle `root`.
// Mirrors src/lib/domain/indexed_merkle.rs: leaf = hash_3(value, next_value,
// next_index); nodes = hash_2; path bit false = current node is the left child.
// `next_value == 0` denotes +infinity (the current largest leaf).
fn assert_non_membership(
    nullifier: Field,
    root: Field,
    low_value: Field,
    low_next_value: Field,
    low_next_index: Field,
    path_bits: [bool; NULLIFIER_TREE_DEPTH],
    siblings: [Field; NULLIFIER_TREE_DEPTH],
) {
    // low_value < nullifier < low_next_value (next_value 0 = +inf).
    assert(low_value.lt(nullifier), "non-membership: nullifier <= low_value");
    if low_next_value != 0 {
        assert(nullifier.lt(low_next_value), "non-membership: nullifier >= low_next_value");
    }

    // Reconstruct the root from the low leaf and its sibling path.
    let mut node = hash_3([low_value, low_next_value, low_next_index]);
    for i in 0..NULLIFIER_TREE_DEPTH {
        if path_bits[i] {
            node = hash_2([siblings[i], node]);
        } else {
            node = hash_2([node, siblings[i]]);
        }
    }
    assert(node == root, "non-membership: root mismatch");
}

fn main(
    // Public inputs (the ChainProof). Epochs are field-encoded integers.
    commitment: pub Field,
    epoch_created: pub Field,
    epoch_validated_through: pub Field,
    accumulator: pub Field,
    // The chain-update circuit's own VK hash, propagated along the chain and
    // pinned by the spend circuit (closes the self-recursion loop).
    fixed_vk_hash: pub Field,
    // Private inputs.
    is_base_case: bool,
    // Prior ChainProof (recursive witness); ignored in the base case.
    prior_vk: UltraHonkVerificationKey,
    prior_proof: UltraHonkZKProof,
    prior_public_inputs: [Field; CHAIN_PROOF_PUB_LEN],
    // frozenNullifierRoots[epoch_validated_through_prev].
    frozen_root_next: Field,
    // Key + note preimage (commitment and epoch_created are public).
    spending_key: Field,
    token: Field,
    amount: Field,
    salt: Field,
    // Sorted-low-leaf non-membership witness for the phantom nullifier.
    low_value: Field,
    low_next_value: Field,
    low_next_index: Field,
    path_bits: [bool; NULLIFIER_TREE_DEPTH],
    siblings: [Field; NULLIFIER_TREE_DEPTH],
) {
    if is_base_case {
        // Genesis: no prior proof, nothing folded yet.
        assert(epoch_validated_through == epoch_created, "base: evt != epoch_created");
        assert(accumulator == 0, "base: accumulator != 0");
    } else {
        // 1. Recursively verify the prior ChainProof under the propagated VK hash.
        verify_honk_proof(prior_vk, prior_proof, prior_public_inputs, fixed_vk_hash);

        // Prior public inputs (same declaration order as this circuit's).
        let prior_commitment = prior_public_inputs[0];
        let prior_epoch_created = prior_public_inputs[1];
        let evt_prev = prior_public_inputs[2];
        let acc_prev = prior_public_inputs[3];
        let prior_vk_hash = prior_public_inputs[4];

        // 2. The prior proof must be about the same note, under the same VK.
        assert(prior_commitment == commitment, "step: commitment mismatch");
        assert(prior_epoch_created == epoch_created, "step: epoch_created mismatch");
        assert(prior_vk_hash == fixed_vk_hash, "step: vk_hash mismatch");

        // 3. Advance one frozen epoch and fold its root into the accumulator.
        assert(epoch_validated_through == evt_prev + 1, "step: evt must advance by 1");
        assert(accumulator == hash_2([acc_prev, frozen_root_next]), "step: accumulator fold");

        // 4. Key binding: pin spending_key to the public commitment so the
        //    phantom nullifier below is the one that would really be published.
        let owner_pubkey = hash_1([spending_key]);
        assert(
            commitment == hash_5([token, amount, owner_pubkey, salt, epoch_created]),
            "step: commitment preimage mismatch",
        );

        // 5. Phantom nullifier for the just-folded epoch and its non-membership.
        let nullifier = hash_3([commitment, spending_key, evt_prev]);
        assert_non_membership(
            nullifier,
            frozen_root_next,
            low_value,
            low_next_value,
            low_next_index,
            path_bits,
            siblings,
        );
    }
}

// Inductive (recursive) cases require real bb proofs and are exercised by the
// bb-prover harness, not Nargo unit tests. These cover the base-case branch.

#[test]
fn test_base_case_valid() {
    main(
        7, 3, 3, 0, 99, true, [0; 115], [0; 458], [0; 5], 0, 0, 0, 0, 0, 0, 0, 0, [false; 32],
        [0; 32],
    );
}

#[test(should_fail_with = "base: accumulator != 0")]
fn test_base_case_nonzero_accumulator() {
    main(
        7, 3, 3, 1, 99, true, [0; 115], [0; 458], [0; 5], 0, 0, 0, 0, 0, 0, 0, 0, [false; 32],
        [0; 32],
    );
}

#[test(should_fail_with = "base: evt != epoch_created")]
fn test_base_case_advanced_epoch() {
    main(
        7, 3, 4, 0, 99, true, [0; 115], [0; 458], [0; 5], 0, 0, 0, 0, 0, 0, 0, 0, [false; 32],
        [0; 32],
    );
}

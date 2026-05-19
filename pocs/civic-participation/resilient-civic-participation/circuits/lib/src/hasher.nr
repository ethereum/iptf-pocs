use crate::domain;
use poseidon::poseidon::bn254::{hash_2, hash_3, hash_4, hash_5, hash_6};

pub fn hash_merkle_node(left: Field, right: Field) -> Field {
    hash_2([left, right])
}

// `attr_hash = Poseidon1(DOMAIN_ATTR, attr_0..attr_{n-1}, chain_root,
// attr_version, identity_secret)`. For `ATTR_COUNT = 4` the arity is 8.
// Implemented as a nested chain of width-5 hashes that produces a
// single field output. identity_secret pins the RI leaf to a specific
// signer-held secret, defending against s_0 compromise alone.
pub fn hash_attr(
    attrs: [Field; 4],
    chain_root: Field,
    attr_version: Field,
    identity_secret: Field,
) -> Field {
    let h1 = hash_5(
        [domain::DOMAIN_ATTR, attrs[0], attrs[1], attrs[2], attrs[3]],
    );
    hash_4([h1, chain_root, attr_version, identity_secret])
}

// `nullifier = Poseidon1(DOMAIN_NULLIFIER, v_slot, petition_id,
// class_index, class_tag, identity_secret)`. identity_secret binds the
// nullifier to a specific signer secret; combined with hash_attr's
// identity_secret binding (which forces a unique RI leaf per secret),
// this enforces "one signature per RI leaf per petition" even under
// partial key compromise.
pub fn hash_nullifier(
    v_slot: Field,
    petition_id: Field,
    class_index: Field,
    class_tag: Field,
    identity_secret: Field,
) -> Field {
    hash_6(
        [domain::DOMAIN_NULLIFIER, v_slot, petition_id, class_index, class_tag, identity_secret],
    )
}

// `identity_tag = Poseidon1(DOMAIN_IDTAG, v_slot, petition_id)`.
pub fn hash_identity_tag(v_slot: Field, petition_id: Field) -> Field {
    hash_3([domain::DOMAIN_IDTAG, v_slot, petition_id])
}

// `leaf = Poseidon1(DOMAIN_LEAF, nullifier, class_tag)`.
pub fn hash_leaf(nullifier: Field, class_tag: Field) -> Field {
    hash_3([domain::DOMAIN_LEAF, nullifier, class_tag])
}

// `predicate_hash = Poseidon1(DOMAIN_PRED, canonical_predicate_def[..],
// petition_id, salt)`. SPEC section Predicate fixes the canonical
// decomposition at 34 scalars. We absorb in a sponge-style chain:
// start from the domain tag, fold each canonical scalar in, then fold
// petition_id and salt.
pub fn hash_predicate(canonical: [Field; 34], petition_id: Field, salt: Field) -> Field {
    let mut acc = domain::DOMAIN_PRED;
    for i in 0..34 {
        acc = hash_2([acc, canonical[i]]);
    }
    acc = hash_2([acc, petition_id]);
    hash_2([acc, salt])
}

// IMT leaf hash: `H(value || next_index || next_value)` with a trailing
// zero to fix the arity at 4. Domain separation against external 4-input
// Poseidon calls relies on input-space disjointness: `value` is itself a
// Poseidon output (`Poseidon1(DOMAIN_LEAF, nullifier, class_tag)`) for
// running-tree leaves or `identity_tag` (a Poseidon output) for the
// idtag tree, so the input tuple cannot collide with an external call.
pub fn hash_imt_leaf(value: Field, next_index: Field, next_value: Field) -> Field {
    hash_4([value, next_index, next_value, 0])
}

// The hash of the empty IMT leaf `(0, 0, 0)`. Used by `imt::verify_insert`
// to constrain that the new-leaf position was empty in the intermediate
// (post-low-update) root before the new leaf was placed.
pub fn imt_empty_leaf_hash() -> Field {
    hash_imt_leaf(0, 0, 0)
}

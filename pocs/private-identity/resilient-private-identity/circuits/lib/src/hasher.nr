use crate::domain;
use poseidon::poseidon::bn254::{hash_2, hash_3, hash_4, hash_6};

// Merkle node hash: PoseidonT3([left, right]) -- NO domain tag.
// Matches LeanIMT's on-chain PoseidonT3.hash([left, right]) exactly.
pub fn hash_merkle_node(left: Field, right: Field) -> Field {
    hash_2([left, right])
}

// Leaf commitment: H(DOMAIN_LEAF, identity_secret, attr_hash)
pub fn hash_leaf(identity_secret: Field, attr_hash: Field) -> Field {
    hash_3([domain::DOMAIN_LEAF, identity_secret, attr_hash])
}

// Presentation nullifier: H(DOMAIN_NULLIFIER, identity_secret, external_nullifier)
pub fn hash_nullifier(identity_secret: Field, external_nullifier: Field) -> Field {
    hash_3([domain::DOMAIN_NULLIFIER, identity_secret, external_nullifier])
}

// Enrollment nullifier: H(DOMAIN_ENROLLMENT_NULL, raw_nullifier_x, raw_nullifier_y)
pub fn hash_enrollment_nullifier(x: Field, y: Field) -> Field {
    hash_3([domain::DOMAIN_ENROLLMENT_NULL, x, y])
}

// Attribute hash: H(DOMAIN_ATTR, version, attr[0], attr[1], attr[2], attr[3])
pub fn hash_attr(version: Field, attrs: [Field; 4]) -> Field {
    hash_6([domain::DOMAIN_ATTR, version, attrs[0], attrs[1], attrs[2], attrs[3]])
}

// External nullifier: H(DOMAIN_EXTERNAL_NULLIFIER, chain_id, verifier_address, scope)
pub fn hash_external_nullifier(chain_id: Field, verifier_address: Field, scope: Field) -> Field {
    hash_4([domain::DOMAIN_EXTERNAL_NULLIFIER, chain_id, verifier_address, scope])
}

// Name hash: H(DOMAIN_NAME, name_digest)
// WARNING: Same arity (t=3) as hash_merkle_node. Domain separation
// comes from usage context, not different Poseidon parameters.
pub fn hash_name(name_digest: Field) -> Field {
    hash_2([domain::DOMAIN_NAME, name_digest])
}

// Identity-blinding link: H(DOMAIN_LINK, user_id_hash, salt)
pub fn hash_link(user_id_hash: Field, salt: Field) -> Field {
    hash_3([domain::DOMAIN_LINK, user_id_hash, salt])
}

// Hash-to-curve field element: H(DOMAIN_H2C, user_id_hash)
// Used by SVDW hash_to_curve to derive t from user_id_hash.
pub fn hash_h2c(user_id_hash: Field) -> Field {
    hash_2([domain::DOMAIN_H2C, user_id_hash])
}

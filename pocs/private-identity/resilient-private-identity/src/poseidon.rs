use ark_bn254::Fr;
use light_poseidon::{
    Poseidon,
    PoseidonHasher,
};

use crate::types::*;

/// Merkle node: NO domain tag, new_circom(2) -- matches LeanIMT PoseidonT3
pub fn hash_merkle_node(left: Fr, right: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).unwrap();
    h.hash(&[left, right]).unwrap()
}

/// Leaf commitment: H(DOMAIN_LEAF, identity_secret, attr_hash)
pub fn hash_leaf(identity_secret: Fr, attr_hash: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(3).unwrap();
    h.hash(&[Fr::from(DOMAIN_LEAF), identity_secret, attr_hash])
        .unwrap()
}

/// Presentation nullifier: H(DOMAIN_NULLIFIER, identity_secret, external_nullifier)
pub fn hash_nullifier(identity_secret: Fr, external_nullifier: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(3).unwrap();
    h.hash(&[
        Fr::from(DOMAIN_NULLIFIER),
        identity_secret,
        external_nullifier,
    ])
    .unwrap()
}

/// Enrollment nullifier: H(DOMAIN_ENROLLMENT_NULL, x, y)
pub fn hash_enrollment_nullifier(x: Fr, y: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(3).unwrap();
    h.hash(&[Fr::from(DOMAIN_ENROLLMENT_NULL), x, y]).unwrap()
}

/// Attribute hash: H(DOMAIN_ATTR, version, attr[0], attr[1], attr[2], attr[3])
pub fn hash_attr(version: Fr, attrs: &[Fr; 4]) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(6).unwrap();
    h.hash(&[
        Fr::from(DOMAIN_ATTR),
        version,
        attrs[0],
        attrs[1],
        attrs[2],
        attrs[3],
    ])
    .unwrap()
}

/// External nullifier: H(DOMAIN_EXTERNAL_NULLIFIER, chain_id, verifier_address, scope)
pub fn hash_external_nullifier(chain_id: Fr, verifier_address: Fr, scope: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(4).unwrap();
    h.hash(&[
        Fr::from(DOMAIN_EXTERNAL_NULLIFIER),
        chain_id,
        verifier_address,
        scope,
    ])
    .unwrap()
}

/// Name hash: H(DOMAIN_NAME, name_digest)
pub fn hash_name(name_digest: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).unwrap();
    h.hash(&[Fr::from(DOMAIN_NAME), name_digest]).unwrap()
}

/// Identity-blinding link: H(DOMAIN_LINK, user_id_hash, salt)
pub fn hash_link(user_id_hash: Fr, salt: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(3).unwrap();
    h.hash(&[Fr::from(DOMAIN_LINK), user_id_hash, salt])
        .unwrap()
}

/// Hash-to-curve field element: H(DOMAIN_H2C, user_id_hash)
/// Used by SVDW hash_to_curve to derive the field element t from user_id_hash.
pub fn hash_h2c(user_id_hash: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).unwrap();
    h.hash(&[Fr::from(DOMAIN_H2C), user_id_hash]).unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hash_merkle_node_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let h1 = hash_merkle_node(a, b);
        let h2 = hash_merkle_node(a, b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_merkle_node_order_matters() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_ne!(hash_merkle_node(a, b), hash_merkle_node(b, a));
    }

    #[test]
    fn test_hash_leaf_deterministic() {
        let secret = Fr::from(42u64);
        let attr_hash = Fr::from(99u64);
        let h1 = hash_leaf(secret, attr_hash);
        let h2 = hash_leaf(secret, attr_hash);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_domain_separation() {
        // hash_leaf and hash_nullifier with same inputs should differ due to domain tags
        let a = Fr::from(10u64);
        let b = Fr::from(20u64);
        let leaf = hash_leaf(a, b);
        let null = hash_nullifier(a, b);
        assert_ne!(leaf, null);
    }

    #[test]
    fn test_hash_attr() {
        let version = Fr::from(1u64);
        let attrs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let h1 = hash_attr(version, &attrs);
        let h2 = hash_attr(version, &attrs);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_external_nullifier() {
        let chain_id = Fr::from(1u64);
        let verifier = Fr::from(0xDEADu64);
        let scope = Fr::from(42u64);
        let h = hash_external_nullifier(chain_id, verifier, scope);
        assert_ne!(h, Fr::from(0u64));
    }

    #[test]
    fn test_hash_name() {
        let digest = Fr::from(12345u64);
        let h = hash_name(digest);
        assert_ne!(h, Fr::from(0u64));
    }

    #[test]
    fn test_hash_link() {
        let user_id = Fr::from(111u64);
        let salt = Fr::from(222u64);
        let h = hash_link(user_id, salt);
        assert_ne!(h, Fr::from(0u64));
    }

    #[test]
    fn test_hash_enrollment_nullifier() {
        let x = Fr::from(7u64);
        let y = Fr::from(13u64);
        let h = hash_enrollment_nullifier(x, y);
        assert_ne!(h, Fr::from(0u64));
    }

    #[test]
    fn test_hash_h2c() {
        let user_id = Fr::from(42u64);
        let h1 = hash_h2c(user_id);
        let h2 = hash_h2c(user_id);
        assert_eq!(h1, h2, "hash_h2c must be deterministic");
        assert_ne!(h1, Fr::from(0u64));
        // Different inputs give different outputs
        assert_ne!(hash_h2c(Fr::from(1u64)), hash_h2c(Fr::from(2u64)));
    }
}

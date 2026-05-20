//! Poseidon1 hashing primitives (SPEC Primitives).

use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};
use light_poseidon::{
    Poseidon,
    PoseidonHasher,
};
/// Decode a 32-byte big-endian buffer into an Fr.
pub fn fr_from_be_bytes(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

/// Encode an Fr into 32 bytes, big-endian.
pub fn fr_to_be_bytes(fr: &Fr) -> [u8; 32] {
    let be = fr.into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// Width-2 Poseidon1; merkle nodes use this without a domain tag.
pub fn poseidon2(a: Fr, b: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(2).expect("circom-2");
    h.hash(&[a, b]).expect("poseidon2")
}

pub fn poseidon3(a: Fr, b: Fr, c: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(3).expect("circom-3");
    h.hash(&[a, b, c]).expect("poseidon3")
}

pub fn poseidon4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(4).expect("circom-4");
    h.hash(&[a, b, c, d]).expect("poseidon4")
}

pub fn poseidon5(inputs: [Fr; 5]) -> Fr {
    let mut h = Poseidon::<Fr>::new_circom(5).expect("circom-5");
    h.hash(&inputs).expect("poseidon5")
}

/// Variable-width hash for `2..=12` inputs.
pub fn poseidon_n(inputs: &[Fr]) -> Fr {
    let n = inputs.len();
    assert!(
        (2..=12).contains(&n),
        "poseidon_n: width must be 2..=12, got {n}"
    );
    let mut h = Poseidon::<Fr>::new_circom(n).expect("circom-n");
    h.hash(inputs).expect("poseidon_n")
}

/// Poseidon1 sponge: rate 4, capacity 1, `t = 5`, 0x80-prefixed padding.
pub struct Poseidon1Sponge {
    state: [Fr; 5],
}

impl Poseidon1Sponge {
    /// Fresh sponge with `domain` absorbed into state[0].
    pub fn with_domain(domain: Fr) -> Self {
        Self {
            state: [
                domain,
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
                Fr::from(0u64),
            ],
        }
    }

    /// Absorb with 0x80-prefixed length-padding to a multiple of `r = 4`.
    pub fn absorb(&mut self, message: &[Fr]) {
        let mut padded: Vec<Fr> = message.to_vec();
        padded.push(Fr::from(0x80u64));
        while !padded.len().is_multiple_of(4) {
            padded.push(Fr::from(0u64));
        }
        for chunk in padded.chunks(4) {
            for (i, &x) in chunk.iter().enumerate() {
                self.state[i + 1] += x;
            }
            self.permute();
        }
    }

    /// Squeeze `n` scalars, re-permuting between each `r = 4` block.
    pub fn squeeze(&mut self, n: usize) -> Vec<Fr> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            for i in 0..4 {
                if out.len() == n {
                    return out;
                }
                out.push(self.state[i + 1]);
            }
            if out.len() < n {
                self.permute();
            }
        }
        out
    }

    fn permute(&mut self) {
        // PoC stand-in: per-position salted width-5 hashes. Production
        // swaps in the canonical `t = 5` round function.
        let snapshot = self.state;
        for i in 0..5 {
            let mut h = Poseidon::<Fr>::new_circom(5).expect("circom-5");
            let mut inputs = snapshot;
            inputs[0] += Fr::from((i as u64) + 1);
            self.state[i] = h.hash(&inputs).expect("permute");
        }
    }
}

// Domain tags as small distinct integers, matching `circuits/lib/src/domain.nr`.
pub fn domain_nullifier() -> Fr {
    Fr::from(1u64)
}
pub fn domain_identity_tag() -> Fr {
    Fr::from(2u64)
}
pub fn domain_leaf() -> Fr {
    Fr::from(3u64)
}
pub fn domain_fsrt_prg() -> Fr {
    Fr::from(4u64)
}
pub fn domain_predicate() -> Fr {
    Fr::from(5u64)
}
pub fn domain_attr() -> Fr {
    Fr::from(6u64)
}
pub fn domain_batch_snark() -> Fr {
    Fr::from(7u64)
}
pub fn domain_petition() -> Fr {
    Fr::from(8u64)
}
pub fn domain_resolution_snark() -> Fr {
    Fr::from(9u64)
}

/// `nullifier = Poseidon1(DOMAIN_NULLIFIER, v_slot, petition_id,
/// class_index, class_tag, identity_secret)`. identity_secret binds the
/// nullifier to a specific signer secret (also bound into attr_hash);
/// this enforces "one signature per RI leaf per petition" even when
/// s_0 is compromised in isolation.
pub fn hash_nullifier(
    v_slot: Fr,
    petition_id: Fr,
    class_index: Fr,
    class_tag: Fr,
    identity_secret: Fr,
) -> Fr {
    poseidon_n(&[
        domain_nullifier(),
        v_slot,
        petition_id,
        class_index,
        class_tag,
        identity_secret,
    ])
}

/// `identity_tag = Poseidon1(DOMAIN_IDTAG, v_slot, petition_id)`.
pub fn hash_identity_tag(v_slot: Fr, petition_id: Fr) -> Fr {
    poseidon3(domain_identity_tag(), v_slot, petition_id)
}

/// `leaf = Poseidon1(DOMAIN_LEAF, nullifier, class_tag)`.
pub fn hash_leaf(nullifier: Fr, class_tag: Fr) -> Fr {
    poseidon3(domain_leaf(), nullifier, class_tag)
}

/// Merkle internal node, no domain tag.
pub fn hash_merkle_node(left: Fr, right: Fr) -> Fr {
    poseidon2(left, right)
}

/// `attr_hash = hash_4(hash_5([DOMAIN_ATTR, attr_0..attr_3]),
/// chain_root, attr_version, identity_secret)`. identity_secret binds
/// the RI leaf to a specific signer-held secret, so an attacker who
/// learns the FSRT seed alone cannot enroll under the same RI leaf.
pub fn hash_attr(
    attr_vector: &[Fr],
    chain_root: Fr,
    attr_version: u32,
    identity_secret: Fr,
) -> Fr {
    assert!(
        attr_vector.len() == 4,
        "hash_attr expects exactly 4 attrs (ATTR_COUNT)"
    );
    let h1 = poseidon5([
        domain_attr(),
        attr_vector[0],
        attr_vector[1],
        attr_vector[2],
        attr_vector[3],
    ]);
    poseidon4(
        h1,
        chain_root,
        Fr::from(attr_version as u64),
        identity_secret,
    )
}

/// Iterated `hash_2` chain over `[DOMAIN_PRED, canonical..., petition_id, salt]`.
pub fn hash_predicate(canonical_predicate_def: &[Fr], petition_id: Fr, salt: Fr) -> Fr {
    let mut acc = domain_predicate();
    for x in canonical_predicate_def {
        acc = poseidon2(acc, *x);
    }
    acc = poseidon2(acc, petition_id);
    poseidon2(acc, salt)
}

/// FSRT PRG step: two width-6 hashes salted by output index 0 and 1.
pub fn fsrt_prg_step(s_i: Fr) -> (Fr, Fr) {
    let v_i = poseidon5([
        domain_fsrt_prg(),
        s_i,
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    ]);
    let s_next = poseidon5([
        domain_fsrt_prg(),
        s_i,
        Fr::from(1u64),
        Fr::from(0u64),
        Fr::from(0u64),
    ]);
    (v_i, s_next)
}

/// `petition_id = keccak256(DOMAIN_PETITION_ID || chain_id || registry || organizer || S || predicate_hash_pre_id || close_at_block)`.
/// Matches `PetitionRegistry._derivePetitionId`: prefix is `keccak256("RCP/petition_id/v1")`,
/// and the top byte of the output is masked so the result fits in BN254 Fr.
pub fn derive_petition_id(
    chain_id: u64,
    registry_address: &[u8; 20],
    organizer: &[u8; 20],
    s_at_registration: u32,
    predicate_hash_pre_id: &[u8; 32],
    close_at_block: u64,
) -> [u8; 32] {
    use sha3::{
        Digest,
        Keccak256,
    };

    let domain = Keccak256::digest(crate::DOMAIN_PETITION);
    let mut h = Keccak256::new();
    h.update(domain);
    h.update(chain_id.to_be_bytes());
    h.update(registry_address);
    h.update(organizer);
    h.update(s_at_registration.to_be_bytes());
    h.update(predicate_hash_pre_id);
    h.update(close_at_block.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out[0] = 0;
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_helpers_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_eq!(poseidon2(a, b), poseidon2(a, b));
        assert_eq!(poseidon3(a, b, a), poseidon3(a, b, a));
        assert_eq!(poseidon5([a, b, a, b, a]), poseidon5([a, b, a, b, a]));
    }

    #[test]
    fn test_poseidon_order_matters() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        assert_ne!(poseidon2(a, b), poseidon2(b, a));
    }

    #[test]
    fn test_fr_be_bytes_roundtrip() {
        let f = Fr::from(123456789u64);
        let be = fr_to_be_bytes(&f);
        assert_eq!(fr_from_be_bytes(&be), f);
    }

    #[test]
    fn test_domain_constants_distinct() {
        let domains: [Fr; 9] = [
            domain_nullifier(),
            domain_identity_tag(),
            domain_leaf(),
            domain_fsrt_prg(),
            domain_predicate(),
            domain_attr(),
            domain_batch_snark(),
            domain_petition(),
            domain_resolution_snark(),
        ];
        for i in 0..domains.len() {
            for j in (i + 1)..domains.len() {
                assert_ne!(
                    domains[i], domains[j],
                    "domain constants {i} and {j} collided"
                );
            }
        }
    }

    #[test]
    fn test_hash_nullifier_and_identity_tag_are_distinct_under_same_inputs() {
        let v = Fr::from(11u64);
        let p = Fr::from(22u64);
        let c_idx = Fr::from(0u64);
        let c_tag = Fr::from(840u64);
        let id_secret = Fr::from(0xc0ffeeu64);
        let n = hash_nullifier(v, p, c_idx, c_tag, id_secret);
        let t = hash_identity_tag(v, p);
        assert_ne!(n, t);
    }

    #[test]
    fn test_hash_leaf_is_deterministic_and_sensitive() {
        let n = Fr::from(7u64);
        let c = Fr::from(42u64);
        let a = hash_leaf(n, c);
        let b = hash_leaf(n, c);
        assert_eq!(a, b);
        let c2 = hash_leaf(n + Fr::from(1u64), c);
        assert_ne!(a, c2);
    }

    #[test]
    fn test_hash_attr_includes_chain_root_and_version() {
        let attrs = [
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let cr = Fr::from(99u64);
        let id_secret = Fr::from(0xc0ffeeu64);
        let h1 = hash_attr(&attrs, cr, 0, id_secret);
        let h2 = hash_attr(&attrs, cr, 1, id_secret);
        assert_ne!(h1, h2);
        let h3 = hash_attr(&attrs, cr + Fr::from(1u64), 0, id_secret);
        assert_ne!(h1, h3);
        let h4 = hash_attr(&attrs, cr, 0, id_secret + Fr::from(1u64));
        assert_ne!(h1, h4);
    }

    #[test]
    fn test_fsrt_prg_step_deterministic_and_two_outputs() {
        let s = Fr::from(0x12345678u64);
        let (a1, b1) = fsrt_prg_step(s);
        let (a2, b2) = fsrt_prg_step(s);
        assert_eq!((a1, b1), (a2, b2));
        assert_ne!(a1, b1);
    }

    #[test]
    fn test_fsrt_prg_step_different_seeds_diverge() {
        let s1 = Fr::from(1u64);
        let s2 = Fr::from(2u64);
        assert_ne!(fsrt_prg_step(s1), fsrt_prg_step(s2));
    }

    #[test]
    fn test_fsrt_prg_second_output_varies_with_seed() {
        let outputs: Vec<Fr> = [1u64, 2, 3, 7, 13, 100, 0x1234]
            .iter()
            .map(|&seed| fsrt_prg_step(Fr::from(seed)).1)
            .collect();
        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(
                    outputs[i], outputs[j],
                    "FSRT PRG produces colliding s_{{i+1}} for distinct s_i"
                );
            }
        }
    }

    #[test]
    fn test_derive_petition_id_changes_with_every_input() {
        let base = derive_petition_id(1, &[0xaa; 20], &[0xbb; 20], 0, &[0xcc; 32], 1000);
        let p2 = derive_petition_id(2, &[0xaa; 20], &[0xbb; 20], 0, &[0xcc; 32], 1000);
        assert_ne!(base, p2);
        let p3 = derive_petition_id(1, &[0xab; 20], &[0xbb; 20], 0, &[0xcc; 32], 1000);
        assert_ne!(base, p3);
        let p4 = derive_petition_id(1, &[0xaa; 20], &[0xbc; 20], 0, &[0xcc; 32], 1000);
        assert_ne!(base, p4);
        let p5 = derive_petition_id(1, &[0xaa; 20], &[0xbb; 20], 1, &[0xcc; 32], 1000);
        assert_ne!(base, p5);
        let p6 = derive_petition_id(1, &[0xaa; 20], &[0xbb; 20], 0, &[0xcd; 32], 1000);
        assert_ne!(base, p6);
        let p7 = derive_petition_id(1, &[0xaa; 20], &[0xbb; 20], 0, &[0xcc; 32], 1001);
        assert_ne!(base, p7);
    }

    #[test]
    fn test_sponge_absorb_one_squeeze_one_distinct_per_input() {
        let mut a = Poseidon1Sponge::with_domain(domain_fsrt_prg());
        a.absorb(&[Fr::from(1u64)]);
        let out_a = a.squeeze(1)[0];

        let mut b = Poseidon1Sponge::with_domain(domain_fsrt_prg());
        b.absorb(&[Fr::from(2u64)]);
        let out_b = b.squeeze(1)[0];

        assert_ne!(out_a, out_b);
    }

    #[test]
    fn test_sponge_domain_changes_output() {
        let mut a = Poseidon1Sponge::with_domain(domain_fsrt_prg());
        a.absorb(&[Fr::from(1u64)]);
        let out_a = a.squeeze(1)[0];

        let mut b = Poseidon1Sponge::with_domain(domain_predicate());
        b.absorb(&[Fr::from(1u64)]);
        let out_b = b.squeeze(1)[0];

        assert_ne!(out_a, out_b);
    }

    #[test]
    fn test_hash_predicate_changes_with_inputs() {
        let canonical = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        let salt_a = Fr::from(10u64);
        let salt_b = Fr::from(11u64);
        let pid = Fr::from(99u64);
        let h_a = hash_predicate(&canonical, pid, salt_a);
        let h_b = hash_predicate(&canonical, pid, salt_b);
        assert_ne!(h_a, h_b);
    }
}

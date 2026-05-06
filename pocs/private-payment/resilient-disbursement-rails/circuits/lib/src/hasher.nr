use crate::domain;
use poseidon::poseidon::bn254::{hash_2, hash_5, hash_6};

pub fn hash_merkle_node(left: Field, right: Field) -> Field {
    hash_2([left, right])
}

pub fn hash_m_packed(m_x_hi: Field, m_x_lo: Field, m_y_hi: Field, m_y_lo: Field) -> Field {
    hash_5([domain::LEAF_DOMAIN_TAG, m_x_hi, m_x_lo, m_y_hi, m_y_lo])
}

pub fn hash_derived_pubkey_packed(
    d_x_hi: Field,
    d_x_lo: Field,
    d_y_hi: Field,
    d_y_lo: Field,
) -> Field {
    hash_5(
        [domain::DERIVED_PUBKEY_DOMAIN_TAG, d_x_hi, d_x_lo, d_y_hi, d_y_lo],
    )
}

pub fn hash_pool_commitment(
    token: Field,
    amount: Field,
    m_packed: Field,
    round_id_packed: Field,
) -> Field {
    hash_5(
        [domain::COMMITMENT_DOMAIN_TAG, token, amount, m_packed, round_id_packed],
    )
}

pub fn hash_claim_nullifier(
    m_packed: Field,
    derived_pubkey_packed: Field,
    round_id_packed: Field,
    claim_contract: Field,
    chain_id_packed: Field,
) -> Field {
    hash_6([
        domain::NULL_DOMAIN_TAG,
        m_packed,
        derived_pubkey_packed,
        round_id_packed,
        claim_contract,
        chain_id_packed,
    ])
}

pub fn pack_round_id(hi: Field, lo: Field) -> Field {
    hash_2([hi, lo])
}

pub fn pack_chain_id(hi: Field, lo: Field) -> Field {
    hash_2([hi, lo])
}

#[test]
fn test_hash_merkle_node_deterministic() {
    let a = hash_merkle_node(1, 2);
    let b = hash_merkle_node(1, 2);
    assert(a == b);
    let c = hash_merkle_node(2, 1);
    assert(a != c);
}

#[test]
fn test_hash_m_packed_deterministic() {
    let a = hash_m_packed(1, 2, 3, 4);
    let b = hash_m_packed(1, 2, 3, 4);
    assert(a == b);
    let c = hash_m_packed(1, 2, 4, 3);
    assert(a != c);
}

#[test]
fn test_domain_separation() {
    let m = hash_m_packed(1, 2, 3, 4);
    let dpk = hash_derived_pubkey_packed(1, 2, 3, 4);
    let r = pack_round_id(7, 8);
    let commit = hash_pool_commitment(0xdead, 1000, m, r);
    let null = hash_claim_nullifier(m, dpk, r, 0xbeef, 0xc0de);
    // m and dpk pack identical limbs but use different domain tags, so they
    // must differ.
    assert(m != dpk);
    // The same inputs through three different domain-tagged hashes
    // must produce three distinct values.
    assert(commit != null);
    assert(commit != m);
    assert(null != m);
}

#[test]
fn test_hash_claim_nullifier_input_sensitivity() {
    let m = hash_m_packed(1, 2, 3, 4);
    let dpk = hash_derived_pubkey_packed(5, 6, 7, 8);
    let r = pack_round_id(9, 10);
    let cc: Field = 0xbeef;
    let cid = pack_chain_id(11, 12);
    let base = hash_claim_nullifier(m, dpk, r, cc, cid);
    // Flipping any one of the five non-tag inputs perturbs the output.
    assert(base != hash_claim_nullifier(hash_m_packed(1, 2, 3, 5), dpk, r, cc, cid));
    assert(base != hash_claim_nullifier(m, hash_derived_pubkey_packed(5, 6, 7, 9), r, cc, cid));
    assert(base != hash_claim_nullifier(m, dpk, pack_round_id(9, 11), cc, cid));
    assert(base != hash_claim_nullifier(m, dpk, r, 0xbef0, cid));
    assert(base != hash_claim_nullifier(m, dpk, r, cc, pack_chain_id(11, 13)));
}

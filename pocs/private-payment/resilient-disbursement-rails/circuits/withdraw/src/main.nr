use rdr_lib::hasher;
use rdr_lib::limbs;
use rdr_lib::merkle;

fn main(
    pool_root: pub Field,
    claim_nullifier: pub Field,
    token: pub Field,
    amount: pub Field,
    recipient: pub Field,
    m_x_hi: Field,
    m_x_lo: Field,
    m_y_hi: Field,
    m_y_lo: Field,
    round_id_hi: Field,
    round_id_lo: Field,
    chain_id_hi: Field,
    chain_id_lo: Field,
    claim_contract: Field,
    proof_length: u32,
    leaf_index_bits: [u1; 32],
    merkle_path: [Field; 32],
) {
    limbs::assert_lt_2_128(m_x_hi);
    limbs::assert_lt_2_128(m_x_lo);
    limbs::assert_lt_2_128(m_y_hi);
    limbs::assert_lt_2_128(m_y_lo);
    limbs::assert_lt_2_128(round_id_hi);
    limbs::assert_lt_2_128(round_id_lo);
    limbs::assert_lt_2_128(chain_id_hi);
    limbs::assert_lt_2_128(chain_id_lo);
    limbs::assert_lt_2_160(claim_contract);
    limbs::assert_lt_2_160(token);
    limbs::assert_lt_2_160(recipient);

    let m_packed = hasher::hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
    let round_id_packed = hasher::pack_round_id(round_id_hi, round_id_lo);
    let chain_id_packed = hasher::pack_chain_id(chain_id_hi, chain_id_lo);

    let commitment = hasher::hash_pool_commitment(token, amount, m_packed, round_id_packed);
    merkle::verify_membership_pool(
        commitment,
        pool_root,
        proof_length,
        leaf_index_bits,
        merkle_path,
    );

    let computed_nullifier =
        hasher::hash_claim_nullifier(m_packed, round_id_packed, claim_contract, chain_id_packed);
    assert(claim_nullifier == computed_nullifier, "claim_nullifier mismatch");
}

#[test]
fn test_withdraw_golden_path() {
    let m_x_hi: Field = 0x0102030405060708090a0b0c0d0e0f10;
    let m_x_lo: Field = 0x1112131415161718191a1b1c1d1e1f20;
    let m_y_hi: Field = 0x2122232425262728292a2b2c2d2e2f30;
    let m_y_lo: Field = 0x3132333435363738393a3b3c3d3e3f40;
    let round_id_hi: Field = 0xa1;
    let round_id_lo: Field = 0xa2;
    let chain_id_hi: Field = 0;
    let chain_id_lo: Field = 1;
    let claim_contract: Field = 0xcafe;
    let token: Field = 0xdead;
    let amount: Field = 1_000_000;
    let recipient: Field = 0xbeef;

    let m_packed = hasher::hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
    let r_packed = hasher::pack_round_id(round_id_hi, round_id_lo);
    let c_packed = hasher::pack_chain_id(chain_id_hi, chain_id_lo);
    let commitment = hasher::hash_pool_commitment(token, amount, m_packed, r_packed);
    let claim_nullifier =
        hasher::hash_claim_nullifier(m_packed, r_packed, claim_contract, c_packed);

    let path: [Field; 32] = [0; 32];
    let bits: [u1; 32] = [0; 32];
    let mut current = commitment;
    for i in 0..32 {
        current = hasher::hash_merkle_node(current, path[i]);
    }
    let pool_root = current;

    main(
        pool_root,
        claim_nullifier,
        token,
        amount,
        recipient,
        m_x_hi,
        m_x_lo,
        m_y_hi,
        m_y_lo,
        round_id_hi,
        round_id_lo,
        chain_id_hi,
        chain_id_lo,
        claim_contract,
        32,
        bits,
        path,
    );
}

#[test(should_fail)]
fn test_withdraw_tampered_path_rejected() {
    let m_x_hi: Field = 1;
    let m_x_lo: Field = 2;
    let m_y_hi: Field = 3;
    let m_y_lo: Field = 4;
    let round_id_hi: Field = 5;
    let round_id_lo: Field = 6;
    let chain_id_hi: Field = 0;
    let chain_id_lo: Field = 1;
    let claim_contract: Field = 0xcafe;
    let token: Field = 0xdead;
    let amount: Field = 100;
    let recipient: Field = 0xbeef;

    let m_packed = hasher::hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
    let r_packed = hasher::pack_round_id(round_id_hi, round_id_lo);
    let c_packed = hasher::pack_chain_id(chain_id_hi, chain_id_lo);
    let commitment = hasher::hash_pool_commitment(token, amount, m_packed, r_packed);
    let claim_nullifier =
        hasher::hash_claim_nullifier(m_packed, r_packed, claim_contract, c_packed);

    let mut path: [Field; 32] = [0; 32];
    let bits: [u1; 32] = [0; 32];
    let mut current = commitment;
    for i in 0..32 {
        current = hasher::hash_merkle_node(current, path[i]);
    }
    let pool_root = current;
    path[7] = 0xCAFEBABE;

    main(
        pool_root,
        claim_nullifier,
        token,
        amount,
        recipient,
        m_x_hi,
        m_x_lo,
        m_y_hi,
        m_y_lo,
        round_id_hi,
        round_id_lo,
        chain_id_hi,
        chain_id_lo,
        claim_contract,
        32,
        bits,
        path,
    );
}

// Cross-card spend rejection: prover witnesses M_B in private inputs but
// the public claim_nullifier comes from M_A. The recompute fails.
#[test(should_fail)]
fn test_withdraw_cross_card_nullifier_rejected() {
    let m_a_x_hi: Field = 0xaa01;
    let m_a_x_lo: Field = 0xaa02;
    let m_a_y_hi: Field = 0xaa03;
    let m_a_y_lo: Field = 0xaa04;
    let m_b_x_hi: Field = 0xbb01;
    let m_b_x_lo: Field = 0xbb02;
    let m_b_y_hi: Field = 0xbb03;
    let m_b_y_lo: Field = 0xbb04;

    let round_id_hi: Field = 7;
    let round_id_lo: Field = 8;
    let chain_id_hi: Field = 0;
    let chain_id_lo: Field = 1;
    let claim_contract: Field = 0xcafe;
    let token: Field = 0xdead;
    let amount: Field = 100;
    let recipient: Field = 0xbeef;

    // Build the pool tree using B's commitment so merkle inclusion passes.
    let m_b_packed = hasher::hash_m_packed(m_b_x_hi, m_b_x_lo, m_b_y_hi, m_b_y_lo);
    let r_packed = hasher::pack_round_id(round_id_hi, round_id_lo);
    let c_packed = hasher::pack_chain_id(chain_id_hi, chain_id_lo);
    let commitment_b = hasher::hash_pool_commitment(token, amount, m_b_packed, r_packed);
    let mut path: [Field; 32] = [0; 32];
    let bits: [u1; 32] = [0; 32];
    let mut current = commitment_b;
    for i in 0..32 {
        current = hasher::hash_merkle_node(current, path[i]);
    }
    let pool_root = current;

    // claim_nullifier is bound to A's claim circuit. Using B's witness must fail.
    let m_a_packed = hasher::hash_m_packed(m_a_x_hi, m_a_x_lo, m_a_y_hi, m_a_y_lo);
    let claim_nullifier =
        hasher::hash_claim_nullifier(m_a_packed, r_packed, claim_contract, c_packed);

    main(
        pool_root,
        claim_nullifier,
        token,
        amount,
        recipient,
        m_b_x_hi,
        m_b_x_lo,
        m_b_y_hi,
        m_b_y_lo,
        round_id_hi,
        round_id_lo,
        chain_id_hi,
        chain_id_lo,
        claim_contract,
        32,
        bits,
        path,
    );
}

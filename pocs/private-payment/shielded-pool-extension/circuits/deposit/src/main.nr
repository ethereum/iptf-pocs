use poseidon::poseidon::bn254::{hash_1, hash_5};

// Poseidon wrapper. Arity MUST match the Rust `crypto::poseidon::poseidon5`;
// see `test_poseidon5_matches_rust`.
fn poseidon5(a: Field, b: Field, c: Field, d: Field, e: Field) -> Field {
    hash_5([a, b, c, d, e])
}

/// Deposit Circuit (extended)
///
/// Proves the commitment is correctly formed from the note components, binding
/// `epoch_created`. `epoch_created` is forced equal to the public
/// `current_epoch_at_deposit` (which the contract sets to its `currentEpoch`)
/// by feeding it directly into the commitment preimage, so a deposit always
/// mints a note tagged with the live epoch.
///
/// Implementation shortcut: the parent's KYC attestation-membership check is
/// intentionally omitted from this circuit. The spec still describes it
/// (unchanged from parent); this is a spec-to-implementation divergence
/// documented in README.md "Implementation shortcuts".
///
/// Public Inputs:
/// - commitment: the note commitment being created
/// - token: ERC-20 token address (lower 160 bits)
/// - amount: deposit amount
/// - current_epoch_at_deposit: contract's `currentEpoch`; bound into the
///   commitment as `epoch_created` (the contract checks it equals `currentEpoch`)
///
/// Private Inputs:
/// - owner_pubkey: depositor's spending public key (poseidon hash of spending_key)
/// - salt: random value for hiding
fn main(
    // Public inputs
    commitment: pub Field,
    token: pub Field,
    amount: pub Field,
    current_epoch_at_deposit: pub u64,
    // Private inputs
    owner_pubkey: Field,
    salt: Field,
) {
    // Verify commitment is correctly formed and binds the deposit epoch.
    // commitment = poseidon5(token, amount, owner_pubkey, salt, epoch_created)
    // with epoch_created == current_epoch_at_deposit.
    let computed_commitment =
        poseidon5(token, amount, owner_pubkey, salt, current_epoch_at_deposit as Field);
    assert(commitment == computed_commitment);
}

#[test]
fn test_deposit_valid() {
    let token = 0x1234567890abcdef1234567890abcdef12345678;
    let amount = 1000;
    let owner_pubkey = hash_1([0xdeadbeef]); // simulated pubkey derivation
    let salt = 0xabcd1234;
    let current_epoch: u64 = 0;

    let commitment = poseidon5(token, amount, owner_pubkey, salt, current_epoch as Field);
    main(commitment, token, amount, current_epoch, owner_pubkey, salt);
}

#[test]
fn test_deposit_nonzero_epoch() {
    // A note deposited after several rollovers binds the live epoch.
    let token = 0x1234567890abcdef1234567890abcdef12345678;
    let amount = 500;
    let owner_pubkey = hash_1([0xbeef]);
    let salt = 0x5678;
    let current_epoch: u64 = 7;

    let commitment = poseidon5(token, amount, owner_pubkey, salt, current_epoch as Field);
    main(commitment, token, amount, current_epoch, owner_pubkey, salt);
}

#[test(should_fail)]
fn test_deposit_invalid_commitment() {
    // Wrong commitment (different salt) must fail.
    let token = 0x1234;
    let amount = 1000;
    let owner_pubkey = hash_1([0xbeef]);
    let salt = 0xabcd;
    let current_epoch: u64 = 0;

    let wrong_commitment = poseidon5(token, amount, owner_pubkey, 0x9999, current_epoch as Field);
    main(wrong_commitment, token, amount, current_epoch, owner_pubkey, salt);
}

#[test(should_fail)]
fn test_deposit_wrong_epoch() {
    // Commitment binds epoch 0 but the contract supplies currentEpoch = 1:
    // the commitment check must fail, enforcing epoch_created == currentEpoch.
    let token = 0x1234;
    let amount = 1000;
    let owner_pubkey = hash_1([0xbeef]);
    let salt = 0xabcd;

    let commitment = poseidon5(token, amount, owner_pubkey, salt, 0);
    main(commitment, token, amount, 1, owner_pubkey, salt);
}

#[test]
fn test_poseidon5_matches_rust() {
    // Cross-implementation vector: MUST equal the Rust crypto::poseidon::poseidon5
    // output for inputs [1,2,3,4,5] (POSEIDON5_12345 in src/lib/crypto/poseidon.rs).
    // This pins the off-chain commitment derivation to the in-circuit one.
    let expected = 0x0dab9449e4a1398a15224c0b15a49d598b2174d305a316c918125f8feeb123c0;
    assert(hash_5([1, 2, 3, 4, 5]) == expected);
}

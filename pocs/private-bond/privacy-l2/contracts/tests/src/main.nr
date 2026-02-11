use aztec::test::helpers::authwit::add_private_authwit_from_call;
use aztec::test::helpers::test_environment::TestEnvironment;

use dvp::DvP;
use private_bonds::PrivateBonds;
use stablecoin::Stablecoin;

fn main() {}

// =============================================================================
// PrivateBonds Tests
// =============================================================================

#[test]
unconstrained fn test_bond_initialize_and_balance() {
    let mut env = TestEnvironment::new();
    let issuer = env.create_light_account();

    let bond_addr = env.deploy("@private_bonds/PrivateBonds").with_private_initializer(
        issuer,
        PrivateBonds::interface().constructor(1_000_000, 0),
    );

    let balance: u128 =
        env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(issuer));
    assert_eq(balance, 1_000_000 as u128);
}

#[test]
unconstrained fn test_bond_whitelist_and_distribute() {
    let mut env = TestEnvironment::new();
    let issuer = env.create_light_account();
    let investor = env.create_light_account();

    let bond_addr = env.deploy("@private_bonds/PrivateBonds").with_private_initializer(
        issuer,
        PrivateBonds::interface().constructor(1_000_000, 0),
    );

    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(investor));
    env.call_private(issuer, PrivateBonds::at(bond_addr).distribute_private(investor, 500_000));

    let issuer_bal: u128 =
        env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(issuer));
    let investor_bal: u128 =
        env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(investor));
    assert_eq(issuer_bal, 500_000 as u128);
    assert_eq(investor_bal, 500_000 as u128);
}

#[test]
unconstrained fn test_bond_transfer_private() {
    let mut env = TestEnvironment::new();
    let issuer = env.create_light_account();
    let alice = env.create_light_account();
    let bob = env.create_light_account();

    let bond_addr = env.deploy("@private_bonds/PrivateBonds").with_private_initializer(
        issuer,
        PrivateBonds::interface().constructor(1_000_000, 0),
    );

    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(alice));
    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(bob));
    env.call_private(issuer, PrivateBonds::at(bond_addr).distribute_private(alice, 500_000));

    env.call_private(alice, PrivateBonds::at(bond_addr).transfer_private(bob, 200_000));

    let alice_bal: u128 =
        env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(alice));
    let bob_bal: u128 = env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(bob));
    assert_eq(alice_bal, 300_000 as u128);
    assert_eq(bob_bal, 200_000 as u128);
}

#[test]
unconstrained fn test_bond_redeem() {
    let mut env = TestEnvironment::new();
    let issuer = env.create_light_account();
    let investor = env.create_light_account();

    // Maturity in the past (timestamp 0) so redeem is immediately available
    let bond_addr = env.deploy("@private_bonds/PrivateBonds").with_private_initializer(
        issuer,
        PrivateBonds::interface().constructor(1_000_000, 0),
    );

    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(investor));
    env.call_private(issuer, PrivateBonds::at(bond_addr).distribute_private(investor, 400_000));

    env.call_private(investor, PrivateBonds::at(bond_addr).redeem(400_000));

    let investor_bal: u128 =
        env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(investor));
    assert_eq(investor_bal, 0 as u128);
}

// =============================================================================
// Stablecoin Tests
// =============================================================================

#[test]
unconstrained fn test_stablecoin_transfer() {
    let mut env = TestEnvironment::new();
    let admin = env.create_light_account();
    let bob = env.create_light_account();

    let stable_addr = env.deploy("@stablecoin/Stablecoin").with_private_initializer(
        admin,
        Stablecoin::interface().constructor(10_000_000),
    );

    env.call_private(admin, Stablecoin::at(stable_addr).transfer_private(bob, 1_000_000));

    let admin_bal: u128 =
        env.simulate_utility(Stablecoin::at(stable_addr).private_balance_of(admin));
    let bob_bal: u128 = env.simulate_utility(Stablecoin::at(stable_addr).private_balance_of(bob));
    assert_eq(admin_bal, 9_000_000 as u128);
    assert_eq(bob_bal, 1_000_000 as u128);
}

#[test]
unconstrained fn test_stablecoin_transfer_from() {
    let mut env = TestEnvironment::new();
    // Contract account needed for authwit support
    let owner = env.create_contract_account();
    let recipient = env.create_light_account();
    let operator = env.create_light_account();

    let stable_addr = env.deploy("@stablecoin/Stablecoin").with_private_initializer(
        owner,
        Stablecoin::interface().constructor(10_000_000),
    );

    // Owner authorizes operator to transfer 500k on their behalf
    let transfer_call = Stablecoin::at(stable_addr).transfer_from(owner, recipient, 500_000, 0);
    add_private_authwit_from_call(env, owner, operator, transfer_call);

    env.call_private(operator, transfer_call);

    let owner_bal: u128 =
        env.simulate_utility(Stablecoin::at(stable_addr).private_balance_of(owner));
    let recipient_bal: u128 =
        env.simulate_utility(Stablecoin::at(stable_addr).private_balance_of(recipient));
    assert_eq(owner_bal, 9_500_000 as u128);
    assert_eq(recipient_bal, 500_000 as u128);
}

// =============================================================================
// DvP Tests
// =============================================================================

#[test]
unconstrained fn test_dvp_atomic_swap() {
    let mut env = TestEnvironment::new();

    let issuer = env.create_light_account();
    // Contract accounts for seller and buyer required for authwit
    let seller = env.create_contract_account();
    let buyer = env.create_contract_account();

    // Deploy bond contract (issuer holds 1M bonds)
    let bond_addr = env.deploy("@private_bonds/PrivateBonds").with_private_initializer(
        issuer,
        PrivateBonds::interface().constructor(1_000_000, 0),
    );

    // Deploy stablecoin (buyer holds 10M stablecoins)
    let stable_addr = env.deploy("@stablecoin/Stablecoin").with_private_initializer(
        buyer,
        Stablecoin::interface().constructor(10_000_000),
    );

    // Deploy DvP coordinator (stateless, no initializer)
    let dvp_addr = env.deploy("@dvp/DvP").without_initializer();

    // Setup: whitelist seller and buyer, distribute bonds to seller
    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(seller));
    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(buyer));
    env.call_private(issuer, PrivateBonds::at(bond_addr).distribute_private(seller, 100_000));

    // Seller authorizes DvP contract to move 100k bonds to buyer
    let bond_transfer_call = PrivateBonds::at(bond_addr).transfer_from(seller, buyer, 100_000, 0);
    add_private_authwit_from_call(env, seller, dvp_addr, bond_transfer_call);

    // Buyer authorizes DvP contract to move 500k stablecoins to seller
    let stable_transfer_call = Stablecoin::at(stable_addr).transfer_from(buyer, seller, 500_000, 0);
    add_private_authwit_from_call(env, buyer, dvp_addr, stable_transfer_call);

    // Execute atomic swap (seller triggers)
    env.call_private(
        seller,
        DvP::at(dvp_addr).execute_swap(
            bond_addr,
            stable_addr,
            seller,
            buyer,
            100_000,
            500_000,
            0,
            0,
        ),
    );

    // Verify post-swap balances
    let seller_bonds: u128 =
        env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(seller));
    let buyer_bonds: u128 =
        env.simulate_utility(PrivateBonds::at(bond_addr).private_balance_of(buyer));
    let seller_stables: u128 =
        env.simulate_utility(Stablecoin::at(stable_addr).private_balance_of(seller));
    let buyer_stables: u128 =
        env.simulate_utility(Stablecoin::at(stable_addr).private_balance_of(buyer));

    assert_eq(seller_bonds, 0 as u128);
    assert_eq(buyer_bonds, 100_000 as u128);
    assert_eq(seller_stables, 500_000 as u128);
    assert_eq(buyer_stables, 9_500_000 as u128);
}

#[test(should_fail)]
unconstrained fn test_dvp_fails_without_authwit() {
    let mut env = TestEnvironment::new();

    let issuer = env.create_light_account();
    let seller = env.create_contract_account();
    let buyer = env.create_contract_account();

    let bond_addr = env.deploy("@private_bonds/PrivateBonds").with_private_initializer(
        issuer,
        PrivateBonds::interface().constructor(1_000_000, 0),
    );

    let stable_addr = env.deploy("@stablecoin/Stablecoin").with_private_initializer(
        buyer,
        Stablecoin::interface().constructor(10_000_000),
    );

    let dvp_addr = env.deploy("@dvp/DvP").without_initializer();

    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(seller));
    env.call_public(issuer, PrivateBonds::at(bond_addr).add_to_whitelist(buyer));
    env.call_private(issuer, PrivateBonds::at(bond_addr).distribute_private(seller, 100_000));

    // No authwits created this should fail
    env.call_private(
        seller,
        DvP::at(dvp_addr).execute_swap(
            bond_addr,
            stable_addr,
            seller,
            buyer,
            100_000,
            500_000,
            0,
            0,
        ),
    );
}

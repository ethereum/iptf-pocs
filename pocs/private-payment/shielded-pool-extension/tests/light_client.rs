//! Light-client root-verification integration test (Slice 3).
//!
//! Spawns anvil, deploys `MockERC20` + mints, then verifies several real storage
//! slots (mixed inclusion + exclusion) through the two-level MPT verifier against
//! the latest block's `stateRoot` — the value Helios supplies (consensus-verified)
//! in production. Demonstrates the on-chain verification half of the light-client
//! check; the consensus verification of the `stateRoot` itself is Helios's job and
//! can't run against anvil (no beacon chain).
//!
//! `#[ignore]` (spawns anvil). Run with:
//!   cargo test --test light_client -- --ignored --nocapture

use alloy::{
    eips::BlockId,
    network::EthereumWallet,
    primitives::{
        Address,
        B256,
        U256,
    },
    providers::{
        Provider,
        ProviderBuilder,
    },
    signers::local::PrivateKeySigner,
    sol,
};
use private_payment_shielded_pool_extension::{
    adapters::light_client::TrustedRootVerifier,
    ports::root_verifier::RootVerifier,
};

sol!(
    #[sol(rpc)]
    MockERC20,
    "contracts/out/MockERC20.sol/MockERC20.json"
);

const DEV_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

#[tokio::test]
#[ignore = "spawns anvil; run with --ignored"]
async fn verifies_real_storage_slots_against_block_state_root() {
    let anvil = alloy::node_bindings::Anvil::new().spawn();
    let signer: PrivateKeySigner = DEV_KEY.parse().unwrap();
    let provider =
        ProviderBuilder::new().wallet(EthereumWallet::from(signer)).connect_http(anvil.endpoint().parse().unwrap());

    // Deploy + mint so storage holds both non-zero (inclusion) and zero
    // (exclusion, unset mapping base) slots.
    let token = *MockERC20::deploy(&provider, "USD Coin".into(), "USDC".into(), 6u8).await.unwrap().address();
    MockERC20::new(token, &provider)
        .mint(Address::repeat_byte(0xAB), U256::from(1_000_000u64))
        .send()
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap();

    // Trust the latest block's stateRoot (in production Helios supplies a
    // consensus-verified one); verification is identical either way.
    let block = provider.get_block(BlockId::latest()).await.unwrap().unwrap();
    let verifier = TrustedRootVerifier::new(block.header.state_root);

    let (mut saw_inclusion, mut saw_exclusion) = (false, false);
    for slot_num in 0u64..5 {
        let slot = B256::from(U256::from(slot_num));
        let stored = provider.get_storage_at(token, U256::from(slot_num)).await.unwrap();
        let proof = provider.get_proof(token, vec![slot]).await.unwrap();

        let verified = verifier.verify_storage(&proof).expect("MPT proof must verify");
        assert_eq!(verified, B256::from(stored), "verified value must equal stored slot {slot_num}");

        if stored.is_zero() {
            saw_exclusion = true;
        } else {
            saw_inclusion = true;
        }
    }
    assert!(saw_inclusion && saw_exclusion, "should exercise both inclusion and exclusion proofs");
}

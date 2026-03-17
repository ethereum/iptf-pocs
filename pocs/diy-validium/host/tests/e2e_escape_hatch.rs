//! End-to-end integration test for the escape hatch (Operation 4).
//!
//! Exercises the full escape hatch flow on Anvil:
//! deploy bridge → deposit → advance time → freeze → escape withdraw → verify
//!
//! Uses mock proofs (MockRiscZeroVerifier) — escape hatch doesn't need ZK proofs.
//!
//! TODO: register escape addresses when front-running protection is tested e2e.
//! The contract now requires msg.sender == escapeAddress[pubkey]. This test deploys
//! with a pre-set root and funds the bridge directly (no deposits), so escape addresses
//! are not populated. Adding raw storage writes via alloy would add complexity for
//! little value — the Foundry tests provide full coverage of front-running protection.
//!
//! ## Running
//!
//! ```bash
//! cd pocs/diy-validium/contracts && forge build
//! cd pocs/diy-validium && RISC0_SKIP_BUILD=1 cargo test --test e2e_escape_hatch -- --nocapture
//! ```

use std::path::PathBuf;

use alloy::{
    network::{EthereumWallet, TransactionBuilder},
    node_bindings::Anvil,
    primitives::{Address, Bytes, FixedBytes, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::TransactionRequest,
    signers::local::PrivateKeySigner,
    sol,
    sol_types::{SolCall, SolValue},
};
use sha2::{Digest, Sha256};

use diy_validium_host::{
    accounts::{Account, AccountStore},
    merkle::account_commitment,
};

// ---------------------------------------------------------------------------
// Solidity ABI definitions
// ---------------------------------------------------------------------------

sol! {
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);

    function deposit(uint256 amount, bytes32 pubkey, bytes calldata membershipSeal) external;
    function stateRoot() external view returns (bytes32);
    function frozen() external view returns (bool);
    function claimed(uint256 leafIndex) external view returns (bool);
    function freeze() external;
    function escapeWithdraw(
        uint256 leafIndex,
        bytes32 pubkey,
        uint64 balance,
        bytes32 salt,
        bytes32[] calldata merkleProof
    ) external;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn contracts_out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("contracts")
        .join("out")
}

fn load_artifact_bytecode(dir_name: &str, json_name: &str) -> Bytes {
    let path = contracts_out_dir()
        .join(dir_name)
        .join(format!("{json_name}.json"));
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read artifact {path:?}: {e}"));
    let artifact: serde_json::Value =
        serde_json::from_str(&raw).expect("Failed to parse artifact JSON");
    let hex_str = artifact["bytecode"]["object"]
        .as_str()
        .expect("Missing bytecode.object in artifact");
    hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))
        .expect("Invalid hex in bytecode")
        .into()
}

async fn deploy(provider: &impl Provider, bytecode: &Bytes, constructor_args: &[u8]) -> Address {
    let mut data = bytecode.to_vec();
    data.extend_from_slice(constructor_args);
    let tx = TransactionRequest::default().with_deploy_code(data);
    provider
        .send_transaction(tx)
        .await
        .expect("deploy: send failed")
        .get_receipt()
        .await
        .expect("deploy: receipt failed")
        .contract_address
        .expect("deploy: no contract address")
}

async fn eth_call(provider: &impl Provider, to: Address, calldata: Vec<u8>) -> Bytes {
    let tx = TransactionRequest::default().to(to).with_input(calldata);
    provider.call(tx).await.expect("eth_call failed")
}

async fn eth_send(provider: &impl Provider, to: Address, calldata: Vec<u8>) {
    let tx = TransactionRequest::default().to(to).with_input(calldata);
    provider
        .send_transaction(tx)
        .await
        .expect("send failed")
        .get_receipt()
        .await
        .expect("receipt failed");
}

/// Convert Rust MerkleProof indices (Vec<bool>) to a leaf index integer.
fn indices_to_leaf_index(indices: &[bool]) -> u64 {
    let mut idx: u64 = 0;
    for (i, &is_right) in indices.iter().enumerate() {
        if is_right {
            idx |= 1 << i;
        }
    }
    idx
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_escape_hatch() {
    let tree_depth = 4;

    // === Off-chain setup ===
    println!("\n=== Setup: accounts + Merkle tree ===");

    let alice_sk = [0xAAu8; 32];
    let alice_pubkey = sha256(&alice_sk);
    let alice_salt = [0x01u8; 32];
    let alice_balance: u64 = 5000;

    let bob_sk = [0xBBu8; 32];
    let bob_pubkey = sha256(&bob_sk);
    let bob_salt = [0x02u8; 32];
    let bob_balance: u64 = 3000;

    let mut store = AccountStore::new();
    let alice_idx = store.add_account(Account {
        pubkey: alice_pubkey,
        balance: alice_balance,
        salt: alice_salt,
    });
    let bob_idx = store.add_account(Account {
        pubkey: bob_pubkey,
        balance: bob_balance,
        salt: bob_salt,
    });

    let tree = store.build_tree(tree_depth);
    let initial_root = tree.root();
    let initial_root_b32 = FixedBytes::from(initial_root);

    let alice_proof = tree.prove(alice_idx);
    let bob_proof = tree.prove(bob_idx);
    let alice_leaf = account_commitment(&alice_pubkey, alice_balance, &alice_salt);
    let bob_leaf = account_commitment(&bob_pubkey, bob_balance, &bob_salt);
    assert!(alice_proof.verify(alice_leaf, initial_root));
    assert!(bob_proof.verify(bob_leaf, initial_root));

    let alice_leaf_index = indices_to_leaf_index(&alice_proof.indices);
    let bob_leaf_index = indices_to_leaf_index(&bob_proof.indices);
    println!("  Alice leaf={alice_leaf_index} balance={alice_balance}");
    println!("  Bob   leaf={bob_leaf_index} balance={bob_balance}");

    // === Deploy on Anvil ===
    println!("\n=== Deploy ===");

    let anvil = Anvil::new().try_spawn().expect("Failed to spawn Anvil");
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let deployer_addr = signer.address();
    let provider = ProviderBuilder::new()
        .wallet(EthereumWallet::from(signer))
        .connect_http(anvil.endpoint_url());

    let mock_verifier_bc = load_artifact_bytecode("ValidiumBridge.t.sol", "MockRiscZeroVerifier");
    let mock_erc20_bc = load_artifact_bytecode("ValidiumBridge.t.sol", "MockERC20");
    let bridge_bc = load_artifact_bytecode("ValidiumBridge.sol", "ValidiumBridge");

    let verifier_addr = deploy(&provider, &mock_verifier_bc, &[]).await;
    let token_addr = deploy(&provider, &mock_erc20_bc, &[]).await;

    let bridge_args = (
        token_addr,
        verifier_addr,
        initial_root_b32,
        FixedBytes::from(alice_pubkey), // allowlist root
        FixedBytes::<32>::ZERO,         // membership image id
        FixedBytes::<32>::ZERO,         // withdrawal image id
        FixedBytes::<32>::ZERO,         // transfer image id
    )
        .abi_encode_params();
    let bridge_addr = deploy(&provider, &bridge_bc, &bridge_args).await;
    println!("  Bridge: {bridge_addr}");

    // === Fund bridge ===
    let total_balance = alice_balance + bob_balance;
    eth_send(
        &provider,
        token_addr,
        mintCall { to: deployer_addr, amount: U256::from(total_balance) }.abi_encode(),
    ).await;
    eth_send(
        &provider,
        token_addr,
        approveCall { spender: bridge_addr, amount: U256::from(total_balance) }.abi_encode(),
    ).await;
    eth_send(
        &provider,
        bridge_addr,
        depositCall {
            amount: U256::from(total_balance),
            pubkey: FixedBytes::from(alice_pubkey),
            membershipSeal: Bytes::new(),
        }.abi_encode(),
    ).await;

    let resp = eth_call(&provider, token_addr, balanceOfCall { account: bridge_addr }.abi_encode()).await;
    assert_eq!(U256::from_be_slice(&resp[..32]), U256::from(total_balance));
    println!("  Bridge funded: {total_balance} tokens");

    // === Advance time past 7-day timeout and freeze ===
    println!("\n=== Freeze ===");

    let escape_timeout_secs: u64 = 7 * 24 * 60 * 60 + 1;
    let _: serde_json::Value = provider
        .raw_request("evm_increaseTime".into(), vec![escape_timeout_secs])
        .await
        .expect("evm_increaseTime failed");
    let _: serde_json::Value = provider
        .raw_request("evm_mine".into(), ())
        .await
        .expect("evm_mine failed");

    eth_send(&provider, bridge_addr, freezeCall {}.abi_encode()).await;

    let resp = eth_call(&provider, bridge_addr, frozenCall {}.abi_encode()).await;
    assert!(resp[31] != 0, "Bridge should be frozen");
    println!("  Bridge frozen after {escape_timeout_secs}s timeout");

    // === Alice escapes ===
    println!("\n=== Alice escape ===");

    let alice_siblings: Vec<FixedBytes<32>> = alice_proof.path.iter().map(|s| FixedBytes::from(*s)).collect();
    eth_send(
        &provider,
        bridge_addr,
        escapeWithdrawCall {
            leafIndex: U256::from(alice_leaf_index),
            pubkey: FixedBytes::from(alice_pubkey),
            balance: alice_balance,
            salt: FixedBytes::from(alice_salt),
            merkleProof: alice_siblings,
        }.abi_encode(),
    ).await;

    let resp = eth_call(&provider, bridge_addr, claimedCall { leafIndex: U256::from(alice_leaf_index) }.abi_encode()).await;
    assert!(resp[31] != 0, "Alice leaf should be claimed");

    let resp = eth_call(&provider, token_addr, balanceOfCall { account: deployer_addr }.abi_encode()).await;
    let deployer_bal = U256::from_be_slice(&resp[..32]);
    assert!(deployer_bal >= U256::from(alice_balance), "Should have received alice_balance");
    println!("  Alice recovered {alice_balance} tokens");

    // === Bob escapes ===
    println!("\n=== Bob escape ===");

    let bob_siblings: Vec<FixedBytes<32>> = bob_proof.path.iter().map(|s| FixedBytes::from(*s)).collect();
    eth_send(
        &provider,
        bridge_addr,
        escapeWithdrawCall {
            leafIndex: U256::from(bob_leaf_index),
            pubkey: FixedBytes::from(bob_pubkey),
            balance: bob_balance,
            salt: FixedBytes::from(bob_salt),
            merkleProof: bob_siblings,
        }.abi_encode(),
    ).await;

    let resp = eth_call(&provider, bridge_addr, claimedCall { leafIndex: U256::from(bob_leaf_index) }.abi_encode()).await;
    assert!(resp[31] != 0, "Bob leaf should be claimed");
    println!("  Bob recovered {bob_balance} tokens");

    // === Bridge drained ===
    let resp = eth_call(&provider, token_addr, balanceOfCall { account: bridge_addr }.abi_encode()).await;
    let final_bridge_bal = U256::from_be_slice(&resp[..32]);
    assert_eq!(final_bridge_bal, U256::ZERO, "Bridge should be fully drained");

    println!("\n=== E2E Escape Hatch PASSED ===");
    println!("  [x] Bridge deployed with real Merkle root");
    println!("  [x] Freeze after 7-day timeout");
    println!("  [x] Alice escaped with Merkle proof");
    println!("  [x] Bob escaped from different leaf");
    println!("  [x] Bridge fully drained");
}

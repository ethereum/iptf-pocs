//! End-to-end integration test for diy-validium.
//!
//! Exercises the full pipeline: off-chain state management → journal computation
//! → on-chain contract interaction → state verification.
//!
//! Uses MockRiscZeroVerifier (accepts all proofs) so no guest ELF compilation
//! is needed, but all roots, amounts, and hashes are computed from real off-chain
//! state via the host library.
//!
//! ## Prerequisites
//!
//! ```bash
//! cd pocs/diy-validium/contracts && forge build
//! ```
//!
//! ## Running
//!
//! ```bash
//! cd pocs/diy-validium && RISC0_SKIP_BUILD=1 cargo test --test e2e_integration -- --nocapture
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
    merkle::{
        account_commitment, compute_disclosure_key_hash, compute_new_root, compute_single_leaf_root,
    },
};

// ---------------------------------------------------------------------------
// Solidity ABI definitions (function signatures only, no #[sol(rpc)])
// ---------------------------------------------------------------------------

sol! {
    // ERC20 functions
    function mint(address to, uint256 amount) external;
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);

    // Shared across TransferVerifier, ValidiumBridge, DisclosureVerifier
    function stateRoot() external view returns (bytes32);

    // TransferVerifier
    function executeTransfer(bytes calldata seal, bytes32 oldRoot, bytes32 newRoot) external;

    // ValidiumBridge
    function deposit(uint256 amount, bytes32 pubkey, bytes calldata membershipSeal) external;
    function withdraw(bytes calldata seal, bytes32 oldRoot, bytes32 newRoot, uint64 amount, address recipient) external;

    // DisclosureVerifier
    function verifyDisclosure(bytes calldata seal, bytes32 root, uint64 threshold, bytes32 disclosureKeyHash) external;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Path to the forge `contracts/out/` directory.
fn contracts_out_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("contracts")
        .join("out")
}

/// Load the creation bytecode from a forge artifact JSON.
///
/// Artifact lives at `contracts/out/{dir_name}/{json_name}.json`.
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

/// Deploy a contract: bytecode + ABI-encoded constructor args.
async fn deploy(provider: &impl Provider, bytecode: &Bytes, constructor_args: &[u8]) -> Address {
    let mut data = bytecode.to_vec();
    data.extend_from_slice(constructor_args);

    let tx = TransactionRequest::default().with_deploy_code(data);
    let receipt = provider
        .send_transaction(tx)
        .await
        .expect("Failed to send deploy tx")
        .get_receipt()
        .await
        .expect("Failed to get deploy receipt");

    receipt
        .contract_address
        .expect("Deploy receipt missing contract_address")
}

/// Make a view call, return raw response bytes.
async fn eth_call(provider: &impl Provider, to: Address, calldata: Vec<u8>) -> Bytes {
    let tx = TransactionRequest::default().to(to).with_input(calldata);
    provider.call(tx).await.expect("eth_call failed")
}

/// Send a state-changing transaction, wait for receipt.
async fn eth_send(provider: &impl Provider, to: Address, calldata: Vec<u8>) {
    let tx = TransactionRequest::default().to(to).with_input(calldata);
    provider
        .send_transaction(tx)
        .await
        .expect("Failed to send tx")
        .get_receipt()
        .await
        .expect("Failed to get receipt");
}

/// Send a state-changing transaction, return whether it succeeded (no panic on revert).
async fn eth_send_may_fail(provider: &impl Provider, to: Address, calldata: Vec<u8>) -> bool {
    let tx = TransactionRequest::default().to(to).with_input(calldata);
    provider.send_transaction(tx).await.is_ok()
}

/// Read `stateRoot()` from a contract.
async fn get_state_root(provider: &impl Provider, addr: Address) -> FixedBytes<32> {
    let resp = eth_call(provider, addr, stateRootCall {}.abi_encode()).await;
    FixedBytes::from_slice(&resp[..32])
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_full_lifecycle() {
    let tree_depth = 4;

    // ===================================================================
    // Step 0 — Off-chain setup
    // ===================================================================
    println!("\n=== Step 0: Off-chain setup ===");

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
    let initial_root_b32: FixedBytes<32> = FixedBytes::from(initial_root);

    println!("  Alice (idx {alice_idx}): balance={alice_balance}");
    println!("  Bob   (idx {bob_idx}): balance={bob_balance}");
    println!("  Initial root: 0x{}", hex::encode(initial_root));

    // ===================================================================
    // Step 1 — Deploy contracts on Anvil
    // ===================================================================
    println!("\n=== Step 1: Deploy contracts ===");

    let anvil = Anvil::new().try_spawn().expect("Failed to spawn Anvil");
    println!("  Anvil running at {}", anvil.endpoint());

    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let deployer_addr = signer.address();
    let wallet = EthereumWallet::from(signer);
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(anvil.endpoint_url());

    // Load bytecodes from forge artifacts
    let mock_verifier_bc = load_artifact_bytecode("ValidiumBridge.t.sol", "MockRiscZeroVerifier");
    let mock_erc20_bc = load_artifact_bytecode("ValidiumBridge.t.sol", "MockERC20");
    let transfer_verifier_bc = load_artifact_bytecode("TransferVerifier.sol", "TransferVerifier");
    let bridge_bc = load_artifact_bytecode("ValidiumBridge.sol", "ValidiumBridge");
    let disclosure_bc = load_artifact_bytecode("DisclosureVerifier.sol", "DisclosureVerifier");

    // Deploy MockRiscZeroVerifier (no constructor args)
    let verifier_addr = deploy(&provider, &mock_verifier_bc, &[]).await;
    println!("  MockRiscZeroVerifier: {verifier_addr}");

    // Deploy MockERC20 (no constructor args)
    let token_addr = deploy(&provider, &mock_erc20_bc, &[]).await;
    println!("  MockERC20:            {token_addr}");

    // Deploy TransferVerifier(address _verifier, bytes32 _initialRoot)
    let tv_args = (verifier_addr, initial_root_b32).abi_encode_params();
    let tv_addr = deploy(&provider, &transfer_verifier_bc, &tv_args).await;
    println!("  TransferVerifier:     {tv_addr}");

    // Deploy ValidiumBridge(IERC20 _token, IRiscZeroVerifier _verifier, bytes32 _initialRoot, bytes32 _allowlistRoot)
    let allowlist_root = FixedBytes::from(sha256(b"allowlist"));
    let bridge_args =
        (token_addr, verifier_addr, initial_root_b32, allowlist_root).abi_encode_params();
    let bridge_addr = deploy(&provider, &bridge_bc, &bridge_args).await;
    println!("  ValidiumBridge:       {bridge_addr}");

    // Deploy DisclosureVerifier(IRiscZeroVerifier _verifier, bytes32 _stateRoot)
    let dv_args = (verifier_addr, initial_root_b32).abi_encode_params();
    let dv_addr = deploy(&provider, &disclosure_bc, &dv_args).await;
    println!("  DisclosureVerifier:   {dv_addr}");

    // ===================================================================
    // Step 2 — Verify initial state roots
    // ===================================================================
    println!("\n=== Step 2: Verify initial state ===");

    let tv_root = get_state_root(&provider, tv_addr).await;
    let br_root = get_state_root(&provider, bridge_addr).await;
    let dv_root = get_state_root(&provider, dv_addr).await;

    assert_eq!(
        tv_root, initial_root_b32,
        "TransferVerifier initial root mismatch"
    );
    assert_eq!(
        br_root, initial_root_b32,
        "ValidiumBridge initial root mismatch"
    );
    assert_eq!(
        dv_root, initial_root_b32,
        "DisclosureVerifier initial root mismatch"
    );
    println!("  All three contracts have matching initial root");

    // ===================================================================
    // Step 3 — Deposit (mint ERC20, approve, deposit into bridge)
    // ===================================================================
    println!("\n=== Step 3: Deposit ===");

    let deposit_amount: u64 = 10_000;

    // Mint tokens to deployer
    eth_send(
        &provider,
        token_addr,
        mintCall {
            to: deployer_addr,
            amount: U256::from(deposit_amount),
        }
        .abi_encode(),
    )
    .await;

    // Approve bridge to spend
    eth_send(
        &provider,
        token_addr,
        approveCall {
            spender: bridge_addr,
            amount: U256::from(deposit_amount),
        }
        .abi_encode(),
    )
    .await;

    // Deposit with empty membership seal
    eth_send(
        &provider,
        bridge_addr,
        depositCall {
            amount: U256::from(deposit_amount),
            pubkey: FixedBytes::from(alice_pubkey),
            membershipSeal: Bytes::new(),
        }
        .abi_encode(),
    )
    .await;

    // Verify: bridge holds tokens
    let resp = eth_call(
        &provider,
        token_addr,
        balanceOfCall {
            account: bridge_addr,
        }
        .abi_encode(),
    )
    .await;
    let bridge_token_bal = U256::from_be_slice(&resp[..32]);
    assert_eq!(
        bridge_token_bal,
        U256::from(deposit_amount),
        "Bridge should hold deposited tokens"
    );

    // Verify: stateRoot unchanged (deposit doesn't change root)
    let br_root_after = get_state_root(&provider, bridge_addr).await;
    assert_eq!(
        br_root_after, initial_root_b32,
        "Deposit should not change bridge stateRoot"
    );
    println!("  Deposited {deposit_amount} tokens, bridge balance correct, root unchanged");

    // ===================================================================
    // Step 4 — Transfer (Alice sends 1000 to Bob)
    // ===================================================================
    println!("\n=== Step 4: Transfer ===");

    let transfer_amount: u64 = 1000;
    let new_alice_balance = alice_balance - transfer_amount;
    let new_bob_balance = bob_balance + transfer_amount;
    let new_alice_salt = [0x11u8; 32];
    let new_bob_salt = [0x22u8; 32];

    // Compute new root from the dual-leaf update
    let alice_proof = tree.prove(alice_idx);
    let bob_proof = tree.prove(bob_idx);

    let new_alice_leaf = account_commitment(&alice_pubkey, new_alice_balance, &new_alice_salt);
    let new_bob_leaf = account_commitment(&bob_pubkey, new_bob_balance, &new_bob_salt);

    let transfer_new_root = compute_new_root(
        new_alice_leaf,
        &alice_proof.indices,
        new_bob_leaf,
        &bob_proof.indices,
        &alice_proof.path,
        &bob_proof.path,
    );
    let transfer_new_root_b32 = FixedBytes::from(transfer_new_root);

    // Execute on-chain
    eth_send(
        &provider,
        tv_addr,
        executeTransferCall {
            seal: Bytes::new(),
            oldRoot: initial_root_b32,
            newRoot: transfer_new_root_b32,
        }
        .abi_encode(),
    )
    .await;

    let tv_root_after = get_state_root(&provider, tv_addr).await;
    assert_eq!(
        tv_root_after, transfer_new_root_b32,
        "TransferVerifier root should be updated after transfer"
    );
    println!(
        "  Transfer: Alice {alice_balance}->{new_alice_balance}, Bob {bob_balance}->{new_bob_balance}"
    );
    println!("  New root: 0x{}", hex::encode(transfer_new_root));

    // Update off-chain state to match
    store.update_balance(alice_idx, new_alice_balance, new_alice_salt);
    store.update_balance(bob_idx, new_bob_balance, new_bob_salt);

    // Rebuild tree and verify consistency
    let tree_after_transfer = store.build_tree(tree_depth);
    assert_eq!(
        tree_after_transfer.root(),
        transfer_new_root,
        "Rebuilt tree root should match computed transfer root"
    );

    // ===================================================================
    // Step 5 — Withdrawal (Bob withdraws 500 from bridge)
    // ===================================================================
    println!("\n=== Step 5: Withdrawal ===");

    let withdraw_amount: u64 = 500;
    let bob_withdraw_salt = [0x33u8; 32];

    // Bridge stateRoot is still initial_root (deposit doesn't change it).
    // Compute single-leaf root update for Bob in the *original* tree.
    let bob_proof_for_bridge = tree.prove(bob_idx);

    let bob_new_leaf_bridge = account_commitment(
        &bob_pubkey,
        bob_balance - withdraw_amount,
        &bob_withdraw_salt,
    );
    let bridge_new_root = compute_single_leaf_root(
        bob_new_leaf_bridge,
        &bob_proof_for_bridge.path,
        &bob_proof_for_bridge.indices,
    );
    let bridge_new_root_b32 = FixedBytes::from(bridge_new_root);

    let recipient_addr = Address::repeat_byte(0xCC);

    eth_send(
        &provider,
        bridge_addr,
        withdrawCall {
            seal: Bytes::new(),
            oldRoot: initial_root_b32,
            newRoot: bridge_new_root_b32,
            amount: withdraw_amount,
            recipient: recipient_addr,
        }
        .abi_encode(),
    )
    .await;

    // Verify: bridge stateRoot updated
    let br_root_after_withdraw = get_state_root(&provider, bridge_addr).await;
    assert_eq!(
        br_root_after_withdraw, bridge_new_root_b32,
        "Bridge stateRoot should be updated after withdrawal"
    );

    // Verify: recipient received tokens
    let resp = eth_call(
        &provider,
        token_addr,
        balanceOfCall {
            account: recipient_addr,
        }
        .abi_encode(),
    )
    .await;
    let recipient_bal = U256::from_be_slice(&resp[..32]);
    assert_eq!(
        recipient_bal,
        U256::from(withdraw_amount),
        "Recipient should have received withdrawn tokens"
    );

    println!("  Withdrew {withdraw_amount} tokens to {recipient_addr}");
    println!("  Bridge new root: 0x{}", hex::encode(bridge_new_root));
    println!("  Recipient balance: {recipient_bal}");

    // ===================================================================
    // Step 6 — Disclosure (read-only attestation)
    // ===================================================================
    println!("\n=== Step 6: Disclosure ===");

    let auditor_pubkey = [0xDDu8; 32];
    let threshold: u64 = 1000;

    let disclosure_key_hash = compute_disclosure_key_hash(&alice_pubkey, &auditor_pubkey);

    let dv_root_before = get_state_root(&provider, dv_addr).await;

    eth_send(
        &provider,
        dv_addr,
        verifyDisclosureCall {
            seal: Bytes::new(),
            root: initial_root_b32,
            threshold,
            disclosureKeyHash: FixedBytes::from(disclosure_key_hash),
        }
        .abi_encode(),
    )
    .await;

    let dv_root_after = get_state_root(&provider, dv_addr).await;
    assert_eq!(
        dv_root_after, dv_root_before,
        "Disclosure should not change stateRoot"
    );
    println!("  Disclosure verified (threshold={threshold}), stateRoot unchanged");

    // ===================================================================
    // Step 7 — Replay protection (stale root should revert)
    // ===================================================================
    println!("\n=== Step 7: Replay protection ===");

    // Replay the Step 4 transfer — oldRoot is now stale on TransferVerifier
    let succeeded = eth_send_may_fail(
        &provider,
        tv_addr,
        executeTransferCall {
            seal: Bytes::new(),
            oldRoot: initial_root_b32,
            newRoot: transfer_new_root_b32,
        }
        .abi_encode(),
    )
    .await;

    assert!(
        !succeeded,
        "Replaying a transfer with stale oldRoot should revert"
    );
    println!("  Replay correctly rejected (stale oldRoot)");

    // ===================================================================
    // Summary
    // ===================================================================
    println!("\n=== E2E Test Passed ===");
    println!("  [x] Initial roots match across all contracts");
    println!("  [x] Deposit locks tokens, root unchanged");
    println!("  [x] Transfer updates TransferVerifier root");
    println!("  [x] Withdrawal updates bridge root + transfers tokens");
    println!("  [x] Disclosure emits event without state change");
    println!("  [x] Replay with stale root reverts");
}

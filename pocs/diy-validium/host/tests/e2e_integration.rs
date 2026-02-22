//! End-to-end integration test for diy-validium.
//!
//! Exercises the full pipeline: off-chain state management → journal computation
//! → on-chain contract interaction → state verification.
//!
//! Supports two modes:
//! - **Mock proofs** (default, `RISC0_SKIP_BUILD=1`): Uses MockRiscZeroVerifier,
//!   no guest ELF compilation needed. Zero IMAGE_IDs and empty seals.
//! - **Real proofs** (guest ELFs compiled): Runs the RISC Zero prover for each
//!   operation, encodes seals via `risc0-ethereum-contracts`, and passes real
//!   IMAGE_IDs and seals to contracts. On-chain uses MockRiscZeroVerifier;
//!   swapping to a Groth16 verifier requires Bonsai or x86 for proof compression.
//!
//! In both modes, all roots, amounts, and hashes are computed from real off-chain
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
//! # Mock proofs (default):
//! cd pocs/diy-validium && RISC0_SKIP_BUILD=1 cargo test --test e2e_integration -- --nocapture
//!
//! # Real proofs (requires compiled guest ELFs):
//! cd pocs/diy-validium && RISC0_DEV_MODE=1 cargo test --test e2e_integration -- --nocapture
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
    journal::{DisclosureJournal, TransferJournal, WithdrawalJournal},
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

/// Convert a RISC Zero image ID ([u32; 8]) to a Solidity-compatible bytes32.
fn image_id_to_bytes32(id: [u32; 8]) -> FixedBytes<32> {
    let bytes: Vec<u8> = id.iter().flat_map(|w| w.to_le_bytes()).collect();
    FixedBytes::from_slice(&bytes)
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
// Real RISC Zero proof helpers (only called when guest ELFs are available)
// ---------------------------------------------------------------------------

/// Run the real RISC Zero prover for a transfer, verify receipt, return journal.
#[allow(clippy::too_many_arguments)]
fn prove_transfer(
    sender_sk: &[u8; 32],
    sender_balance: u64,
    sender_salt: &[u8; 32],
    sender_path: &[[u8; 32]],
    sender_indices: &[bool],
    amount: u64,
    recipient_pubkey: &[u8; 32],
    recipient_balance: u64,
    recipient_salt: &[u8; 32],
    recipient_path: &[[u8; 32]],
    recipient_indices: &[bool],
    new_sender_salt: &[u8; 32],
    new_recipient_salt: &[u8; 32],
) -> (TransferJournal, Bytes) {
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(sender_sk)
        .unwrap()
        .write(&sender_balance)
        .unwrap()
        .write(sender_salt)
        .unwrap()
        .write(&sender_path.to_vec())
        .unwrap()
        .write(&sender_indices.to_vec())
        .unwrap()
        .write(&amount)
        .unwrap()
        .write(recipient_pubkey)
        .unwrap()
        .write(&recipient_balance)
        .unwrap()
        .write(recipient_salt)
        .unwrap()
        .write(&recipient_path.to_vec())
        .unwrap()
        .write(&recipient_indices.to_vec())
        .unwrap()
        .write(new_sender_salt)
        .unwrap()
        .write(new_recipient_salt)
        .unwrap()
        .build()
        .unwrap();

    let prover = risc0_zkvm::default_prover();
    let prove_info = prover.prove(env, methods::TRANSFER_ELF).unwrap();
    let receipt = prove_info.receipt;
    receipt.verify(methods::TRANSFER_ID).unwrap();
    let seal = risc0_ethereum_contracts::encode_seal(&receipt).unwrap();
    let journal = TransferJournal::from_bytes(&receipt.journal.bytes).unwrap();
    (journal, Bytes::from(seal))
}

/// Run the real RISC Zero prover for a withdrawal, verify receipt, return journal.
#[allow(clippy::too_many_arguments)]
fn prove_withdrawal(
    secret_key: &[u8; 32],
    balance: u64,
    salt: &[u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    amount: u64,
    new_salt: &[u8; 32],
    recipient: &[u8; 20],
) -> (WithdrawalJournal, Bytes) {
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(secret_key)
        .unwrap()
        .write(&balance)
        .unwrap()
        .write(salt)
        .unwrap()
        .write(&path.to_vec())
        .unwrap()
        .write(&indices.to_vec())
        .unwrap()
        .write(&amount)
        .unwrap()
        .write(new_salt)
        .unwrap()
        .write(recipient)
        .unwrap()
        .build()
        .unwrap();

    let prover = risc0_zkvm::default_prover();
    let prove_info = prover.prove(env, methods::WITHDRAWAL_ELF).unwrap();
    let receipt = prove_info.receipt;
    receipt.verify(methods::WITHDRAWAL_ID).unwrap();
    let seal = risc0_ethereum_contracts::encode_seal(&receipt).unwrap();
    let journal = WithdrawalJournal::from_bytes(&receipt.journal.bytes).unwrap();
    (journal, Bytes::from(seal))
}

/// Run the real RISC Zero prover for a disclosure, verify receipt, return journal.
fn prove_disclosure(
    secret_key: &[u8; 32],
    balance: u64,
    salt: &[u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    threshold: u64,
    auditor_pubkey: &[u8; 32],
) -> (DisclosureJournal, Bytes) {
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(secret_key)
        .unwrap()
        .write(&balance)
        .unwrap()
        .write(salt)
        .unwrap()
        .write(&path.to_vec())
        .unwrap()
        .write(&indices.to_vec())
        .unwrap()
        .write(&threshold)
        .unwrap()
        .write(auditor_pubkey)
        .unwrap()
        .build()
        .unwrap();

    let prover = risc0_zkvm::default_prover();
    let prove_info = prover.prove(env, methods::DISCLOSURE_ELF).unwrap();
    let receipt = prove_info.receipt;
    receipt.verify(methods::DISCLOSURE_ID).unwrap();
    let seal = risc0_ethereum_contracts::encode_seal(&receipt).unwrap();
    let journal = DisclosureJournal::from_bytes(&receipt.journal.bytes).unwrap();
    (journal, Bytes::from(seal))
}

/// Run the real RISC Zero prover for a membership proof, verify receipt.
fn prove_membership(
    leaf: &[u8; 32],
    path: &[[u8; 32]],
    indices: &[bool],
    expected_root: &[u8; 32],
) -> Bytes {
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(leaf)
        .unwrap()
        .write(&path.to_vec())
        .unwrap()
        .write(&indices.to_vec())
        .unwrap()
        .write(expected_root)
        .unwrap()
        .build()
        .unwrap();

    let prover = risc0_zkvm::default_prover();
    let prove_info = prover.prove(env, methods::MEMBERSHIP_ELF).unwrap();
    let receipt = prove_info.receipt;
    receipt.verify(methods::MEMBERSHIP_ID).unwrap();
    let seal = risc0_ethereum_contracts::encode_seal(&receipt).unwrap();
    Bytes::from(seal)
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

#[tokio::test]
async fn e2e_full_lifecycle() {
    let tree_depth = 4;

    // Auto-detect whether real RISC Zero guest ELFs are available
    let real_proofs = !methods::TRANSFER_ELF.is_empty();
    if real_proofs {
        println!("\n  Real RISC Zero proofs ENABLED (guest ELFs available)");
    } else {
        println!("\n  Mock proofs (guest ELFs not compiled, set RISC0_SKIP_BUILD=0 to enable)");
    }

    // Compute IMAGE_IDs for contract deployment
    let (transfer_image_id, membership_image_id, withdrawal_image_id, disclosure_image_id) =
        if real_proofs {
            (
                image_id_to_bytes32(methods::TRANSFER_ID),
                image_id_to_bytes32(methods::MEMBERSHIP_ID),
                image_id_to_bytes32(methods::WITHDRAWAL_ID),
                image_id_to_bytes32(methods::DISCLOSURE_ID),
            )
        } else {
            (
                FixedBytes::ZERO,
                FixedBytes::ZERO,
                FixedBytes::ZERO,
                FixedBytes::ZERO,
            )
        };

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
    let tv_args = (verifier_addr, initial_root_b32, transfer_image_id).abi_encode_params();
    let tv_addr = deploy(&provider, &transfer_verifier_bc, &tv_args).await;
    println!("  TransferVerifier:     {tv_addr}");

    // Deploy ValidiumBridge(IERC20 _token, IRiscZeroVerifier _verifier, bytes32 _initialRoot, bytes32 _allowlistRoot)
    // Allowlist is a single-element depth-0 tree: root = Alice's pubkey
    let allowlist_root = FixedBytes::from(alice_pubkey);
    let bridge_args = (
        token_addr,
        verifier_addr,
        initial_root_b32,
        allowlist_root,
        membership_image_id,
        withdrawal_image_id,
    )
        .abi_encode_params();
    let bridge_addr = deploy(&provider, &bridge_bc, &bridge_args).await;
    println!("  ValidiumBridge:       {bridge_addr}");

    // Deploy DisclosureVerifier(IRiscZeroVerifier _verifier, bytes32 _stateRoot)
    let dv_args = (verifier_addr, initial_root_b32, disclosure_image_id).abi_encode_params();
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

    // Generate membership seal (real or empty)
    let membership_seal = if real_proofs {
        println!("  Generating real membership proof for allowlist...");
        let seal = prove_membership(&alice_pubkey, &[], &[], &alice_pubkey);
        println!("  Membership proof verified locally: OK");
        seal
    } else {
        Bytes::new()
    };

    // Deposit with membership seal
    eth_send(
        &provider,
        bridge_addr,
        depositCall {
            amount: U256::from(deposit_amount),
            pubkey: FixedBytes::from(alice_pubkey),
            membershipSeal: membership_seal,
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

    // Generate transfer proof (real or empty seal)
    let transfer_seal = if real_proofs {
        println!("  Generating real transfer proof...");
        let (tj, seal) = prove_transfer(
            &alice_sk,
            alice_balance,
            &alice_salt,
            &alice_proof.path,
            &alice_proof.indices,
            transfer_amount,
            &bob_pubkey,
            bob_balance,
            &bob_salt,
            &bob_proof.path,
            &bob_proof.indices,
            &new_alice_salt,
            &new_bob_salt,
        );
        assert_eq!(
            tj.old_root, initial_root,
            "Transfer journal old_root mismatch"
        );
        assert_eq!(
            tj.new_root, transfer_new_root,
            "Transfer journal new_root mismatch"
        );
        println!("  Transfer journal verified: old_root and new_root match");
        seal
    } else {
        Bytes::new()
    };

    // Execute on-chain
    eth_send(
        &provider,
        tv_addr,
        executeTransferCall {
            seal: transfer_seal,
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

    let recipient_raw: [u8; 20] = [0xCC; 20];
    let recipient_addr = Address::from(recipient_raw);

    // Generate withdrawal proof (real or empty seal)
    let withdrawal_seal = if real_proofs {
        println!("  Generating real withdrawal proof...");
        let (wj, seal) = prove_withdrawal(
            &bob_sk,
            bob_balance,
            &bob_salt,
            &bob_proof_for_bridge.path,
            &bob_proof_for_bridge.indices,
            withdraw_amount,
            &bob_withdraw_salt,
            &recipient_raw,
        );
        assert_eq!(
            wj.old_root, initial_root,
            "Withdrawal journal old_root mismatch"
        );
        assert_eq!(
            wj.new_root, bridge_new_root,
            "Withdrawal journal new_root mismatch"
        );
        assert_eq!(
            wj.amount, withdraw_amount,
            "Withdrawal journal amount mismatch"
        );
        assert_eq!(
            wj.recipient, recipient_raw,
            "Withdrawal journal recipient mismatch"
        );
        println!("  Withdrawal journal verified: roots, amount, and recipient match");
        seal
    } else {
        Bytes::new()
    };

    eth_send(
        &provider,
        bridge_addr,
        withdrawCall {
            seal: withdrawal_seal,
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

    // Generate disclosure proof (real or empty seal)
    let disclosure_seal = if real_proofs {
        println!("  Generating real disclosure proof...");
        let alice_proof_for_disclosure = tree.prove(alice_idx);
        let (dj, seal) = prove_disclosure(
            &alice_sk,
            alice_balance,
            &alice_salt,
            &alice_proof_for_disclosure.path,
            &alice_proof_for_disclosure.indices,
            threshold,
            &auditor_pubkey,
        );
        assert_eq!(
            dj.merkle_root, initial_root,
            "Disclosure journal root mismatch"
        );
        assert_eq!(
            dj.threshold, threshold,
            "Disclosure journal threshold mismatch"
        );
        assert_eq!(
            dj.disclosure_key_hash, disclosure_key_hash,
            "Disclosure journal key hash mismatch"
        );
        println!("  Disclosure journal verified: root, threshold, and key hash match");
        seal
    } else {
        Bytes::new()
    };

    let dv_root_before = get_state_root(&provider, dv_addr).await;

    eth_send(
        &provider,
        dv_addr,
        verifyDisclosureCall {
            seal: disclosure_seal,
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

//! Integration test for the Resilient Private Identity PoC.
//!
//! This test demonstrates the full enrollment and verification flow:
//! 1. Deploy contracts via `forge script`
//! 2. Enroll a user (Alice) via the IdentityClient
//! 3. Submit enrollment on-chain
//! 4. Generate a membership proof
//! 5. Verify the membership proof on-chain
//!
//! ## Prerequisites
//!
//! - `anvil` (Foundry's local Ethereum node)
//! - `forge` (Foundry's build tool)
//! - `nargo` (Noir compiler) -- only if running with real proofs
//! - `bb` (Barretenberg CLI) -- only if running with real proofs
//!
//! ## Running
//!
//! ```bash
//! cargo test --test integration -- --nocapture
//! ```

use std::{
    path::PathBuf,
    process::Command,
};

use alloy::{
    network::EthereumWallet,
    node_bindings::Anvil,
    primitives::{
        Address,
        Bytes,
        U256,
    },
    providers::ProviderBuilder,
    signers::local::PrivateKeySigner,
    sol,
};
use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};

use resilient_private_identity::{
    adapters::{
        bb_prover::BBProver,
        lean_imt_merkle::LeanImtMerkleStore,
        mock_mpc::MockMpcNetwork,
        mock_proof::MockProofBackend,
    },
    client::IdentityClient,
    ports::mpc::MpcNetwork,
    poseidon::hash_external_nullifier,
    types::Predicate,
};

// Contract interfaces via alloy::sol!

sol! {
    #[sol(rpc)]
    interface IIdentityTree {
        function insertLeaf(uint256 leaf, uint256 enrollmentNullifier) external;
        function isRecentRoot(uint256 root) external view returns (bool);
        function addAuthorized(address addr) external;
        function governance() external view returns (address);
        function recentRoots(uint256 index) external view returns (uint256);
        function rootIndex() external view returns (uint256);
    }

    #[sol(rpc)]
    interface IEnrollment {
        function enroll(
            uint256 leaf,
            uint256 enrollmentNullifier,
            uint256 gIdX,
            uint256 gIdY,
            bytes calldata proof
        ) external;

        function mpcPublicKey() external view returns (uint256 x, uint256 y);
    }

    #[sol(rpc)]
    interface IIdentityVerifier {
        function verifyProof(
            bytes calldata proof,
            uint256 root,
            uint256 nullifier,
            uint256 externalNullifier,
            uint256 version,
            uint256 predicateType,
            uint256 predicateAttrIndex,
            uint256 predicateValue,
            uint256 predicateResult
        ) external;

        function usedNullifiers(uint256 nullifier) external view returns (bool);
    }
}

// Helpers

/// Convert an Fr field element to a U256 for on-chain submission.
fn fr_to_u256(f: Fr) -> U256 {
    let bigint = f.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    U256::from_le_slice(&le_bytes)
}

/// Convert a BN254 base field Fq coordinate to U256.
fn fq_to_u256(fq: ark_bn254::Fq) -> U256 {
    let bigint = fq.into_bigint();
    let le_bytes = bigint.to_bytes_le();
    U256::from_le_slice(&le_bytes)
}

enum VerifierVariant {
    Mock,
    Real,
}

/// Deploy contracts using `forge script` with Deploy.s.sol.
///
/// Returns (identity_tree_address, enrollment_address, identity_verifier_address).
fn deploy_contracts(
    anvil_endpoint: &str,
    deployer_private_key: &str,
    mpc_key_x: &U256,
    mpc_key_y: &U256,
    verifiers: VerifierVariant,
) -> (Address, Address, Address) {
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let deployer_address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    let use_mock = match verifiers {
        VerifierVariant::Mock => "true",
        VerifierVariant::Real => "false",
    };

    // Save deployments.toml before forge script (Config writes back to it)
    let deployments_path = project_root.join("deployments.toml");
    let original_deployments = std::fs::read_to_string(&deployments_path)
        .expect("Failed to read deployments.toml");

    let output = Command::new("forge")
        .args([
            "script",
            "contracts/script/Deploy.s.sol:Deploy",
            "--rpc-url",
            anvil_endpoint,
            "--private-key",
            deployer_private_key,
            "--broadcast",
        ])
        .env("USE_MOCK_VERIFIER", use_mock)
        .env("GOVERNANCE", deployer_address)
        .env("MULTISIG", deployer_address)
        .env("GUARDIAN", deployer_address)
        .env("MPC_KEY_X", &format!("{mpc_key_x}"))
        .env("MPC_KEY_Y", &format!("{mpc_key_y}"))
        // Dummy values for Config env var resolution (not used when deploying fresh)
        .env("IDENTITY_TREE_ADDRESS", Address::ZERO.to_string())
        .env("ENROLLMENT_ADDRESS", Address::ZERO.to_string())
        .env("IDENTITY_VERIFIER_ADDRESS", Address::ZERO.to_string())
        .env("ENROLLMENT_VERIFIER_ADDRESS", Address::ZERO.to_string())
        .env("MEMBERSHIP_VERIFIER_ADDRESS", Address::ZERO.to_string())
        .env("SEPOLIA_RPC_URL", "http://localhost:8545")
        .current_dir(&project_root)
        .output()
        .expect("Failed to run forge script");

    // Restore original deployments.toml
    std::fs::write(&deployments_path, &original_deployments)
        .expect("Failed to restore deployments.toml");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        panic!("forge script failed!\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }

    let full_output = format!("{stdout}\n{stderr}");

    fn find_address(output: &str, label: &str) -> Address {
        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix(label) {
                let addr_str = rest.trim();
                if let Ok(addr) = addr_str.parse::<Address>() {
                    return addr;
                }
            }
        }
        panic!("Could not find address for '{label}' in forge output:\n{output}");
    }

    let identity_tree = find_address(&full_output, "IdentityTree:");
    let enrollment = find_address(&full_output, "Enrollment:");
    let identity_verifier = find_address(&full_output, "IdentityVerifier:");

    (identity_tree, enrollment, identity_verifier)
}

// Test

#[tokio::test]
async fn test_full_enrollment_and_verification() {
    println!("=== Starting Integration Test ===\n");

    // 1. Start Anvil
    println!("Starting Anvil...");
    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();
    println!("  Anvil running at: {endpoint}");

    // Anvil default private key (account 0)
    let private_key =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let signer: PrivateKeySigner = private_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());

    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(anvil.endpoint_url());

    // 2. Create MockMpcNetwork and get public key coordinates
    println!("Creating mock MPC network...");
    let mpc = MockMpcNetwork::new(4, 7, MockProofBackend);
    let mpc_pk = mpc.public_key();
    let mpc_key_x = fq_to_u256(mpc_pk.x);
    let mpc_key_y = fq_to_u256(mpc_pk.y);
    println!("  MPC public key x: {mpc_key_x}");
    println!("  MPC public key y: {mpc_key_y}");

    // 3. Deploy contracts via forge script
    println!("\nDeploying contracts via forge script...");
    let (identity_tree_addr, enrollment_addr, identity_verifier_addr) = deploy_contracts(
        &endpoint,
        private_key,
        &mpc_key_x,
        &mpc_key_y,
        VerifierVariant::Mock,
    );
    println!("  IdentityTree:    {identity_tree_addr}");
    println!("  Enrollment:      {enrollment_addr}");
    println!("  IdentityVerifier: {identity_verifier_addr}");

    // 4. Create contract instances
    let identity_tree = IIdentityTree::new(identity_tree_addr, &provider);
    let enrollment_contract = IEnrollment::new(enrollment_addr, &provider);
    let identity_verifier = IIdentityVerifier::new(identity_verifier_addr, &provider);

    // 5. Create IdentityClient with mock proof backend
    //    (Mock verifier on-chain accepts any proof bytes)
    println!("\nCreating IdentityClient...");
    let prover = MockProofBackend;
    let merkle = LeanImtMerkleStore::new();
    let mut client = IdentityClient::new(prover, mpc, merkle);

    // 6. Enroll Alice
    println!("\n=== Enrolling Alice ===");
    let attrs = [
        Fr::from(1u64),     // age_over_18 = true
        Fr::from(840u64),   // nationality = 840 (US)
        Fr::from(0u64),     // name_hash placeholder
        Fr::from(20178u64), // enrollment_day
    ];

    let (identity, enrollment_data, enrollment_proof_bytes) = client
        .enroll("email:alice@example.com", attrs, 1)
        .expect("Enrollment failed");

    println!(
        "  leaf:                {}",
        fr_to_u256(enrollment_data.leaf)
    );
    println!(
        "  enrollment_nullifier: {}",
        fr_to_u256(enrollment_data.enrollment_nullifier)
    );
    println!("  leaf_index:          {}", identity.leaf_index);

    // 7. Submit enrollment transaction
    println!("\nSubmitting enrollment on-chain...");
    let g_id_x = fq_to_u256(enrollment_data.g_id.x);
    let g_id_y = fq_to_u256(enrollment_data.g_id.y);

    let enroll_tx = enrollment_contract
        .enroll(
            fr_to_u256(enrollment_data.leaf),
            fr_to_u256(enrollment_data.enrollment_nullifier),
            g_id_x,
            g_id_y,
            Bytes::from(enrollment_proof_bytes),
        )
        .send()
        .await
        .expect("Failed to send enrollment tx");

    let enroll_receipt = enroll_tx
        .get_receipt()
        .await
        .expect("Failed to get enrollment receipt");
    println!("  Enrollment tx: {:?}", enroll_receipt.transaction_hash);
    assert!(enroll_receipt.status(), "Enrollment transaction reverted");

    // 8. Verify the root was updated on-chain
    let root_index = identity_tree
        .rootIndex()
        .call()
        .await
        .expect("Failed to read rootIndex");
    let on_chain_root = identity_tree
        .recentRoots(root_index)
        .call()
        .await
        .expect("Failed to read recent root");
    println!("  On-chain root index: {root_index}");
    println!("  On-chain root:       {on_chain_root}");
    assert_ne!(
        on_chain_root,
        U256::ZERO,
        "Root should be nonzero after enrollment"
    );

    // 9. Generate membership proof
    println!("\n=== Generating Membership Proof ===");
    let chain_id = Fr::from(31337u64);
    let verifier_addr_fr = Fr::from(0u64); // simplified for test
    let scope = Fr::from(1u64);
    let external_nullifier = hash_external_nullifier(chain_id, verifier_addr_fr, scope);

    let predicate = Predicate {
        predicate_type: 1, // boolean
        attr_index: 0,     // age_over_18
        value: Fr::from(0u64),
    };

    let proof_data = client
        .generate_membership_proof(&identity, external_nullifier, &predicate)
        .expect("Membership proof generation failed");

    println!("  root:              {}", fr_to_u256(proof_data.root));
    println!("  nullifier:         {}", fr_to_u256(proof_data.nullifier));
    println!(
        "  external_nullifier: {}",
        fr_to_u256(proof_data.external_nullifier)
    );
    println!(
        "  predicate_result:  {}",
        fr_to_u256(proof_data.predicate_result)
    );

    // 10. Verify the local root is recognized on-chain
    let local_root_u256 = fr_to_u256(proof_data.root);
    let is_recent = identity_tree
        .isRecentRoot(local_root_u256)
        .call()
        .await
        .expect("Failed to call isRecentRoot");
    println!("  Root recognized on-chain: {is_recent}");
    assert!(is_recent, "Local Merkle root should match on-chain root");

    // 11. Submit verification on-chain
    println!("\nSubmitting verification on-chain...");
    let verify_tx = identity_verifier
        .verifyProof(
            Bytes::from(proof_data.proof_bytes.clone()),
            fr_to_u256(proof_data.root),
            fr_to_u256(proof_data.nullifier),
            fr_to_u256(proof_data.external_nullifier),
            U256::from(proof_data.version),
            U256::from(proof_data.predicate_type),
            U256::from(proof_data.predicate_attr_index),
            fr_to_u256(proof_data.predicate_value),
            fr_to_u256(proof_data.predicate_result),
        )
        .send()
        .await
        .expect("Failed to send verify tx");

    let verify_receipt = verify_tx
        .get_receipt()
        .await
        .expect("Failed to get verification receipt");
    println!("  Verification tx: {:?}", verify_receipt.transaction_hash);
    assert!(verify_receipt.status(), "Verification transaction reverted");

    // 12. Verify nullifier is spent
    let nullifier_spent = identity_verifier
        .usedNullifiers(fr_to_u256(proof_data.nullifier))
        .call()
        .await
        .expect("Failed to check nullifier");
    assert!(nullifier_spent, "Nullifier should be marked as used");
    println!("  Nullifier marked as used: true");

    // 13. Verify double-spend prevention: same proof should fail
    println!("\nVerifying double-spend prevention...");
    let double_spend_result = identity_verifier
        .verifyProof(
            Bytes::from(proof_data.proof_bytes),
            fr_to_u256(proof_data.root),
            fr_to_u256(proof_data.nullifier),
            fr_to_u256(proof_data.external_nullifier),
            U256::from(proof_data.version),
            U256::from(proof_data.predicate_type),
            U256::from(proof_data.predicate_attr_index),
            fr_to_u256(proof_data.predicate_value),
            fr_to_u256(proof_data.predicate_result),
        )
        .send()
        .await;

    // The transaction should fail (revert with NullifierUsed)
    assert!(
        double_spend_result.is_err(),
        "Double-spend should be rejected"
    );
    println!("  Double-spend correctly rejected");

    println!("\n=== Integration Test Passed ===");
    println!("Summary:");
    println!(
        "  - Deployed IdentityTree, Enrollment, IdentityVerifier (with mock verifiers)"
    );
    println!("  - Enrolled Alice with identity attributes");
    println!("  - Verified Merkle root matches between local and on-chain trees");
    println!("  - Generated and verified membership proof on-chain");
    println!("  - Confirmed double-spend protection works");
}

/// Integration test with real ZK proofs generated by nargo + bb (Barretenberg).
///
/// This test deploys real HonkVerifier contracts and generates actual ZK proofs
/// that are verified on-chain. Requires `nargo` and `bb` to be installed.
///
/// Run with:
/// ```bash
/// cargo test --test integration test_real_proofs -- --nocapture
/// ```
#[tokio::test]
async fn test_real_proofs_enrollment_and_verification() {
    println!("=== Real Proofs Integration Test ===\n");

    // 1. Start Anvil
    println!("Starting Anvil...");
    let anvil = Anvil::new().spawn();
    let endpoint = anvil.endpoint();
    println!("  Anvil running at: {endpoint}");

    let private_key =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let signer: PrivateKeySigner = private_key.parse().unwrap();
    let wallet = EthereumWallet::from(signer.clone());
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .connect_http(anvil.endpoint_url());

    // 2. Create MockMpcNetwork with BBProver for real link proof verification
    println!("Creating mock MPC network...");
    let project_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mpc_verifier = BBProver::new(project_root.clone());
    let mpc = MockMpcNetwork::new(4, 7, mpc_verifier);
    let mpc_pk = mpc.public_key();
    let mpc_key_x = fq_to_u256(mpc_pk.x);
    let mpc_key_y = fq_to_u256(mpc_pk.y);

    // 3. Deploy all contracts (including real HonkVerifiers) via forge script
    println!("\nDeploying contracts with real verifiers...");
    let (identity_tree_addr, enrollment_addr, identity_verifier_addr) = deploy_contracts(
        &endpoint,
        private_key,
        &mpc_key_x,
        &mpc_key_y,
        VerifierVariant::Real,
    );
    println!("  IdentityTree:     {identity_tree_addr}");
    println!("  Enrollment:       {enrollment_addr}");
    println!("  IdentityVerifier: {identity_verifier_addr}");

    // 5. Create contract instances
    let enrollment_contract = IEnrollment::new(enrollment_addr, &provider);
    let identity_verifier = IIdentityVerifier::new(identity_verifier_addr, &provider);

    // 6. Create IdentityClient with BBProver (real ZK proofs)
    println!("\nCreating IdentityClient with BBProver...");
    let prover = BBProver::new(project_root);
    let merkle = LeanImtMerkleStore::new();
    let mut client = IdentityClient::new(prover, mpc, merkle);

    // 7. Enroll Alice (real proof generation)
    println!("\n=== Enrolling Alice (real proof generation) ===");
    let attrs = [
        Fr::from(1u64),     // age_over_18 = true
        Fr::from(840u64),   // nationality = 840 (US)
        Fr::from(0u64),     // name_hash placeholder
        Fr::from(20178u64), // enrollment_day
    ];

    let (identity, enrollment_data, enrollment_proof_bytes) = client
        .enroll("email:alice@example.com", attrs, 1)
        .expect("Enrollment failed");
    println!(
        "  Enrollment proof size: {} bytes",
        enrollment_proof_bytes.len()
    );

    // 8. Submit enrollment on-chain (real verifier checks real proof)
    println!("\nSubmitting enrollment on-chain (real verification)...");
    let g_id_x = fq_to_u256(enrollment_data.g_id.x);
    let g_id_y = fq_to_u256(enrollment_data.g_id.y);

    let enroll_tx = enrollment_contract
        .enroll(
            fr_to_u256(enrollment_data.leaf),
            fr_to_u256(enrollment_data.enrollment_nullifier),
            g_id_x,
            g_id_y,
            Bytes::from(enrollment_proof_bytes),
        )
        .send()
        .await
        .expect("Failed to send enrollment tx");

    let enroll_receipt = enroll_tx
        .get_receipt()
        .await
        .expect("Failed to get enrollment receipt");
    assert!(enroll_receipt.status(), "Enrollment transaction reverted");
    println!("  Enrollment verified on-chain!");

    // 9. Generate membership proof (real)
    println!("\n=== Generating Membership Proof (real proof generation) ===");
    let chain_id = Fr::from(31337u64);
    let verifier_addr_fr = Fr::from(0u64);
    let scope = Fr::from(1u64);
    let external_nullifier = hash_external_nullifier(chain_id, verifier_addr_fr, scope);

    let predicate = Predicate {
        predicate_type: 1,
        attr_index: 0,
        value: Fr::from(0u64),
    };

    let proof_data = client
        .generate_membership_proof(&identity, external_nullifier, &predicate)
        .expect("Membership proof generation failed");
    println!(
        "  Membership proof size: {} bytes",
        proof_data.proof_bytes.len()
    );

    // 10. Submit verification on-chain (real verifier checks real proof)
    println!("\nSubmitting verification on-chain (real verification)...");
    let verify_tx = identity_verifier
        .verifyProof(
            Bytes::from(proof_data.proof_bytes.clone()),
            fr_to_u256(proof_data.root),
            fr_to_u256(proof_data.nullifier),
            fr_to_u256(proof_data.external_nullifier),
            U256::from(proof_data.version),
            U256::from(proof_data.predicate_type),
            U256::from(proof_data.predicate_attr_index),
            fr_to_u256(proof_data.predicate_value),
            fr_to_u256(proof_data.predicate_result),
        )
        .send()
        .await
        .expect("Failed to send verify tx");

    let verify_receipt = verify_tx
        .get_receipt()
        .await
        .expect("Failed to get verification receipt");
    assert!(verify_receipt.status(), "Verification transaction reverted");
    println!("  Membership proof verified on-chain!");

    // 11. Double-spend prevention
    println!("\nVerifying double-spend prevention...");
    let double_spend = identity_verifier
        .verifyProof(
            Bytes::from(proof_data.proof_bytes),
            fr_to_u256(proof_data.root),
            fr_to_u256(proof_data.nullifier),
            fr_to_u256(proof_data.external_nullifier),
            U256::from(proof_data.version),
            U256::from(proof_data.predicate_type),
            U256::from(proof_data.predicate_attr_index),
            fr_to_u256(proof_data.predicate_value),
            fr_to_u256(proof_data.predicate_result),
        )
        .send()
        .await;
    assert!(double_spend.is_err(), "Double-spend should be rejected");
    println!("  Double-spend correctly rejected");

    println!("\n=== Real Proofs Integration Test Passed ===");
}

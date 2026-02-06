//! DIY Validium Host - Proof generation and verification
//!
//! This is the host program that runs outside the zkVM. It:
//! - Prepares sample allowlist data (account commitments)
//! - Builds a Merkle tree and generates an inclusion proof
//! - Executes the guest program in the zkVM to generate a ZK proof
//! - Verifies the proof locally
//!
//! NOTE: Uses tree depth 4 (16 leaf slots) instead of 20 (~1M) for
//! faster demo proving times. Production would use depth 20 per SPEC.md.

use anyhow::Result;
use diy_validium_host::merkle::{account_commitment, MerkleTree};

fn main() -> Result<()> {
    // --- 1. Create sample allowlist accounts ---
    // Each account is (pubkey, balance, salt) -> commitment leaf.
    let accounts: Vec<([u8; 32], u64, [u8; 32])> = (0..6)
        .map(|i| {
            let mut pubkey = [0u8; 32];
            pubkey[0] = i as u8;
            let balance = 1000 * (i + 1) as u64;
            let mut salt = [0u8; 32];
            salt[31] = i as u8;
            (pubkey, balance, salt)
        })
        .collect();

    let leaves: Vec<[u8; 32]> = accounts
        .iter()
        .map(|(pk, bal, salt)| account_commitment(pk, *bal, salt))
        .collect();

    println!("Created {} account commitments", leaves.len());

    // --- 2. Build Merkle tree (depth 4 for demo speed) ---
    // Depth 4 = 16 leaf slots. Production uses depth 20 (~1M slots).
    let tree = MerkleTree::from_leaves(&leaves, 4);
    let root = tree.root();
    println!("Merkle root: 0x{}", hex::encode(root));

    // --- 3. Generate inclusion proof for leaf at index 0 ---
    let prover_index: usize = 0;
    let leaf = leaves[prover_index];
    let proof = tree.prove(prover_index);

    println!(
        "Proving membership for leaf {}: 0x{}...",
        prover_index,
        hex::encode(&leaf[..8])
    );
    println!("Proof path length: {} siblings", proof.path.len());

    // Sanity-check the proof off-chain before entering the zkVM
    assert!(
        proof.verify(leaf, root),
        "Off-chain Merkle proof verification failed — bug in tree/proof code"
    );
    println!("Off-chain proof verification: OK");

    // --- 4. Build ExecutorEnv (must match guest env::read() order) ---
    // Guest reads: leaf, path, indices, expected_root
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&leaf)?
        .write(&proof.path)?
        .write(&proof.indices)?
        .write(&root)?
        .build()?;

    // --- 5. Generate ZK proof ---
    // When RISC0_DEV_MODE=1 is set, this uses a fake prover for speed.
    println!("Starting proof generation (set RISC0_DEV_MODE=1 for fast dev mode)...");
    let prover = risc0_zkvm::default_prover();
    let prove_info = prover.prove(env, methods::MEMBERSHIP_ELF)?;
    let receipt = prove_info.receipt;
    println!("Proof generated successfully!");

    // --- 6. Verify the receipt locally ---
    receipt.verify(methods::MEMBERSHIP_ID)?;
    println!("Receipt verified locally: OK");

    // --- 7. Extract journal (committed public outputs) and seal ---
    let journal_bytes = &receipt.journal.bytes;
    println!(
        "Journal ({} bytes): 0x{}",
        journal_bytes.len(),
        hex::encode(journal_bytes)
    );

    // Deserialize the committed root from the journal (serde-encoded by the guest)
    let journal_root: [u8; 32] = receipt.journal.decode()?;
    println!("Journal root: 0x{}", hex::encode(journal_root));
    assert_eq!(
        journal_root, root,
        "Journal root should match the tree root"
    );
    println!("Journal root matches tree root: OK");

    // Print seal info for on-chain verification context
    let seal_bytes = receipt
        .inner
        .groth16()
        .map(|g| g.seal.clone())
        .unwrap_or_default();
    if seal_bytes.is_empty() {
        println!("Seal: not available (dev-mode receipts have no cryptographic seal)");
    } else {
        println!(
            "Seal ({} bytes): 0x{}...",
            seal_bytes.len() * 4,
            hex::encode(&seal_bytes[..4])
        );
    }

    println!("\nPhase 1 membership proof complete.");

    Ok(())
}

//! DIY Validium Host - Proof generation and verification
//!
//! Demonstrates both Phase 1 (membership) and Phase 2 (balance) proof flows.
//! Builds a Merkle tree from sample accounts, then:
//!   Phase 1: Proves an account is in the allowlist
//!   Phase 2: Proves an account has balance >= required_amount
//!
//! NOTE: Uses tree depth 4 (16 leaf slots) instead of 20 (~1M) for
//! faster demo proving times. Production would use depth 20 per SPEC.md.

use anyhow::Result;
use diy_validium_host::accounts::{Account, AccountStore};
use diy_validium_host::merkle::account_commitment;

fn main() -> Result<()> {
    // --- 1. Create sample accounts using AccountStore ---
    let mut store = AccountStore::new();
    for i in 0..6u8 {
        let mut pubkey = [0u8; 32];
        pubkey[0] = i;
        let balance = 1000 * (i as u64 + 1);
        let mut salt = [0u8; 32];
        salt[31] = i;
        store.add_account(Account {
            pubkey,
            balance,
            salt,
        });
    }

    println!("Created {} accounts", store.len());

    // --- 2. Build Merkle tree (depth 4 for demo speed) ---
    let tree = store.build_tree(4);
    let root = tree.root();
    println!("Merkle root: 0x{}", hex::encode(root));

    // ===================================================================
    // Phase 1: Membership proof
    // ===================================================================
    println!("\n--- Phase 1: Membership Proof ---");

    let prover_index: usize = 0;
    let commitments = store.commitments();
    let leaf = commitments[prover_index];
    let proof = tree.prove(prover_index);

    println!(
        "Proving membership for leaf {}: 0x{}...",
        prover_index,
        hex::encode(&leaf[..8])
    );

    // Sanity-check the proof off-chain before entering the zkVM
    assert!(
        proof.verify(leaf, root),
        "Off-chain Merkle proof verification failed"
    );
    println!("Off-chain proof verification: OK");

    // Build ExecutorEnv (must match guest env::read() order)
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&leaf)?
        .write(&proof.path)?
        .write(&proof.indices)?
        .write(&root)?
        .build()?;

    println!("Starting membership proof generation (set RISC0_DEV_MODE=1 for fast dev mode)...");
    let prover = risc0_zkvm::default_prover();
    let prove_info = prover.prove(env, methods::MEMBERSHIP_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(methods::MEMBERSHIP_ID)?;
    println!("Membership proof verified: OK");

    let journal_root: [u8; 32] = receipt.journal.decode()?;
    assert_eq!(journal_root, root, "Journal root should match tree root");
    println!("Journal root matches: OK");

    // ===================================================================
    // Phase 2: Balance proof
    // ===================================================================
    println!("\n--- Phase 2: Balance Proof ---");

    let balance_index: usize = 0;
    let acct = store.get_account(balance_index);
    let required_amount: u64 = 500;

    println!(
        "Proving account {} has balance >= {} (actual: {})",
        balance_index, required_amount, acct.balance
    );

    // Verify off-chain first
    let balance_leaf = account_commitment(&acct.pubkey, acct.balance, &acct.salt);
    let balance_proof = tree.prove(balance_index);
    assert!(
        balance_proof.verify(balance_leaf, root),
        "Off-chain balance proof verification failed"
    );
    println!("Off-chain balance proof verification: OK");

    // Build ExecutorEnv for balance guest (must match guest env::read() order)
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&acct.pubkey)?
        .write(&acct.balance)?
        .write(&acct.salt)?
        .write(&balance_proof.path)?
        .write(&balance_proof.indices)?
        .write(&root)?
        .write(&required_amount)?
        .build()?;

    println!("Starting balance proof generation...");
    let prove_info = prover.prove(env, methods::BALANCE_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(methods::BALANCE_ID)?;
    println!("Balance proof verified: OK");

    // Extract journal: root (32 bytes) + required_amount big-endian (8 bytes)
    let journal_bytes = &receipt.journal.bytes;
    println!(
        "Journal ({} bytes): 0x{}",
        journal_bytes.len(),
        hex::encode(journal_bytes)
    );

    let journal_root: [u8; 32] = journal_bytes[..32].try_into()?;
    let journal_amount = u64::from_be_bytes(journal_bytes[32..40].try_into()?);
    assert_eq!(journal_root, root, "Balance journal root should match");
    assert_eq!(
        journal_amount, required_amount,
        "Balance journal amount should match"
    );
    println!(
        "Journal: root matches, required_amount={}: OK",
        journal_amount
    );

    println!("\nPhase 1 + Phase 2 proofs complete.");

    Ok(())
}

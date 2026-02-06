//! DIY Validium Host - Proof generation and verification
//!
//! Demonstrates the full institutional lifecycle:
//!   Phase 1: Proves an account is in the allowlist (membership proof)
//!   Phase 2: Proves an account has balance >= required_amount (balance proof)
//!   Phase 3: Proves a valid private transfer between two accounts (transfer proof)
//!   Phase 4a: Proves a valid withdrawal from private to on-chain ERC20 (withdrawal proof)
//!   Phase 4b: Proves balance >= threshold to a specific auditor (disclosure proof)
//!
//! NOTE: Uses tree depth 4 (16 leaf slots) instead of 20 (~1M) for
//! faster demo proving times. Production would use depth 20 per SPEC.md.

use anyhow::Result;
use diy_validium_host::accounts::{Account, AccountStore};
use diy_validium_host::merkle::{
    account_commitment, compute_disclosure_key_hash, compute_new_root, compute_single_leaf_root,
};
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    // --- 1. Create sample accounts using AccountStore ---
    // Accounts use pubkey = SHA256(sk) derivation, where sk = [i, 0, 0, ...].
    let mut store = AccountStore::new();
    for i in 0..6u8 {
        let mut sk = [0u8; 32];
        sk[0] = i;
        let pubkey: [u8; 32] = Sha256::digest(sk).into();
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

    // ===================================================================
    // Phase 3: Transfer proof
    // ===================================================================
    println!("\n--- Phase 3: Transfer Proof ---");

    let sender_idx: usize = 0;
    let recipient_idx: usize = 1;
    let amount: u64 = 500;

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    // Derive sender SK (same pattern as account creation: sk[0] = index)
    let sender_sk = {
        let mut sk = [0u8; 32];
        sk[0] = sender_idx as u8;
        sk
    };

    println!(
        "Transfer: account {} -> account {}, amount = {}",
        sender_idx, recipient_idx, amount
    );
    println!(
        "  Sender balance:    {} -> {}",
        sender.balance,
        sender.balance - amount
    );
    println!(
        "  Recipient balance: {} -> {}",
        recipient.balance,
        recipient.balance + amount
    );

    let sender_proof = tree.prove(sender_idx);
    let recipient_proof = tree.prove(recipient_idx);

    // Fresh salts for new commitments
    let new_sender_salt: [u8; 32] = Sha256::digest(b"new_sender_salt_demo").into();
    let new_recipient_salt: [u8; 32] = Sha256::digest(b"new_recipient_salt_demo").into();

    // Compute expected new root via dual-leaf recomputation (for verification)
    let sender_new_leaf =
        account_commitment(&sender.pubkey, sender.balance - amount, &new_sender_salt);
    let recipient_new_leaf = account_commitment(
        &recipient.pubkey,
        recipient.balance + amount,
        &new_recipient_salt,
    );
    let expected_new_root = compute_new_root(
        sender_new_leaf,
        &sender_proof.indices,
        recipient_new_leaf,
        &recipient_proof.indices,
        &sender_proof.path,
        &recipient_proof.path,
    );

    // Compute expected nullifier: SHA256(sender_sk || old_root || "transfer_v1")
    let expected_nullifier: [u8; 32] =
        Sha256::digest([&sender_sk[..], &root[..], b"transfer_v1"].concat()).into();

    // Build ExecutorEnv (must match guest env::read() order in transfer.rs)
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&sender_sk)?
        .write(&sender.balance)?
        .write(&sender.salt)?
        .write(&sender_proof.path)?
        .write(&sender_proof.indices)?
        .write(&amount)?
        .write(&recipient.pubkey)?
        .write(&recipient.balance)?
        .write(&recipient.salt)?
        .write(&recipient_proof.path)?
        .write(&recipient_proof.indices)?
        .write(&new_sender_salt)?
        .write(&new_recipient_salt)?
        .build()?;

    println!("Starting transfer proof generation...");
    let prove_info = prover.prove(env, methods::TRANSFER_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(methods::TRANSFER_ID)?;
    println!("Transfer proof verified: OK");

    // Extract journal: old_root (32) + new_root (32) + nullifier (32) = 96 bytes
    let journal_bytes = &receipt.journal.bytes;
    assert_eq!(
        journal_bytes.len(),
        96,
        "Transfer journal should be 96 bytes"
    );

    let journal_old_root: [u8; 32] = journal_bytes[..32].try_into()?;
    let journal_new_root: [u8; 32] = journal_bytes[32..64].try_into()?;
    let journal_nullifier: [u8; 32] = journal_bytes[64..96].try_into()?;

    assert_eq!(journal_old_root, root, "Journal old_root should match");
    assert_eq!(
        journal_new_root, expected_new_root,
        "Journal new_root should match expected"
    );
    assert_eq!(
        journal_nullifier, expected_nullifier,
        "Journal nullifier should match expected"
    );

    println!(
        "Journal: old_root=0x{}..., new_root=0x{}..., nullifier=0x{}...",
        hex::encode(&journal_old_root[..4]),
        hex::encode(&journal_new_root[..4]),
        hex::encode(&journal_nullifier[..4]),
    );
    println!("All journal fields match: OK");

    // ===================================================================
    // Phase 4a: Withdrawal proof
    // ===================================================================
    println!("\n--- Phase 4a: Withdrawal Proof ---");

    let withdraw_idx: usize = 2;
    let withdraw_acct = store.get_account(withdraw_idx);
    let withdraw_amount: u64 = 500;
    let withdraw_sk = {
        let mut sk = [0u8; 32];
        sk[0] = withdraw_idx as u8;
        sk
    };
    let recipient: [u8; 20] = [0xAB; 20];
    let new_withdraw_salt: [u8; 32] = Sha256::digest(b"new_withdrawal_salt_demo").into();

    println!(
        "Withdrawing {} from account {} (balance: {}) to 0x{}",
        withdraw_amount,
        withdraw_idx,
        withdraw_acct.balance,
        hex::encode(recipient),
    );

    let withdraw_proof = tree.prove(withdraw_idx);

    // Compute expected outputs for journal verification
    let withdraw_pubkey: [u8; 32] = Sha256::digest(withdraw_sk).into();
    let new_withdraw_leaf = account_commitment(
        &withdraw_pubkey,
        withdraw_acct.balance - withdraw_amount,
        &new_withdraw_salt,
    );
    let expected_withdraw_new_root = compute_single_leaf_root(
        new_withdraw_leaf,
        &withdraw_proof.path,
        &withdraw_proof.indices,
    );
    let expected_withdraw_nullifier: [u8; 32] =
        Sha256::digest([&withdraw_sk[..], &root[..], b"withdrawal_v1"].concat()).into();

    // Build ExecutorEnv (must match guest env::read() order in withdrawal.rs)
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&withdraw_sk)?
        .write(&withdraw_acct.balance)?
        .write(&withdraw_acct.salt)?
        .write(&withdraw_proof.path)?
        .write(&withdraw_proof.indices)?
        .write(&withdraw_amount)?
        .write(&new_withdraw_salt)?
        .write(&recipient)?
        .build()?;

    println!("Starting withdrawal proof generation...");
    let prove_info = prover.prove(env, methods::WITHDRAWAL_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(methods::WITHDRAWAL_ID)?;
    println!("Withdrawal proof verified: OK");

    // Extract journal: old_root(32) + new_root(32) + nullifier(32) + amount_be(8) + recipient(20) = 124 bytes
    let journal_bytes = &receipt.journal.bytes;
    assert_eq!(
        journal_bytes.len(),
        124,
        "Withdrawal journal should be 124 bytes"
    );

    let j_old_root: [u8; 32] = journal_bytes[..32].try_into()?;
    let j_new_root: [u8; 32] = journal_bytes[32..64].try_into()?;
    let j_nullifier: [u8; 32] = journal_bytes[64..96].try_into()?;
    let j_amount = u64::from_be_bytes(journal_bytes[96..104].try_into()?);
    let j_recipient: [u8; 20] = journal_bytes[104..124].try_into()?;

    assert_eq!(j_old_root, root, "Withdrawal old_root should match");
    assert_eq!(
        j_new_root, expected_withdraw_new_root,
        "Withdrawal new_root should match"
    );
    assert_eq!(
        j_nullifier, expected_withdraw_nullifier,
        "Withdrawal nullifier should match"
    );
    assert_eq!(j_amount, withdraw_amount, "Withdrawal amount should match");
    assert_eq!(j_recipient, recipient, "Withdrawal recipient should match");

    println!(
        "Journal (124 bytes): old_root=0x{}..., new_root=0x{}..., nullifier=0x{}..., amount={}, recipient=0x{}",
        hex::encode(&j_old_root[..4]),
        hex::encode(&j_new_root[..4]),
        hex::encode(&j_nullifier[..4]),
        j_amount,
        hex::encode(j_recipient),
    );
    println!("All withdrawal journal fields match: OK");

    // ===================================================================
    // Phase 4b: Disclosure proof
    // ===================================================================
    println!("\n--- Phase 4b: Disclosure Proof ---");

    let disclosure_idx: usize = 3;
    let disclosure_acct = store.get_account(disclosure_idx);
    let threshold: u64 = 2000;
    let disclosure_sk = {
        let mut sk = [0u8; 32];
        sk[0] = disclosure_idx as u8;
        sk
    };
    let auditor_pubkey: [u8; 32] = Sha256::digest(b"auditor_pubkey_demo").into();

    println!(
        "Proving account {} has balance >= {} (actual: {}) to auditor 0x{}...",
        disclosure_idx,
        threshold,
        disclosure_acct.balance,
        hex::encode(&auditor_pubkey[..8]),
    );

    let disclosure_proof = tree.prove(disclosure_idx);

    // Compute expected disclosure key hash
    let disclosure_pubkey: [u8; 32] = Sha256::digest(disclosure_sk).into();
    let expected_dkh = compute_disclosure_key_hash(&disclosure_pubkey, &auditor_pubkey);

    // Build ExecutorEnv (must match guest env::read() order in disclosure.rs)
    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&disclosure_sk)?
        .write(&disclosure_acct.balance)?
        .write(&disclosure_acct.salt)?
        .write(&disclosure_proof.path)?
        .write(&disclosure_proof.indices)?
        .write(&threshold)?
        .write(&auditor_pubkey)?
        .build()?;

    println!("Starting disclosure proof generation...");
    let prove_info = prover.prove(env, methods::DISCLOSURE_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(methods::DISCLOSURE_ID)?;
    println!("Disclosure proof verified: OK");

    // Extract journal: merkle_root(32) + threshold_be(8) + disclosure_key_hash(32) = 72 bytes
    let journal_bytes = &receipt.journal.bytes;
    assert_eq!(
        journal_bytes.len(),
        72,
        "Disclosure journal should be 72 bytes"
    );

    let j_root: [u8; 32] = journal_bytes[..32].try_into()?;
    let j_threshold = u64::from_be_bytes(journal_bytes[32..40].try_into()?);
    let j_dkh: [u8; 32] = journal_bytes[40..72].try_into()?;

    assert_eq!(j_root, root, "Disclosure root should match");
    assert_eq!(j_threshold, threshold, "Disclosure threshold should match");
    assert_eq!(j_dkh, expected_dkh, "Disclosure key hash should match");

    println!(
        "Journal (72 bytes): root=0x{}..., threshold={}, disclosure_key_hash=0x{}...",
        hex::encode(&j_root[..4]),
        j_threshold,
        hex::encode(&j_dkh[..4]),
    );
    println!("All disclosure journal fields match: OK");
    println!(
        "\nAuditor learns: account satisfies balance >= {}",
        threshold
    );
    println!("Auditor does NOT learn: actual balance, pubkey, or tree position");

    println!("\nAll phases complete (Phase 1 + Phase 2 + Phase 3 + Phase 4a + Phase 4b).");

    Ok(())
}

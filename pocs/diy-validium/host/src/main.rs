//! DIY Validium Host - Proof generation and verification
//!
//! Demonstrates three core institutional privacy operations:
//!   1. Transfer: Private payment between accounts (ZK-proven state transition)
//!   2. Withdrawal: Proven exit from private system to on-chain ERC20
//!   3. Disclosure: Prove compliance to a regulator without revealing balances
//!
//! NOTE: Uses tree depth 4 (16 leaf slots) instead of 20 (~1M) for
//! faster demo proving times. Production would use depth 20 per SPEC.md.

use anyhow::Result;
use diy_validium_host::accounts::{Account, AccountStore};
use diy_validium_host::journal::{DisclosureJournal, TransferJournal, WithdrawalJournal};
use diy_validium_host::merkle::{
    account_commitment, compute_disclosure_key_hash, compute_new_root, compute_single_leaf_root,
};
use sha2::{Digest, Sha256};

fn main() -> Result<()> {
    // --- Setup: Create sample accounts ---
    let mut store = AccountStore::new();
    for i in 0..6u8 {
        let sk = [i; 32];
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

    // Build Merkle tree (depth 4 for demo speed)
    let tree = store.build_tree(4);
    let root = tree.root();
    println!("Merkle root: 0x{}", hex::encode(root));

    // ===================================================================
    // 1. Transfer: Private payment between accounts
    // ===================================================================
    println!("\n--- Transfer: Private Payment ---");

    let sender_idx: usize = 0;
    let recipient_idx: usize = 1;
    let amount: u64 = 500;

    let sender = store.get_account(sender_idx);
    let recipient = store.get_account(recipient_idx);

    let sender_sk = [sender_idx as u8; 32];

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

    let new_sender_salt: [u8; 32] = Sha256::digest(b"new_sender_salt_demo").into();
    let new_recipient_salt: [u8; 32] = Sha256::digest(b"new_recipient_salt_demo").into();

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

    let sender_old_leaf = account_commitment(&sender.pubkey, sender.balance, &sender.salt);
    let expected_nullifier: [u8; 32] =
        Sha256::digest([&sender_sk[..], &sender_old_leaf[..], b"transfer_v1"].concat()).into();

    // NOTE: Each env.write() is a separate syscall. Production code should batch
    // these into a single struct to minimize overhead.
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

    println!("Starting transfer proof generation (set RISC0_DEV_MODE=1 for fast dev mode)...");
    // RISC Zero supports multiple proof types via ProverOpts: composite (default),
    // succinct (smaller), and groth16 (on-chain verifiable). See ProverOpts docs.
    let prover = risc0_zkvm::default_prover();
    let prove_info = prover.prove(env, methods::TRANSFER_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(methods::TRANSFER_ID)?;
    println!("Transfer proof verified: OK");

    let tj = TransferJournal::from_bytes(&receipt.journal.bytes)?;

    assert_eq!(tj.old_root, root);
    assert_eq!(tj.new_root, expected_new_root);
    assert_eq!(tj.nullifier, expected_nullifier);

    println!(
        "Journal: old_root=0x{}..., new_root=0x{}..., nullifier=0x{}...",
        hex::encode(&tj.old_root[..4]),
        hex::encode(&tj.new_root[..4]),
        hex::encode(&tj.nullifier[..4]),
    );
    println!("All journal fields match: OK");

    // ===================================================================
    // 2. Withdrawal: Proven exit to on-chain ERC20
    // ===================================================================
    println!("\n--- Withdrawal: Proven Exit to L1 ---");

    let withdraw_idx: usize = 2;
    let withdraw_acct = store.get_account(withdraw_idx);
    let withdraw_amount: u64 = 500;
    let withdraw_sk = [withdraw_idx as u8; 32];
    let eth_recipient: [u8; 20] = [0xAB; 20];
    let new_withdraw_salt: [u8; 32] = Sha256::digest(b"new_withdrawal_salt_demo").into();

    println!(
        "Withdrawing {} from account {} (balance: {}) to 0x{}",
        withdraw_amount,
        withdraw_idx,
        withdraw_acct.balance,
        hex::encode(eth_recipient),
    );

    let withdraw_proof = tree.prove(withdraw_idx);

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
    let withdraw_old_leaf =
        account_commitment(&withdraw_pubkey, withdraw_acct.balance, &withdraw_acct.salt);
    let expected_withdraw_nullifier: [u8; 32] =
        Sha256::digest([&withdraw_sk[..], &withdraw_old_leaf[..], b"withdrawal_v1"].concat())
            .into();

    let env = risc0_zkvm::ExecutorEnv::builder()
        .write(&withdraw_sk)?
        .write(&withdraw_acct.balance)?
        .write(&withdraw_acct.salt)?
        .write(&withdraw_proof.path)?
        .write(&withdraw_proof.indices)?
        .write(&withdraw_amount)?
        .write(&new_withdraw_salt)?
        .write(&eth_recipient)?
        .build()?;

    println!("Starting withdrawal proof generation...");
    let prove_info = prover.prove(env, methods::WITHDRAWAL_ELF)?;
    let receipt = prove_info.receipt;

    receipt.verify(methods::WITHDRAWAL_ID)?;
    println!("Withdrawal proof verified: OK");

    let wj = WithdrawalJournal::from_bytes(&receipt.journal.bytes)?;

    assert_eq!(wj.old_root, root);
    assert_eq!(wj.new_root, expected_withdraw_new_root);
    assert_eq!(wj.nullifier, expected_withdraw_nullifier);
    assert_eq!(wj.amount, withdraw_amount);
    assert_eq!(wj.recipient, eth_recipient);

    println!(
        "Journal (124 bytes): old_root=0x{}..., new_root=0x{}..., nullifier=0x{}..., amount={}, recipient=0x{}",
        hex::encode(&wj.old_root[..4]),
        hex::encode(&wj.new_root[..4]),
        hex::encode(&wj.nullifier[..4]),
        wj.amount,
        hex::encode(wj.recipient),
    );
    println!("All withdrawal journal fields match: OK");

    // ===================================================================
    // 3. Disclosure: Prove compliance without revealing balances
    // ===================================================================
    println!("\n--- Disclosure: Regulatory Compliance Proof ---");

    let disclosure_idx: usize = 3;
    let disclosure_acct = store.get_account(disclosure_idx);
    let threshold: u64 = 2000;
    let disclosure_sk = [disclosure_idx as u8; 32];
    let auditor_pubkey: [u8; 32] = Sha256::digest(b"auditor_pubkey_demo").into();

    println!(
        "Proving account {} has balance >= {} (actual: {}) to auditor 0x{}...",
        disclosure_idx,
        threshold,
        disclosure_acct.balance,
        hex::encode(&auditor_pubkey[..8]),
    );

    let disclosure_proof = tree.prove(disclosure_idx);

    let disclosure_pubkey: [u8; 32] = Sha256::digest(disclosure_sk).into();
    let expected_dkh = compute_disclosure_key_hash(&disclosure_pubkey, &auditor_pubkey);

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

    let dj = DisclosureJournal::from_bytes(&receipt.journal.bytes)?;

    assert_eq!(dj.merkle_root, root);
    assert_eq!(dj.threshold, threshold);
    assert_eq!(dj.disclosure_key_hash, expected_dkh);

    println!(
        "Journal (72 bytes): root=0x{}..., threshold={}, disclosure_key_hash=0x{}...",
        hex::encode(&dj.merkle_root[..4]),
        dj.threshold,
        hex::encode(&dj.disclosure_key_hash[..4]),
    );
    println!("All disclosure journal fields match: OK");
    println!(
        "\nAuditor learns: account satisfies balance >= {}",
        threshold
    );
    println!("Auditor does NOT learn: actual balance, pubkey, or tree position");

    println!("\nAll operations complete (Transfer + Withdrawal + Disclosure).");

    Ok(())
}

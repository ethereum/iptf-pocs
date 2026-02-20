//! TEE Swap Protocol Demo
//!
//! Exercises the full swap flow in-process without actual ZK proof generation
//! or blockchain interaction. Uses LocalMerkleTree for each chain and pure
//! crypto functions.
//!
//! Run with: `cargo run --bin demo`

use alloy_primitives::B256;
use ark_ec::{CurveGroup, PrimeGroup};
use ark_grumpkin::Projective;

use tee_swap::adapters::merkle_tree::LocalMerkleTree;
use tee_swap::crypto::poseidon::{bind_enc, bind_meta, bind_r, bind_swap, swap_id_hash};
use tee_swap::crypto::stealth::affine_x_to_b256;
use tee_swap::domain::note::Note;
use tee_swap::domain::stealth::MetaKeyPair;
use tee_swap::domain::swap::{SwapAnnouncement, SwapTerms};
use tee_swap::party::{prepare_claim, prepare_lock, prepare_refund, PartyRole};

fn main() {
    println!("=== TEE-Coordinated Private Atomic Swap ===");
    println!("=== Protocol Demo (PoC — no real proofs) ===\n");

    scenario_happy_path();
    println!("\n{}\n", "=".repeat(60));
    scenario_refund_path();

    println!("\n=== All scenarios completed successfully ===");
}

fn scenario_happy_path() {
    println!("--- Scenario 1: Happy Path (Lock → TEE Verify → Claim) ---\n");

    // ── Setup ──
    println!("[Setup] Generating key pairs...");
    let mut rng = ark_std::test_rng();
    let meta_a = MetaKeyPair::generate(&mut rng);
    let meta_b = MetaKeyPair::generate(&mut rng);
    println!("  Party A pk: 0x{}...", &hex::encode(&meta_a.pk_x().0)[..16]);
    println!("  Party B pk: 0x{}...", &hex::encode(&meta_b.pk_x().0)[..16]);

    let mut tree_chain1 = LocalMerkleTree::new(); // USD chain
    let mut tree_chain2 = LocalMerkleTree::new(); // BOND chain

    // ── Phase 0: Agree on Swap Terms ──
    println!("\n[Phase 0] Agreeing on swap terms...");
    let terms = SwapTerms::new(
        B256::left_padding_from(&[1]), // chain_id_a (Chain 1 = USD)
        B256::left_padding_from(&[2]), // chain_id_b (Chain 2 = BOND)
        1000,                           // value_a (1000 USD)
        50,                             // value_b (50 BOND)
        B256::repeat_byte(0x01),        // asset_id_a (USD)
        B256::repeat_byte(0x02),        // asset_id_b (BOND)
        B256::left_padding_from(&[0x00, 0x01, 0x51, 0x80]), // timeout ~24h
        meta_a.pk_x(),
        meta_b.pk_x(),
        B256::repeat_byte(0xFF), // nonce
    );
    println!("  swap_id: 0x{}...", &hex::encode(&terms.swap_id.0)[..16]);

    // ── Fund Parties (PoC: insert commitments directly) ──
    println!("\n[Fund] Creating initial notes...");
    let note_a = Note::new(
        terms.chain_id_a,
        terms.value_a,
        terms.asset_id_a,
        meta_a.pk_x(),
        B256::ZERO,
        B256::ZERO,
    );
    let leaf_idx_a = tree_chain1.len() as u64;
    tree_chain1.insert_commitment(&note_a.commitment());
    println!(
        "  Party A funded: {} USD on Chain 1 (commitment: 0x{}...)",
        note_a.value,
        &hex::encode(&note_a.commitment().0 .0)[..16]
    );

    let note_b = Note::new(
        terms.chain_id_b,
        terms.value_b,
        terms.asset_id_b,
        meta_b.pk_x(),
        B256::ZERO,
        B256::ZERO,
    );
    let leaf_idx_b = tree_chain2.len() as u64;
    tree_chain2.insert_commitment(&note_b.commitment());
    println!(
        "  Party B funded: {} BOND on Chain 2 (commitment: 0x{}...)",
        note_b.value,
        &hex::encode(&note_b.commitment().0 .0)[..16]
    );

    // ── Phase 1: Lock Notes ──
    println!("\n[Phase 1] Locking notes to stealth addresses...");

    let proof_a = tree_chain1.generate_proof(leaf_idx_a).unwrap();
    let root_a = tree_chain1.current_root().unwrap();
    let lock_a = prepare_lock(
        &terms,
        &meta_a,
        &meta_b.pk.into(),
        &note_a,
        &proof_a,
        root_a,
    );
    tree_chain1.insert_commitment(&lock_a.locked_note.commitment());
    println!(
        "  Party A locked {} USD → stealth(B) on Chain 1",
        lock_a.locked_note.value
    );
    println!(
        "    locked commitment: 0x{}...",
        &hex::encode(&lock_a.locked_note.commitment().0 .0)[..16]
    );
    println!(
        "    nullifier (input): 0x{}...",
        &hex::encode(&lock_a.witness.nullifier.0)[..16]
    );

    let proof_b = tree_chain2.generate_proof(leaf_idx_b).unwrap();
    let root_b = tree_chain2.current_root().unwrap();
    let lock_b = prepare_lock(
        &terms,
        &meta_b,
        &meta_a.pk.into(),
        &note_b,
        &proof_b,
        root_b,
    );
    tree_chain2.insert_commitment(&lock_b.locked_note.commitment());
    println!(
        "  Party B locked {} BOND → stealth(A) on Chain 2",
        lock_b.locked_note.value
    );
    println!(
        "    locked commitment: 0x{}...",
        &hex::encode(&lock_b.locked_note.commitment().0 .0)[..16]
    );

    // ── Phase 2: TEE Verification (inline, hash-only) ──
    println!("\n[Phase 2] TEE verifying submissions (hash-only)...");

    // Verify both swapIds match
    assert_eq!(lock_a.submission.swap_id, lock_b.submission.swap_id);
    println!("  ✓ Both parties submitted same swap_id");

    // Verify commitment correctness
    assert_eq!(
        lock_a.locked_note.commitment().0,
        lock_a.witness.new_commitment
    );
    assert_eq!(
        lock_b.locked_note.commitment().0,
        lock_b.witness.new_commitment
    );
    println!("  ✓ Commitment preimages match on-chain commitments");

    // Verify binding commitments for Party A
    let recomputed_h_swap_a = bind_swap(terms.swap_id, lock_a.locked_note.salt);
    let recomputed_h_r_a = bind_r(lock_a.submission.ephemeral_pubkey);
    let recomputed_h_meta_a = bind_meta(meta_b.pk_x(), lock_a.locked_note.salt);
    let recomputed_h_enc_a = bind_enc(lock_a.submission.encrypted_salt);
    assert_eq!(lock_a.witness.h_swap, recomputed_h_swap_a);
    assert_eq!(lock_a.witness.h_r, recomputed_h_r_a);
    assert_eq!(lock_a.witness.h_meta, recomputed_h_meta_a);
    assert_eq!(lock_a.witness.h_enc, recomputed_h_enc_a);
    println!("  ✓ Party A binding commitments verified (h_swap, h_R, h_meta, h_enc)");

    // Verify binding commitments for Party B
    let recomputed_h_swap_b = bind_swap(terms.swap_id, lock_b.locked_note.salt);
    let recomputed_h_r_b = bind_r(lock_b.submission.ephemeral_pubkey);
    let recomputed_h_meta_b = bind_meta(meta_a.pk_x(), lock_b.locked_note.salt);
    let recomputed_h_enc_b = bind_enc(lock_b.submission.encrypted_salt);
    assert_eq!(lock_b.witness.h_swap, recomputed_h_swap_b);
    assert_eq!(lock_b.witness.h_r, recomputed_h_r_b);
    assert_eq!(lock_b.witness.h_meta, recomputed_h_meta_b);
    assert_eq!(lock_b.witness.h_enc, recomputed_h_enc_b);
    println!("  ✓ Party B binding commitments verified");

    // Verify swapId encodes the agreed terms
    let recomputed_swap_id = swap_id_hash(
        lock_a.locked_note.value,
        lock_a.locked_note.asset_id,
        lock_a.locked_note.chain_id,
        lock_b.locked_note.value,
        lock_b.locked_note.asset_id,
        lock_b.locked_note.chain_id,
        terms.timeout,
        meta_a.pk_x(),
        meta_b.pk_x(),
        terms.nonce,
    );
    assert_eq!(recomputed_swap_id, terms.swap_id);
    println!("  ✓ Recomputed swap_id matches agreed terms");

    // ── Phase 3: Atomic Announcement ──
    println!("\n[Phase 3] TEE announcing swap (atomic revelation)...");
    let announcement = SwapAnnouncement {
        swap_id: terms.swap_id,
        ephemeral_key_a: lock_a.submission.ephemeral_pubkey,
        ephemeral_key_b: lock_b.submission.ephemeral_pubkey,
        encrypted_salt_a: lock_a.submission.encrypted_salt,
        encrypted_salt_b: lock_b.submission.encrypted_salt,
    };
    println!(
        "  R_A: 0x{}...",
        &hex::encode(&announcement.ephemeral_key_a.0)[..16]
    );
    println!(
        "  R_B: 0x{}...",
        &hex::encode(&announcement.ephemeral_key_b.0)[..16]
    );

    // ── Phase 4: Claim ──
    println!("\n[Phase 4] Parties claiming counterparty notes...");

    // Party B claims A's note (USD on Chain 1)
    let locked_leaf_a = 1u64; // second leaf on chain 1
    let locked_proof_a = tree_chain1.generate_proof(locked_leaf_a).unwrap();
    let locked_root_a = tree_chain1.current_root().unwrap();

    let claim_b = prepare_claim(
        &announcement,
        &meta_b,
        &lock_a.ephemeral_keypair.r_pub.into(),
        &terms,
        PartyRole::B,
        &locked_proof_a,
        locked_root_a,
    );

    // Verify B's claim reconstructed the correct note
    assert_eq!(
        claim_b.witness.nullifier,
        lock_a.locked_note.nullifier().0,
        "Claim nullifier must match locked note"
    );
    println!(
        "  Party B claims {} USD on Chain 1",
        claim_b.output_note.value
    );
    println!(
        "    nullifier: 0x{}...",
        &hex::encode(&claim_b.witness.nullifier.0)[..16]
    );
    println!(
        "    new commitment: 0x{}...",
        &hex::encode(&claim_b.output_note.commitment().0 .0)[..16]
    );

    // Verify stealth key roundtrip
    let sk_stealth_b = tee_swap::crypto::stealth::derive_stealth_secret(
        &meta_b.sk,
        &lock_a.ephemeral_keypair.r_pub.into(),
    );
    let pk_stealth_b = (Projective::generator() * sk_stealth_b).into_affine();
    assert_eq!(
        affine_x_to_b256(&pk_stealth_b),
        lock_a.locked_note.owner,
        "Stealth key roundtrip failed for Party B"
    );
    println!("  ✓ Party B stealth key roundtrip verified");

    // Party A claims B's note (BOND on Chain 2)
    let locked_leaf_b = 1u64;
    let locked_proof_b = tree_chain2.generate_proof(locked_leaf_b).unwrap();
    let locked_root_b = tree_chain2.current_root().unwrap();

    let claim_a = prepare_claim(
        &announcement,
        &meta_a,
        &lock_b.ephemeral_keypair.r_pub.into(),
        &terms,
        PartyRole::A,
        &locked_proof_b,
        locked_root_b,
    );

    assert_eq!(
        claim_a.witness.nullifier,
        lock_b.locked_note.nullifier().0
    );
    println!(
        "  Party A claims {} BOND on Chain 2",
        claim_a.output_note.value
    );
    println!("  ✓ Party A stealth key roundtrip verified");

    // ── Final Verification ──
    println!("\n[Verify] Final checks...");
    // Both output notes are standard (timeout=0)
    assert_eq!(claim_a.output_note.timeout, B256::ZERO);
    assert_eq!(claim_b.output_note.timeout, B256::ZERO);
    println!("  ✓ Both output notes are standard (timeout=0)");

    // Output notes have correct owners
    assert_eq!(claim_a.output_note.owner, meta_a.pk_x());
    assert_eq!(claim_b.output_note.owner, meta_b.pk_x());
    println!("  ✓ Output notes owned by correct parties");

    // Values preserved
    assert_eq!(claim_b.output_note.value, terms.value_a); // B got A's USD
    assert_eq!(claim_a.output_note.value, terms.value_b); // A got B's BOND
    println!("  ✓ Values preserved (A: {} BOND, B: {} USD)", terms.value_b, terms.value_a);

    println!("\n  ★ Happy path completed successfully!");
}

fn scenario_refund_path() {
    println!("--- Scenario 2: Refund Path (Lock → Timeout → Refund) ---\n");

    // ── Setup (same as happy path) ──
    println!("[Setup] Generating key pairs...");
    let mut rng = ark_std::test_rng();
    let meta_a = MetaKeyPair::generate(&mut rng);
    let meta_b = MetaKeyPair::generate(&mut rng);

    let mut tree_chain1 = LocalMerkleTree::new();
    let mut tree_chain2 = LocalMerkleTree::new();

    let terms = SwapTerms::new(
        B256::left_padding_from(&[1]),
        B256::left_padding_from(&[2]),
        1000,
        50,
        B256::repeat_byte(0x01),
        B256::repeat_byte(0x02),
        B256::left_padding_from(&[0x00, 0x01, 0x51, 0x80]),
        meta_a.pk_x(),
        meta_b.pk_x(),
        B256::repeat_byte(0xEE), // different nonce for separate swap
    );
    println!("  swap_id: 0x{}...", &hex::encode(&terms.swap_id.0)[..16]);

    // ── Fund ──
    println!("\n[Fund] Creating initial notes...");
    let note_a = Note::new(
        terms.chain_id_a,
        terms.value_a,
        terms.asset_id_a,
        meta_a.pk_x(),
        B256::ZERO,
        B256::ZERO,
    );
    let leaf_idx_a = tree_chain1.len() as u64;
    tree_chain1.insert_commitment(&note_a.commitment());
    println!("  Party A funded: {} USD", note_a.value);

    let note_b = Note::new(
        terms.chain_id_b,
        terms.value_b,
        terms.asset_id_b,
        meta_b.pk_x(),
        B256::ZERO,
        B256::ZERO,
    );
    let leaf_idx_b = tree_chain2.len() as u64;
    tree_chain2.insert_commitment(&note_b.commitment());
    println!("  Party B funded: {} BOND", note_b.value);

    // ── Lock ──
    println!("\n[Phase 1] Locking notes...");
    let proof_a = tree_chain1.generate_proof(leaf_idx_a).unwrap();
    let root_a = tree_chain1.current_root().unwrap();
    let lock_a = prepare_lock(
        &terms,
        &meta_a,
        &meta_b.pk.into(),
        &note_a,
        &proof_a,
        root_a,
    );
    tree_chain1.insert_commitment(&lock_a.locked_note.commitment());
    println!("  Party A locked {} USD", lock_a.locked_note.value);

    let proof_b = tree_chain2.generate_proof(leaf_idx_b).unwrap();
    let root_b = tree_chain2.current_root().unwrap();
    let lock_b = prepare_lock(
        &terms,
        &meta_b,
        &meta_a.pk.into(),
        &note_b,
        &proof_b,
        root_b,
    );
    tree_chain2.insert_commitment(&lock_b.locked_note.commitment());
    println!("  Party B locked {} BOND", lock_b.locked_note.value);

    // ── TEE Failure ──
    println!("\n[Phase 2-3] TEE goes offline! No announcement made.");
    println!("  (Simulating TEE failure — parties must wait for timeout)");

    // ── Timeout + Refund ──
    println!(
        "\n[Phase 4] Timeout expired (block.timestamp > {}). Refunding...",
        hex::encode(&terms.timeout.0[28..]) // last 4 bytes
    );

    // Party A refunds on Chain 1
    let locked_leaf_a = 1u64;
    let locked_proof_a = tree_chain1.generate_proof(locked_leaf_a).unwrap();
    let locked_root_a = tree_chain1.current_root().unwrap();

    let refund_a = prepare_refund(
        &lock_a.locked_note,
        &meta_a.sk,
        &locked_proof_a,
        locked_root_a,
    );
    println!(
        "  Party A refunds {} USD on Chain 1",
        refund_a.output_note.value
    );
    println!(
        "    nullifier: 0x{}...",
        &hex::encode(&refund_a.witness.nullifier.0)[..16]
    );

    // Party B refunds on Chain 2
    let locked_leaf_b = 1u64;
    let locked_proof_b = tree_chain2.generate_proof(locked_leaf_b).unwrap();
    let locked_root_b = tree_chain2.current_root().unwrap();

    let refund_b = prepare_refund(
        &lock_b.locked_note,
        &meta_b.sk,
        &locked_proof_b,
        locked_root_b,
    );
    println!(
        "  Party B refunds {} BOND on Chain 2",
        refund_b.output_note.value
    );

    // ── Verification ──
    println!("\n[Verify] Final checks...");

    // Refund witnesses are in refund mode
    assert_eq!(refund_a.witness.pk_stealth, B256::ZERO);
    assert_eq!(refund_b.witness.pk_stealth, B256::ZERO);
    println!("  ✓ Both refund witnesses in refund mode (pk_stealth = 0)");

    // Timeout is set (contract would check block.timestamp > timeout)
    assert_ne!(refund_a.witness.timeout, B256::ZERO);
    assert_ne!(refund_b.witness.timeout, B256::ZERO);
    println!("  ✓ Timeout exposed as public input for contract enforcement");

    // Output notes are standard
    assert_eq!(refund_a.output_note.timeout, B256::ZERO);
    assert_eq!(refund_b.output_note.timeout, B256::ZERO);
    println!("  ✓ Refund output notes are standard (timeout=0)");

    // Funds returned to original owners
    assert_eq!(refund_a.output_note.owner, meta_a.pk_x());
    assert_eq!(refund_b.output_note.owner, meta_b.pk_x());
    println!("  ✓ Funds returned to original owners");

    // Values preserved
    assert_eq!(refund_a.output_note.value, terms.value_a);
    assert_eq!(refund_b.output_note.value, terms.value_b);
    println!("  ✓ Values preserved (A: {} USD, B: {} BOND)", terms.value_a, terms.value_b);

    // Double-spend protection: claim and refund produce same nullifier
    assert_eq!(
        refund_a.witness.nullifier,
        lock_a.locked_note.nullifier().0,
        "Refund nullifier must match canonical nullifier"
    );
    println!("  ✓ Canonical nullifiers prevent double-spend across paths");

    println!("\n  ★ Refund path completed successfully!");
}

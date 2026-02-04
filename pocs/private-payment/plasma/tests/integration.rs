//! Integration test: deposit → transfer → withdraw.
//!
//! Demonstrates the full private payment flow using the
//! intmax2 plasma architecture:
//!
//! 1. Alice deposits native ETH
//! 2. Bob deposits native ETH
//! 3. Alice transfers to Bob (private L2 transfer)
//! 4. Bob withdraws to L1

use alloy::primitives::B256;
use anyhow::{
    Context,
    Result,
};
use intmax2_client_sdk::{
    client::{
        client::Client,
        types::{
            GenericRecipient,
            TransferRequest,
        },
    },
    external_api::contract::convert::{
        convert_address_to_intmax,
        convert_b256_to_bytes32,
        convert_u256_to_intmax,
    },
};
use intmax2_interfaces::{
    data::deposit_data::TokenType,
    utils::{
        key::KeyPair,
        key_derivation::{
            derive_keypair_from_spend_key,
            derive_spend_key_from_bytes32,
        },
    },
};
use intmax2_zkp::ethereum_types::{
    bytes32::Bytes32,
    u32limb_trait::U32LimbTrait,
    u256::U256 as ZkpU256,
};
use private_payment_plasma::harness::{
    TestEnv,
    relay_pending_deposits,
};
use std::time::Duration;

/// Derive an intmax2 `KeyPair` from an Ethereum private key.
fn keypair_from_eth_key(eth_key: B256) -> KeyPair {
    let spend_key = derive_spend_key_from_bytes32(convert_b256_to_bytes32(eth_key));
    derive_keypair_from_spend_key(spend_key, false)
}

/// Poll the validity prover until a deposit is synced and
/// relayed (has a block_number).
async fn poll_deposit_synced(client: &Client, pubkey_salt_hash: Bytes32) -> Result<()> {
    for i in 0..180 {
        let info = client
            .validity_prover
            .get_deposit_info(pubkey_salt_hash)
            .await;
        match info {
            Ok(Some(di)) if di.block_number.is_some() => {
                log::info!(
                    "Deposit synced after {i} polls \
                     (block_number={:?})",
                    di.block_number
                );
                return Ok(());
            }
            Ok(Some(_)) => {
                // Seen but not yet relayed
            }
            Ok(None) => {
                // Not yet seen
            }
            Err(e) => {
                log::warn!("get_deposit_info error: {e:?}");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    anyhow::bail!("deposit not synced within given retry range");
}

/// Poll until a transaction is settled on the rollup.
async fn poll_tx_settled(client: &Client, tx_tree_root: Bytes32) -> Result<()> {
    for i in 0..180 {
        let block_number = client
            .validity_prover
            .get_block_number_by_tx_tree_root(tx_tree_root)
            .await;
        match block_number {
            Ok(Some(bn)) => {
                log::info!(
                    "Tx settled after {i} polls \
                     (block_number={bn})"
                );
                return Ok(());
            }
            Ok(None) => {}
            Err(e) => {
                log::warn!("get_block_number error: {e:?}");
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    anyhow::bail!("tx not settled within given retry range");
}

/// Metadata collected from a deposit operation.
struct DepositInfo {
    pubkey_salt_hash: Bytes32,
    deposit_digest: Bytes32,
    relay_tx_hash: Option<alloy::primitives::B256>,
}

/// Metadata collected from a transfer/withdrawal operation.
struct TxInfo {
    tx_tree_root: Bytes32,
    tx_digest: Bytes32,
    tx_index: u32,
}

/// Execute a single deposit (prepare → on-chain tx → relay →
/// poll → sync).
async fn do_deposit(
    env: &TestEnv,
    client: &Client,
    eth_key: B256,
    depositor: alloy::primitives::Address,
    key_pair: KeyPair,
    amount_wei: alloy::primitives::U256,
) -> Result<DepositInfo> {
    let pubkey_pair = intmax2_interfaces::utils::key::PublicKeyPair::from(&key_pair);

    // 1. Prepare deposit (saves encrypted data to store vault)
    let deposit_result = client
        .prepare_deposit(
            convert_address_to_intmax(depositor),
            pubkey_pair,
            convert_u256_to_intmax(amount_wei),
            TokenType::NATIVE,
            intmax2_zkp::ethereum_types::address::Address::default(),
            ZkpU256::default(),
            false,
        )
        .await
        .context("prepare_deposit")?;

    let psh = deposit_result.deposit_data.pubkey_salt_hash;
    let deposit_digest = deposit_result.deposit_digest;
    log::info!("Deposit prepared, pubkey_salt_hash={psh}");

    // 2. On-chain deposit (no AML/eligibility permitters)
    client
        .liquidity_contract
        .deposit_native(
            eth_key,
            None,
            psh,
            convert_u256_to_intmax(amount_wei),
            &[],
            &[],
        )
        .await
        .context("deposit_native")?;
    log::info!("On-chain deposit tx sent");

    // 3. Relay deposit to rollup via test scroll messenger
    let relay_tx_hash = relay_pending_deposits(&env.anvil, &env.contracts)
        .await
        .context("relay deposits")?;

    // 4. Wait for validity prover to sync the deposit
    poll_deposit_synced(client, psh).await?;

    // 5. Sync client balance
    client
        .sync(key_pair.into())
        .await
        .map_err(|e| anyhow::anyhow!("sync: {e:?}"))?;
    log::info!("Balance synced after deposit");

    Ok(DepositInfo {
        pubkey_salt_hash: psh,
        deposit_digest,
        relay_tx_hash,
    })
}

/// Execute a private transfer from sender to recipient on L2.
async fn do_transfer(
    client: &Client,
    block_builder_url: &str,
    sender_kp: KeyPair,
    recipient_kp: KeyPair,
    amount: ZkpU256,
) -> Result<TxInfo> {
    let recipient_pubkey_pair =
        intmax2_interfaces::utils::key::PublicKeyPair::from(&recipient_kp);
    let recipient_addr = client.get_address(recipient_pubkey_pair);

    let transfer = TransferRequest {
        recipient: GenericRecipient::IntmaxAddress(recipient_addr),
        token_index: 0,
        amount,
        description: None,
    };

    let sender_pub =
        intmax2_interfaces::utils::key::PublicKey::from_private_key(&sender_kp.spend);

    // 1. Quote transfer fee
    let fee_quote = client
        .quote_transfer_fee(block_builder_url, sender_pub.0, 0)
        .await
        .map_err(|e| anyhow::anyhow!("quote_transfer_fee: {e:?}"))?;
    log::info!("Transfer fee quoted: {fee_quote:?}");

    // 2. Ensure tx is sendable
    client
        .await_tx_sendable(sender_kp.into(), &[transfer.clone()], &fee_quote)
        .await
        .map_err(|e| anyhow::anyhow!("await_tx_sendable: {e:?}"))?;

    // 3. Send tx request to block builder
    let memo = client
        .send_tx_request(block_builder_url, sender_kp, &[transfer], &[], &fee_quote)
        .await
        .map_err(|e| anyhow::anyhow!("send_tx_request: {e:?}"))?;
    log::info!("Tx request sent, waiting for proposal...");

    // 4. Wait for block builder to build
    tokio::time::sleep(Duration::from_secs(5)).await;

    // 5. Query proposal
    let proposal = client
        .query_proposal(block_builder_url, &memo.request_id)
        .await
        .map_err(|e| anyhow::anyhow!("query_proposal: {e:?}"))?;
    log::info!("Proposal received");

    // 6. Finalize tx
    let result = client
        .finalize_tx(block_builder_url, sender_kp, &memo, &proposal)
        .await
        .map_err(|e| anyhow::anyhow!("finalize_tx: {e:?}"))?;
    log::info!("Tx finalized, tx_tree_root={}", result.tx_tree_root);

    // 7. Wait for tx to settle
    poll_tx_settled(client, result.tx_tree_root).await?;

    Ok(TxInfo {
        tx_tree_root: result.tx_tree_root,
        tx_digest: result.tx_digest,
        tx_index: result.tx_data.tx_index,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn test_full_plasma_flow() -> anyhow::Result<()> {
    let env = TestEnv::build().await?;
    let client = env.build_client()?;
    let block_builder_url = env.block_builder_url();

    // Use anvil accounts [2] and [3] for Alice and Bob
    let alice_eth_key = B256::from_slice(&env.anvil.keys()[2].to_bytes());
    let bob_eth_key = B256::from_slice(&env.anvil.keys()[3].to_bytes());
    let alice_addr = env.anvil.addresses()[2];
    let bob_addr = env.anvil.addresses()[3];
    let alice_kp = keypair_from_eth_key(alice_eth_key);
    let bob_kp = keypair_from_eth_key(bob_eth_key);

    // Deposit amount: 0.1 ETH each
    let deposit_amount = alloy::primitives::U256::from(100_000_000_000_000_000u128);

    // Compute intmax addresses for the summary
    let alice_pubkey_pair =
        intmax2_interfaces::utils::key::PublicKeyPair::from(&alice_kp);
    let bob_pubkey_pair = intmax2_interfaces::utils::key::PublicKeyPair::from(&bob_kp);
    let alice_intmax_addr = client.get_address(alice_pubkey_pair);
    let bob_intmax_addr = client.get_address(bob_pubkey_pair);

    // ---- Phase 1: Alice deposits ----
    log::info!("=== Phase 1: Alice deposits ===");
    let alice_deposit = do_deposit(
        &env,
        &client,
        alice_eth_key,
        alice_addr,
        alice_kp,
        deposit_amount,
    )
    .await
    .context("Alice deposit")?;
    log::info!("Alice deposit complete");

    // ---- Phase 2: Bob deposits ----
    log::info!("=== Phase 2: Bob deposits ===");
    let bob_deposit =
        do_deposit(&env, &client, bob_eth_key, bob_addr, bob_kp, deposit_amount)
            .await
            .context("Bob deposit")?;
    log::info!("Bob deposit complete");

    // ---- Phase 3: Alice transfers to Bob ----
    log::info!("=== Phase 3: Alice transfers to Bob ===");
    // Transfer 0.01 ETH (after fees)
    let transfer_amount = ZkpU256::from_bytes_be(
        &alloy::primitives::U256::from(10_000_000_000_000_000u128).to_be_bytes_vec(),
    )
    .expect("convert transfer amount");

    let transfer_info = do_transfer(
        &client,
        &block_builder_url,
        alice_kp,
        bob_kp,
        transfer_amount,
    )
    .await
    .context("Alice->Bob transfer")?;
    log::info!(
        "Transfer settled, tx_tree_root={}",
        transfer_info.tx_tree_root
    );

    // Sync Bob's balance
    client
        .sync(bob_kp.into())
        .await
        .map_err(|e| anyhow::anyhow!("bob sync: {e:?}"))?;
    log::info!("Bob balance synced after transfer");

    // ---- Phase 4: Bob withdraws ----
    log::info!("=== Phase 4: Bob withdraws ===");

    // Bob withdraws to his L1 address
    let withdrawal_amount = transfer_amount;
    let withdrawal_transfer = TransferRequest {
        recipient: GenericRecipient::Address(convert_address_to_intmax(bob_addr)),
        token_index: 0,
        amount: withdrawal_amount,
        description: None,
    };

    // Generate withdrawal transfers (includes fee transfers)
    let withdrawal_transfers = client
        .generate_withdrawal_transfers(&withdrawal_transfer, 0, false)
        .await
        .map_err(|e| anyhow::anyhow!("generate_withdrawal_transfers: {e:?}"))?;

    let bob_pub =
        intmax2_interfaces::utils::key::PublicKey::from_private_key(&bob_kp.spend);

    // Quote + send withdrawal transfers via block builder
    let fee_quote = client
        .quote_transfer_fee(&block_builder_url, bob_pub.0, 0)
        .await
        .map_err(|e| anyhow::anyhow!("quote fee for withdrawal: {e:?}"))?;

    client
        .await_tx_sendable(
            bob_kp.into(),
            &withdrawal_transfers.transfer_requests,
            &fee_quote,
        )
        .await
        .map_err(|e| anyhow::anyhow!("await_tx_sendable withdrawal: {e:?}"))?;

    let memo = client
        .send_tx_request(
            &block_builder_url,
            bob_kp,
            &withdrawal_transfers.transfer_requests,
            &[],
            &fee_quote,
        )
        .await
        .map_err(|e| anyhow::anyhow!("send withdrawal tx: {e:?}"))?;

    tokio::time::sleep(Duration::from_secs(5)).await;

    let proposal = client
        .query_proposal(&block_builder_url, &memo.request_id)
        .await
        .map_err(|e| anyhow::anyhow!("query withdrawal proposal: {e:?}"))?;

    let wd_result = client
        .finalize_tx(&block_builder_url, bob_kp, &memo, &proposal)
        .await
        .map_err(|e| anyhow::anyhow!("finalize withdrawal tx: {e:?}"))?;

    let wd_info = TxInfo {
        tx_tree_root: wd_result.tx_tree_root,
        tx_digest: wd_result.tx_digest,
        tx_index: wd_result.tx_data.tx_index,
    };

    poll_tx_settled(&client, wd_info.tx_tree_root).await?;
    log::info!("Withdrawal tx settled on L2");

    // Sync withdrawals to L1
    let withdrawal_fee_info = client
        .withdrawal_server
        .get_withdrawal_fee()
        .await
        .map_err(|e| anyhow::anyhow!("get_withdrawal_fee: {e:?}"))?;

    client
        .sync_withdrawals(bob_kp.into(), &withdrawal_fee_info, 0)
        .await
        .map_err(|e| anyhow::anyhow!("sync_withdrawals: {e:?}"))?;
    log::info!("Withdrawals synced to L1");

    // ---- Transaction Summary ----
    let relay_hash_str = |h: &Option<alloy::primitives::B256>| match h {
        Some(hash) => format!("{hash}"),
        None => "N/A (no relay needed)".to_string(),
    };

    log::info!("=== Transaction Summary ===");
    log::info!("");
    log::info!("--- Deployed Contracts ---");
    log::info!("  Rollup:              {:?}", env.contracts.rollup);
    log::info!("  Liquidity:           {:?}", env.contracts.liquidity);
    log::info!(
        "  Block Builder Reg:   {:?}",
        env.contracts.block_builder_registry
    );
    log::info!("  Withdrawal:          {:?}", env.contracts.withdrawal);
    log::info!("  Test Messenger:      {:?}", env.contracts.test_messenger);
    log::info!("");
    log::info!("--- Participants ---");
    log::info!("  Alice (L1 addr):     {:?}", alice_addr);
    log::info!("  Alice (intmax addr): {}", alice_intmax_addr);
    log::info!("  Bob   (L1 addr):     {:?}", bob_addr);
    log::info!("  Bob   (intmax addr): {}", bob_intmax_addr);
    log::info!("");
    log::info!("--- Phase 1: Alice Deposit (0.1 ETH) ---");
    log::info!("  Pubkey salt hash:    {}", alice_deposit.pubkey_salt_hash);
    log::info!("  Deposit digest:      {}", alice_deposit.deposit_digest);
    log::info!(
        "  Relay tx hash:       {}",
        relay_hash_str(&alice_deposit.relay_tx_hash)
    );
    log::info!("");
    log::info!("--- Phase 2: Bob Deposit (0.1 ETH) ---");
    log::info!("  Pubkey salt hash:    {}", bob_deposit.pubkey_salt_hash);
    log::info!("  Deposit digest:      {}", bob_deposit.deposit_digest);
    log::info!(
        "  Relay tx hash:       {}",
        relay_hash_str(&bob_deposit.relay_tx_hash)
    );
    log::info!("");
    log::info!("--- Phase 3: Alice -> Bob Transfer (0.01 ETH, private L2) ---");
    log::info!("  Tx tree root:        {}", transfer_info.tx_tree_root);
    log::info!("  Tx digest:           {}", transfer_info.tx_digest);
    log::info!("  Tx index:            {}", transfer_info.tx_index);
    log::info!("");
    log::info!("--- Phase 4: Bob Withdrawal (0.01 ETH to L1) ---");
    log::info!("  Tx tree root:        {}", wd_info.tx_tree_root);
    log::info!("  Tx digest:           {}", wd_info.tx_digest);
    log::info!("  Tx index:            {}", wd_info.tx_index);
    log::info!("");
    log::info!("=== Test Completed Successfully ===");

    env.shutdown().await;
    Ok(())
}

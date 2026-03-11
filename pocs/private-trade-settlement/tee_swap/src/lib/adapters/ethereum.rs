use alloy::{
    network::EthereumWallet, primitives::{Address, Bytes, B256, U256}, providers::{DynProvider, Provider, ProviderBuilder}, rpc::types::TransactionReceipt, signers::local::PrivateKeySigner,
};

use super::abi::{IPrivateUTXO, ITeeLock};
use crate::{
    domain::swap::SwapAnnouncement,
    ports::{
        chain::{ChainError, ChainPort},
        SwapLockData, TransferPublicInputs, TxReceipt,
    },
};

/// Ethereum RPC adapter
#[derive(Clone)]
pub struct EthereumRpc {
    provider: DynProvider,
    private_utxo: Address,
    tee_lock: Address,
}

impl EthereumRpc {
    pub async fn new(
        rpc_url: &str,
        private_key: &str,
        private_utxo: Address,
        tee_lock: Address,
    ) -> Result<Self, ChainError> {
        let signer: PrivateKeySigner = private_key
            .parse()
            .map_err(|e| ChainError::Rpc(format!("Invalid private key: {}", e)))?;
        let wallet = EthereumWallet::from(signer);
        let provider = DynProvider::new(
            ProviderBuilder::new().wallet(wallet).connect_http(
                rpc_url
                    .parse()
                    .map_err(|e| ChainError::Rpc(format!("Invalid RPC URL: {}", e)))?,
            ),
        );

        Ok(Self {
            provider,
            private_utxo,
            tee_lock,
        })
    }

    /// Access the underlying provider (e.g. for chain ID queries).
    pub fn provider(&self) -> &DynProvider {
        &self.provider
    }

    fn convert_receipt(receipt: &alloy::rpc::types::TransactionReceipt) -> TxReceipt {
        TxReceipt {
            tx_hash: receipt.transaction_hash,
            success: receipt.status(),
        }
    }

    /// Compute EIP-1559 gas overrides for a transaction attempt.
    /// Returns `(max_fee_per_gas, max_priority_fee_per_gas)`.
    fn gas_overrides(attempt: u32, current_gas_price: u128) -> (u128, u128) {
        // Priority fee: 2 gwei * 1.2^(attempt-1)
        let priority = 2_000_000_000u128 * 12u128.pow(attempt - 1) / 10u128.pow(attempt - 1);
        // Max fee: 2x current gas price + priority
        let max_fee = current_gas_price + priority;
        (max_fee, priority)
    }

    async fn send_with_retries<F, Fut>(
        &self,
        name: &str,
        f: F,
    ) -> Result<TxReceipt, ChainError>
    where
        F: Fn(u32, u128) -> Fut,
        Fut: std::future::Future<Output = Result<TransactionReceipt, ChainError>>,
    {
        let max_retries = 5;

        for attempt in 1..=max_retries {
            if attempt > 1 {
                tokio::time::sleep(std::time::Duration::from_secs(2 * attempt as u64)).await;
            }

            let gas_price = self.provider.get_gas_price().await.unwrap_or(20_000_000_000);

            tracing::info!(attempt, name, "sending transaction");

            match tokio::time::timeout(std::time::Duration::from_secs(60), f(attempt, gas_price)).await {
                Ok(Ok(receipt)) if receipt.status() => {
                    return Ok(Self::convert_receipt(&receipt));
                }
                Ok(Ok(receipt)) => {
                    tracing::warn!(attempt, name, tx = ?receipt.transaction_hash, "transaction reverted");
                }
                Ok(Err(e)) => {
                    tracing::warn!(attempt, name, error = %e, "transaction failed");
                }
                Err(_) => {
                    tracing::warn!(attempt, name, "transaction timed out");
                }
            }
        }

        Err(ChainError::TransactionFailed(
            format!("{name} failed after {max_retries} attempts"),
        ))
    }
}

impl ChainPort for EthereumRpc {
    async fn get_commitment_root(&self) -> Result<B256, ChainError> {
        let utxo = IPrivateUTXO::new(self.private_utxo, &self.provider);
        let result = utxo
            .commitmentRoot()
            .call()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?;
        Ok(result)
    }

    async fn is_nullifier_spent(&self, nullifier: B256) -> Result<bool, ChainError> {
        let utxo = IPrivateUTXO::new(self.private_utxo, &self.provider);
        let result = utxo
            .nullifiers(nullifier)
            .call()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?;
        Ok(result)
    }


    async fn fund(&self, commitment: B256) -> Result<TxReceipt, ChainError> {
        let utxo = IPrivateUTXO::new(self.private_utxo, &self.provider);

        self.send_with_retries("fund", |attempt, gas_price| {
            let utxo = utxo.clone();
            async move {
                let (max_fee, priority) = EthereumRpc::gas_overrides(attempt, gas_price);
                let call = utxo.fund(commitment)
                    .gas(500_000)
                    .max_fee_per_gas(max_fee)
                    .max_priority_fee_per_gas(priority);
                call.send()
                    .await
                    .map_err(|e| ChainError::TransactionFailed(format!("send failed: {e}")))?
                    .with_timeout(Some(std::time::Duration::from_secs(45)))
                    .get_receipt()
                    .await
                    .map_err(|e| ChainError::TransactionFailed(format!("receipt failed: {e}")))
            }
        })
        .await
    }

    async fn transfer(
        &self,
        proof: &[u8],
        public_inputs: &TransferPublicInputs,
    ) -> Result<TxReceipt, ChainError> {
        let utxo = IPrivateUTXO::new(self.private_utxo, &self.provider);
        let timeout = U256::from_be_bytes(public_inputs.timeout.0);

        self.send_with_retries("transfer", |attempt, gas_price| {
            let utxo = utxo.clone();
            async move {
                let (max_fee, priority) = EthereumRpc::gas_overrides(attempt, gas_price);
                let call = utxo.transfer(
                    Bytes::copy_from_slice(proof),
                    public_inputs.nullifier,
                    public_inputs.root,
                    public_inputs.new_commitment,
                    timeout,
                    public_inputs.pk_stealth,
                    public_inputs.h_swap,
                    public_inputs.h_r,
                    public_inputs.h_meta,
                    public_inputs.h_enc,
                ).gas(5_000_000).max_fee_per_gas(max_fee).max_priority_fee_per_gas(priority);
                call.send()
                    .await
                    .map_err(|e| ChainError::TransactionFailed(format!("send failed: {e}")))?
                    .with_timeout(Some(std::time::Duration::from_secs(45)))
                    .get_receipt()
                    .await
                    .map_err(|e| ChainError::TransactionFailed(format!("receipt failed: {e}")))
            }
        })
        .await
    }

    async fn get_swap_lock_data(&self, commitment: B256) -> Result<SwapLockData, ChainError> {
        let utxo = IPrivateUTXO::new(self.private_utxo, &self.provider);

        // assume that the transactions happened in the last 500 blocks
        let latest = self.provider.get_block_number().await.unwrap_or(0);
        let from = latest.saturating_sub(500);

        let filter = utxo
            .SwapNoteLocked_filter()
            .topic1(commitment)
            .from_block(from);

        let logs = filter
            .query()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?;

        let (event, _) = logs
            .last()
            .ok_or(ChainError::CommitmentNotFound(commitment))?;

        Ok(SwapLockData {
            commitment,
            timeout: B256::from(event.timeout.to_be_bytes::<32>()),
            pk_stealth: event.pkStealth,
            h_swap: event.hSwap,
            h_r: event.hR,
            h_meta: event.hMeta,
            h_enc: event.hEnc,
        })
    }

    async fn announce_swap(
        &self,
        announcement: &SwapAnnouncement,
    ) -> Result<TxReceipt, ChainError> {
        let tee_lock = ITeeLock::new(self.tee_lock, &self.provider);

        self.send_with_retries("announce_swap", |attempt, gas_price| {
            let tee_lock = tee_lock.clone();
            async move {
                let (max_fee, priority) = EthereumRpc::gas_overrides(attempt, gas_price);
                let call = tee_lock.announceSwap(
                    announcement.swap_id,
                    announcement.ephemeral_key_a,
                    announcement.ephemeral_key_b,
                    announcement.encrypted_salt_a,
                    announcement.encrypted_salt_b,
                ).gas(500_000).max_fee_per_gas(max_fee).max_priority_fee_per_gas(priority);
                call.send()
                    .await
                    .map_err(|e| ChainError::TransactionFailed(e.to_string()))?
                    .with_timeout(Some(std::time::Duration::from_secs(45)))
                    .get_receipt()
                    .await
                    .map_err(|e| ChainError::TransactionFailed(e.to_string()))
            }
        })
        .await
    }

    async fn get_announcement(&self, swap_id: B256) -> Result<SwapAnnouncement, ChainError> {
        let tee_lock = ITeeLock::new(self.tee_lock, &self.provider);
        let result = tee_lock
            .announcements(swap_id)
            .call()
            .await
            .map_err(|e| ChainError::Rpc(e.to_string()))?;

        if !result.revealed {
            return Err(ChainError::AnnouncementNotFound(swap_id));
        }

        Ok(SwapAnnouncement {
            swap_id,
            ephemeral_key_a: result.ephemeralKeyA,
            ephemeral_key_b: result.ephemeralKeyB,
            encrypted_salt_a: result.encryptedSaltA,
            encrypted_salt_b: result.encryptedSaltB,
        })
    }
}

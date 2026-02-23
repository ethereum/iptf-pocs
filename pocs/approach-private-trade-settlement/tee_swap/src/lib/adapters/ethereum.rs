use alloy::{
    network::EthereumWallet,
    primitives::{Address, B256, Bytes, U256},
    providers::{DynProvider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};

use crate::{
    domain::swap::SwapAnnouncement,
    ports::{
        chain::{ChainError, ChainPort},
        SwapLockData, TransferPublicInputs, TxReceipt,
    },
};

sol! {
    #[sol(rpc)]
    interface IPrivateUTXO {
        function commitmentRoot() external view returns (bytes32);
        function nullifiers(bytes32 nullifier) external view returns (bool);

        function fund(bytes32 commitment) external;

        function transfer(
            bytes calldata proof,
            bytes32 nullifier,
            bytes32 root,
            bytes32 newCommitment,
            uint256 timeout,
            bytes32 pkStealth,
            bytes32 hSwap,
            bytes32 hR,
            bytes32 hMeta,
            bytes32 hEnc
        ) external;

        event SwapNoteLocked(
            bytes32 indexed commitment,
            uint256 timeout,
            bytes32 pkStealth,
            bytes32 hSwap,
            bytes32 hR,
            bytes32 hMeta,
            bytes32 hEnc
        );
    }

    #[sol(rpc)]
    interface ITeeLock {
        function announcements(bytes32 swapId) external view returns (
            bool revealed,
            bytes32 ephemeralKeyA,
            bytes32 ephemeralKeyB,
            bytes32 encryptedSaltA,
            bytes32 encryptedSaltB
        );

        function announceSwap(
            bytes32 swapId,
            bytes32 ephemeralKeyA,
            bytes32 ephemeralKeyB,
            bytes32 encryptedSaltA,
            bytes32 encryptedSaltB
        ) external;
    }
}

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

    fn convert_receipt(receipt: &alloy::rpc::types::TransactionReceipt) -> TxReceipt {
        TxReceipt {
            tx_hash: receipt.transaction_hash,
            success: receipt.status(),
        }
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
        let receipt = utxo
            .fund(commitment)
            .send()
            .await
            .map_err(|e| ChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| ChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(ChainError::TransactionFailed("fund reverted".into()));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    async fn transfer(
        &self,
        proof: &[u8],
        public_inputs: &TransferPublicInputs,
    ) -> Result<TxReceipt, ChainError> {
        let utxo = IPrivateUTXO::new(self.private_utxo, &self.provider);
        let timeout = U256::from_be_bytes(public_inputs.timeout.0);

        let receipt = utxo
            .transfer(
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
            )
            .send()
            .await
            .map_err(|e| ChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| ChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(ChainError::TransactionFailed("transfer reverted".into()));
        }

        Ok(Self::convert_receipt(&receipt))
    }

    async fn get_swap_lock_data(&self, commitment: B256) -> Result<SwapLockData, ChainError> {
        let utxo = IPrivateUTXO::new(self.private_utxo, &self.provider);

        let filter = utxo
            .SwapNoteLocked_filter()
            .topic1(commitment)
            .from_block(0); // in production, this indexer would be running in parallel, and not use ad-hoc queries

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

        let receipt = tee_lock
            .announceSwap(
                announcement.swap_id,
                announcement.ephemeral_key_a,
                announcement.ephemeral_key_b,
                announcement.encrypted_salt_a,
                announcement.encrypted_salt_b,
            )
            .send()
            .await
            .map_err(|e| ChainError::TransactionFailed(e.to_string()))?
            .get_receipt()
            .await
            .map_err(|e| ChainError::TransactionFailed(e.to_string()))?;

        if !receipt.status() {
            return Err(ChainError::TransactionFailed(
                "announceSwap reverted".into(),
            ));
        }

        Ok(Self::convert_receipt(&receipt))
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

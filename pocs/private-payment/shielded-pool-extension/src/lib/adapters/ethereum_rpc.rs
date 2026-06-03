//! Alloy-backed adapter for `ShieldedPoolExt` (and the mock ERC-20), used by the
//! in-process e2e to drive the contract on anvil.
//!
//! Differs from the parent's RPC adapter: no attestation registry and no on-chain
//! nullifier set (the extension keeps neither); adds the epoch / active-tree views
//! (`currentEpoch`, `activeNullifierRoot`, `activeLeafCount`, `frozenNullifierRoots`,
//! `expectedChainAccumulator`, `chainVkHash`) and the two-proof `transfer` /
//! `withdraw` signatures (wallet spend proof + relayer insertion proof). Methods
//! are inherent: the single-backend PoC does not need an on-chain port trait.

use alloy::{
    network::EthereumWallet,
    primitives::{
        Address,
        B256,
        Bytes,
        U256,
    },
    providers::{
        DynProvider,
        ProviderBuilder,
    },
    signers::local::PrivateKeySigner,
    sol,
};

// Contract bindings (function signatures mirror `contracts/src/ShieldedPoolExt.sol`).
sol! {
    #[sol(rpc)]
    interface IShieldedPoolExt {
        function commitmentRoot() external view returns (bytes32);
        function getCommitmentCount() external view returns (uint256);
        function isKnownRoot(bytes32 root) external view returns (bool);
        function supportedTokens(address token) external view returns (bool);
        function currentEpoch() external view returns (uint64);
        function activeNullifierRoot() external view returns (bytes32);
        function activeLeafCount() external view returns (uint64);
        function frozenNullifierRoots(uint64 epoch) external view returns (bytes32);
        function expectedChainAccumulator(uint64 epochCreated) external view returns (bytes32);
        function chainVkHash() external view returns (bytes32);

        function deposit(
            bytes proof,
            bytes32 commitment,
            address token,
            uint256 amount,
            bytes encryptedNote
        ) external;

        function transfer(
            bytes spendProof,
            bytes insertionProof,
            bytes32[2] nullifiers,
            bytes32[2] outputCommitments,
            bytes32 root,
            uint64[2] epochCreated,
            bytes32 postActiveRoot,
            bytes encryptedNotes
        ) external;

        function withdraw(
            bytes spendProof,
            bytes insertionProof,
            bytes32 nullifier,
            address token,
            uint256 amount,
            address recipient,
            bytes32 root,
            uint64 epochCreated,
            bytes32 postActiveRoot
        ) external;

        function rolloverEpoch() external;
        function addSupportedToken(address token) external;
    }

    #[sol(rpc)]
    interface IMockERC20 {
        function mint(address to, uint256 amount) external;
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

/// Errors from on-chain interaction.
#[derive(Debug, thiserror::Error)]
pub enum OnChainError {
    #[error("signer: {0}")]
    Signer(String),
    #[error("rpc: {0}")]
    Rpc(String),
    #[error("contract call: {0}")]
    Contract(String),
    #[error("tx failed: {0}")]
    TransactionFailed(String),
    #[error("tx reverted: {0}")]
    TransactionReverted(String),
}

/// Minimal transaction receipt.
#[derive(Debug, Clone)]
pub struct TxReceipt {
    pub tx_hash: B256,
    pub block_number: u64,
    pub gas_used: u64,
    pub success: bool,
}

impl From<alloy::rpc::types::TransactionReceipt> for TxReceipt {
    fn from(receipt: alloy::rpc::types::TransactionReceipt) -> Self {
        Self {
            tx_hash: receipt.transaction_hash,
            block_number: receipt.block_number.unwrap_or(0),
            gas_used: receipt.gas_used,
            success: receipt.status(),
        }
    }
}

/// RPC adapter for `ShieldedPoolExt`.
pub struct EthereumRpc {
    provider: DynProvider,
    pool: Address,
    signer_address: Address,
}

impl EthereumRpc {
    /// Connect with a signing key and the deployed `ShieldedPoolExt` address.
    pub async fn new(rpc_url: &str, private_key: &str, pool: Address) -> Result<Self, OnChainError> {
        let signer: PrivateKeySigner = private_key
            .parse()
            .map_err(|e| OnChainError::Signer(format!("invalid private key: {e}")))?;
        let signer_address = signer.address();
        let wallet = EthereumWallet::from(signer);
        let provider = DynProvider::new(
            ProviderBuilder::new().wallet(wallet).connect_http(
                rpc_url.parse().map_err(|e| OnChainError::Rpc(format!("invalid RPC URL: {e}")))?,
            ),
        );
        Ok(Self { provider, pool, signer_address })
    }

    pub fn signer_address(&self) -> Address {
        self.signer_address
    }

    pub fn pool_address(&self) -> Address {
        self.pool
    }

    fn pool(&self) -> IShieldedPoolExt::IShieldedPoolExtInstance<&DynProvider> {
        IShieldedPoolExt::new(self.pool, &self.provider)
    }

    // ===== Reads =====

    pub async fn commitment_root(&self) -> Result<B256, OnChainError> {
        self.pool().commitmentRoot().call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn commitment_count(&self) -> Result<u64, OnChainError> {
        let n = self.pool().getCommitmentCount().call().await.map_err(|e| OnChainError::Contract(e.to_string()))?;
        Ok(n.try_into().unwrap_or(u64::MAX))
    }

    pub async fn is_known_root(&self, root: B256) -> Result<bool, OnChainError> {
        self.pool().isKnownRoot(root).call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn is_token_supported(&self, token: Address) -> Result<bool, OnChainError> {
        self.pool().supportedTokens(token).call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn current_epoch(&self) -> Result<u64, OnChainError> {
        self.pool().currentEpoch().call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn active_nullifier_root(&self) -> Result<B256, OnChainError> {
        self.pool().activeNullifierRoot().call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn active_leaf_count(&self) -> Result<u64, OnChainError> {
        self.pool().activeLeafCount().call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn frozen_nullifier_root(&self, epoch: u64) -> Result<B256, OnChainError> {
        self.pool().frozenNullifierRoots(epoch).call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn expected_chain_accumulator(&self, epoch_created: u64) -> Result<B256, OnChainError> {
        self.pool().expectedChainAccumulator(epoch_created).call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    pub async fn chain_vk_hash(&self) -> Result<B256, OnChainError> {
        self.pool().chainVkHash().call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    // ===== Writes =====

    pub async fn deposit(
        &self,
        proof: Bytes,
        commitment: B256,
        token: Address,
        amount: U256,
        encrypted_note: Bytes,
    ) -> Result<TxReceipt, OnChainError> {
        let pending = self
            .pool()
            .deposit(proof, commitment, token, amount, encrypted_note)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        self.confirm(pending, "deposit").await
    }

    /// Two-proof transfer: wallet spend proof + relayer insertion proof. The
    /// `nullifiers` list is fed to both verifiers by the contract (cross-proof
    /// binding); `post_active_root` is the insertion proof's attested new root.
    #[allow(clippy::too_many_arguments)]
    pub async fn transfer(
        &self,
        spend_proof: Bytes,
        insertion_proof: Bytes,
        nullifiers: [B256; 2],
        output_commitments: [B256; 2],
        root: B256,
        epoch_created: [u64; 2],
        post_active_root: B256,
        encrypted_notes: Bytes,
    ) -> Result<TxReceipt, OnChainError> {
        let pending = self
            .pool()
            .transfer(
                spend_proof,
                insertion_proof,
                nullifiers,
                output_commitments,
                root,
                epoch_created,
                post_active_root,
                encrypted_notes,
            )
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        self.confirm(pending, "transfer").await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn withdraw(
        &self,
        spend_proof: Bytes,
        insertion_proof: Bytes,
        nullifier: B256,
        token: Address,
        amount: U256,
        recipient: Address,
        root: B256,
        epoch_created: u64,
        post_active_root: B256,
    ) -> Result<TxReceipt, OnChainError> {
        let pending = self
            .pool()
            .withdraw(
                spend_proof,
                insertion_proof,
                nullifier,
                token,
                amount,
                recipient,
                root,
                epoch_created,
                post_active_root,
            )
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        self.confirm(pending, "withdraw").await
    }

    pub async fn rollover_epoch(&self) -> Result<TxReceipt, OnChainError> {
        let pending = self
            .pool()
            .rolloverEpoch()
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        self.confirm(pending, "rolloverEpoch").await
    }

    pub async fn add_supported_token(&self, token: Address) -> Result<TxReceipt, OnChainError> {
        let pending = self
            .pool()
            .addSupportedToken(token)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        self.confirm(pending, "addSupportedToken").await
    }

    // ===== ERC-20 (mock token) =====

    pub async fn approve_token(&self, token: Address, amount: U256) -> Result<TxReceipt, OnChainError> {
        let erc20 = IMockERC20::new(token, &self.provider);
        let pending = erc20
            .approve(self.pool, amount)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        self.confirm(pending, "approve").await
    }

    pub async fn mint_mock_token(&self, token: Address, to: Address, amount: U256) -> Result<TxReceipt, OnChainError> {
        let erc20 = IMockERC20::new(token, &self.provider);
        let pending = erc20
            .mint(to, amount)
            .send()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        self.confirm(pending, "mint").await
    }

    pub async fn get_token_balance(&self, token: Address, account: Address) -> Result<U256, OnChainError> {
        let erc20 = IMockERC20::new(token, &self.provider);
        erc20.balanceOf(account).call().await.map_err(|e| OnChainError::Contract(e.to_string()))
    }

    /// Await a sent tx's receipt and require success.
    async fn confirm(
        &self,
        pending: alloy::providers::PendingTransactionBuilder<alloy::network::Ethereum>,
        what: &str,
    ) -> Result<TxReceipt, OnChainError> {
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| OnChainError::TransactionFailed(e.to_string()))?;
        if !receipt.status() {
            return Err(OnChainError::TransactionReverted(format!("{what} reverted")));
        }
        Ok(receipt.into())
    }
}

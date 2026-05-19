//! Alloy adapter for the on-chain `PetitionRegistry`.

#![allow(clippy::too_many_arguments)] // alloy `sol!` generates wide constructors.

use alloy::{
    consensus::BlobTransactionSidecar,
    network::{
        EthereumWallet,
        TransactionBuilder4844,
    },
    primitives::{
        Address as AlloyAddress,
        Bytes,
        FixedBytes,
    },
    providers::{
        DynProvider,
        Provider,
        ProviderBuilder,
    },
    signers::local::PrivateKeySigner,
    sol,
};

use crate::types::{
    Address,
    BatchPublicInputs,
    PetitionId,
    ResolutionPublicInputs,
};

sol! {
    #[derive(Debug)]
    #[sol(rpc)]
    interface IPetitionRegistry {
        struct PetitionParams {
            bytes32 rRoot;
            bytes predicateDef;
            bytes32 salt;
            uint16[] classSet;
            uint64[] classThresholds;
            uint8 classIndex;
            uint64 closeAtBlock;
            uint256 bounty;
        }

        struct BatchPublicInputs {
            bytes32 petitionId;
            bytes32 rRoot;
            bytes32 predicateHash;
            uint8 classIndex;
            uint32 slot;
            uint32 batchSize;
            bytes32 priorRunningRoot;
            bytes32 newRunningRoot;
            bytes32 priorIdentityTagSetRoot;
            bytes32 newIdentityTagSetRoot;
            uint64 priorLeafCount;
            uint64 newLeafCount;
            bytes32 batchVersionedHash;
            bytes32[24] blsFields;
            bytes32 signerVkHash;
        }

        struct ResolutionPublicInputs {
            bool b;
            bool[] bPerClass;
        }

        function register(
            PetitionParams calldata params
        ) external returns (bytes32 petitionId);

        function publishBatch(
            BatchPublicInputs calldata pi,
            bytes calldata batchProof,
            bytes calldata kzgCommitment,
            bytes calldata kzgProofs
        ) external;

        function resolve(
            bytes32 petitionId,
            ResolutionPublicInputs calldata pi,
            bytes calldata resolutionProof
        ) external;

        function markUnresolved(bytes32 petitionId) external;

        function dispute(
            bytes32 petitionId,
            uint32 batchIndex,
            uint32 positionI,
            uint32 positionJ,
            uint8 violationType,
            bytes calldata kzgCommitment,
            bytes calldata openingsBlob,
            bytes calldata proofsBlob
        ) external;

        function getBatchCount(bytes32 petitionId) external view returns (uint256);

        event PetitionRegistered(
            bytes32 indexed petitionId,
            uint32 slot,
            bytes32 rRoot,
            bytes32 predicateHash,
            uint16[] classSet,
            uint64[] classThresholds,
            uint8 classIndex,
            uint64 closeAtBlock,
            uint256 bounty
        );
        event BatchPublished(
            bytes32 indexed petitionId,
            uint32 indexed batchIndex,
            bytes32 batchVersionedHash,
            bytes32 newRunningRoot,
            bytes32 newIdentityTagSetRoot,
            uint64 newLeafCount
        );
        event PetitionResolved(bytes32 indexed petitionId, bool b, bool[] bPerClass);
        event BountyPaid(bytes32 indexed petitionId, address recipient, uint256 amount);
        event BatchRepudiated(
            bytes32 indexed petitionId,
            uint32 indexed batchIndex,
            bytes32 newRunningRoot,
            bytes32 newIdentityTagSetRoot,
            uint64 newLeafCount
        );
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ChainRegistryError {
    #[error("alloy rpc: {0}")]
    Rpc(String),
    #[error("decoding: {0}")]
    Decode(String),
    #[error("expected event not found: {0}")]
    EventNotFound(&'static str),
}

#[derive(Clone)]
pub struct ChainPetitionRegistry {
    pub provider: DynProvider,
    pub address: AlloyAddress,
}

impl ChainPetitionRegistry {
    pub fn new(provider: DynProvider, address: AlloyAddress) -> Self {
        Self { provider, address }
    }

    /// Build a provider from an HTTP endpoint + private key (test convenience).
    pub fn provider_from_pk(endpoint: &str, pk_hex: &str) -> DynProvider {
        let signer: PrivateKeySigner = pk_hex.parse().expect("parse pk");
        let wallet = EthereumWallet::from(signer);
        ProviderBuilder::new()
            .with_simple_nonce_management()
            .wallet(wallet)
            .connect_http(endpoint.parse().expect("parse endpoint"))
            .erased()
    }

    pub async fn register(
        &self,
        params: IPetitionRegistry::PetitionParams,
    ) -> Result<PetitionId, ChainRegistryError> {
        let contract = IPetitionRegistry::new(self.address, &self.provider);
        let receipt = contract
            .register(params)
            .send()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("register send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("register receipt: {e}")))?;
        for log in receipt.logs() {
            if let Ok(ev) = log.log_decode::<IPetitionRegistry::PetitionRegistered>() {
                return Ok(ev.inner.petitionId.0);
            }
        }
        Err(ChainRegistryError::EventNotFound("PetitionRegistered"))
    }

    /// Submit the batch as an EIP-4844 blob transaction; sidecar binds to `pi.batch_versioned_hash`.
    pub async fn publish_batch(
        &self,
        pi: BatchPublicInputs,
        batch_proof: Vec<u8>,
        kzg_commitment: Vec<u8>,
        kzg_proofs: Vec<u8>,
        sidecar: BlobTransactionSidecar,
    ) -> Result<(), ChainRegistryError> {
        let contract = IPetitionRegistry::new(self.address, &self.provider);
        let pi_sol = batch_public_inputs_to_sol(&pi);
        let mut tx = contract
            .publishBatch(
                pi_sol,
                Bytes::from(batch_proof),
                Bytes::from(kzg_commitment),
                Bytes::from(kzg_proofs),
            )
            .into_transaction_request();
        tx = tx.with_blob_sidecar(sidecar);

        let pending =
            self.provider.send_transaction(tx).await.map_err(|e| {
                ChainRegistryError::Rpc(format!("publishBatch send: {e}"))
            })?;
        let receipt = pending
            .get_receipt()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("publishBatch receipt: {e}")))?;
        if !receipt.status() {
            return Err(ChainRegistryError::Rpc("publishBatch reverted".into()));
        }
        Ok(())
    }

    pub async fn resolve(
        &self,
        petition_id: PetitionId,
        pi: ResolutionPublicInputs,
        resolution_proof: Vec<u8>,
    ) -> Result<(), ChainRegistryError> {
        let contract = IPetitionRegistry::new(self.address, &self.provider);
        let pi_sol = resolution_public_inputs_to_sol(&pi);
        let receipt = contract
            .resolve(
                FixedBytes(petition_id),
                pi_sol,
                Bytes::from(resolution_proof),
            )
            .send()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("resolve send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("resolve receipt: {e}")))?;
        if !receipt.status() {
            return Err(ChainRegistryError::Rpc("resolve reverted".into()));
        }
        Ok(())
    }

    /// Submit a dispute against `batch_index`. Returns the `BatchRepudiated`
    /// event payload if the dispute is upheld; the contract reverts on
    /// failure. `kzg_commitment` is the same 48-byte commitment used to
    /// publish the batch; `openings_blob` carries y-values (32 bytes each)
    /// and `proofs_blob` carries 48-byte KZG proofs, in the canonical
    /// position layout (`positionI`'s 4 FEs, then `positionJ`'s 4 for
    /// violation types 0x02 and 0x03).
    pub async fn dispute(
        &self,
        petition_id: PetitionId,
        batch_index: u32,
        position_i: u32,
        position_j: u32,
        violation_type: u8,
        kzg_commitment: Vec<u8>,
        openings_blob: Vec<u8>,
        proofs_blob: Vec<u8>,
    ) -> Result<IPetitionRegistry::BatchRepudiated, ChainRegistryError> {
        let contract = IPetitionRegistry::new(self.address, &self.provider);
        let receipt = contract
            .dispute(
                FixedBytes(petition_id),
                batch_index,
                position_i,
                position_j,
                violation_type,
                Bytes::from(kzg_commitment),
                Bytes::from(openings_blob),
                Bytes::from(proofs_blob),
            )
            .send()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("dispute send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("dispute receipt: {e}")))?;
        if !receipt.status() {
            return Err(ChainRegistryError::Rpc("dispute reverted".into()));
        }
        for log in receipt.logs() {
            if let Ok(ev) = log.log_decode::<IPetitionRegistry::BatchRepudiated>() {
                return Ok(ev.inner.data);
            }
        }
        Err(ChainRegistryError::EventNotFound("BatchRepudiated"))
    }

    pub async fn mark_unresolved(
        &self,
        petition_id: PetitionId,
    ) -> Result<(), ChainRegistryError> {
        let contract = IPetitionRegistry::new(self.address, &self.provider);
        let receipt = contract
            .markUnresolved(FixedBytes(petition_id))
            .send()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("markUnresolved send: {e}")))?
            .get_receipt()
            .await
            .map_err(|e| {
                ChainRegistryError::Rpc(format!("markUnresolved receipt: {e}"))
            })?;
        if !receipt.status() {
            return Err(ChainRegistryError::Rpc("markUnresolved reverted".into()));
        }
        Ok(())
    }

    pub async fn get_batch_count(
        &self,
        petition_id: PetitionId,
    ) -> Result<u64, ChainRegistryError> {
        let contract = IPetitionRegistry::new(self.address, &self.provider);
        let n = contract
            .getBatchCount(FixedBytes(petition_id))
            .call()
            .await
            .map_err(|e| ChainRegistryError::Rpc(format!("getBatchCount: {e}")))?;
        n.try_into()
            .map_err(|_| ChainRegistryError::Decode("getBatchCount > u64::MAX".into()))
    }
}

pub fn batch_public_inputs_to_sol(
    pi: &BatchPublicInputs,
) -> IPetitionRegistry::BatchPublicInputs {
    use crate::poseidon::fr_to_be_bytes;
    let mut bls_fields: [FixedBytes<32>; 24] = [FixedBytes::ZERO; 24];
    for (i, fe) in pi.bls_fields.iter().enumerate().take(24) {
        bls_fields[i] = FixedBytes(fr_to_be_bytes(fe));
    }
    IPetitionRegistry::BatchPublicInputs {
        petitionId: FixedBytes(fr_to_be_bytes(&pi.petition_id)),
        rRoot: FixedBytes(fr_to_be_bytes(&pi.r_root)),
        predicateHash: FixedBytes(fr_to_be_bytes(&pi.predicate_hash)),
        classIndex: fr_to_u8(&pi.class_index),
        slot: fr_to_u32(&pi.slot),
        batchSize: fr_to_u32(&pi.batch_size),
        priorRunningRoot: FixedBytes(fr_to_be_bytes(&pi.prior_running_root)),
        newRunningRoot: FixedBytes(fr_to_be_bytes(&pi.new_running_root)),
        priorIdentityTagSetRoot: FixedBytes(fr_to_be_bytes(
            &pi.prior_identity_tag_set_root,
        )),
        newIdentityTagSetRoot: FixedBytes(fr_to_be_bytes(&pi.new_identity_tag_set_root)),
        priorLeafCount: fr_to_u64(&pi.prior_leaf_count),
        newLeafCount: fr_to_u64(&pi.new_leaf_count),
        batchVersionedHash: FixedBytes(fr_to_be_bytes(&pi.batch_versioned_hash)),
        blsFields: bls_fields,
        signerVkHash: FixedBytes(fr_to_be_bytes(&pi.signer_vk_hash)),
    }
}

/// Translates the prover-side `ResolutionPublicInputs` (which carries every
/// circuit public input for proof generation) into the on-chain submission struct.
pub fn resolution_public_inputs_to_sol(
    pi: &ResolutionPublicInputs,
) -> IPetitionRegistry::ResolutionPublicInputs {
    use ark_ff::Zero;
    IPetitionRegistry::ResolutionPublicInputs {
        b: !pi.b.is_zero(),
        bPerClass: pi.b_per_class.iter().map(|f| !f.is_zero()).collect(),
    }
}

fn fr_to_be_tail<const N: usize>(fr: &ark_bn254::Fr) -> [u8; N] {
    let be = crate::poseidon::fr_to_be_bytes(fr);
    let mut out = [0u8; N];
    out.copy_from_slice(&be[32 - N..]);
    out
}

fn fr_to_u8(fr: &ark_bn254::Fr) -> u8 {
    crate::poseidon::fr_to_be_bytes(fr)[31]
}

fn fr_to_u32(fr: &ark_bn254::Fr) -> u32 {
    u32::from_be_bytes(fr_to_be_tail(fr))
}

fn fr_to_u64(fr: &ark_bn254::Fr) -> u64 {
    u64::from_be_bytes(fr_to_be_tail(fr))
}

pub fn address_to_alloy(a: &Address) -> AlloyAddress {
    AlloyAddress::from_slice(a)
}

pub fn address_from_alloy(a: AlloyAddress) -> Address {
    let mut out = [0u8; 20];
    out.copy_from_slice(a.as_slice());
    out
}

//! Relay actor: decrypts voucher, looks up `leaf_index` via on-chain
//! commitment-index map, builds claim and pool-withdraw witnesses, and
//! generates both proofs. The actual on-chain submission is delegated to
//! the caller (the example wires it to alloy).

use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};

use crate::{
    crypto::aead::decrypt_from_companion,
    error::PoolError,
    ports::proof::ProofBackend,
    poseidon::{
        fr_from_be_bytes,
        hash_claim_nullifier,
        hash_m_packed,
        hash_pool_commitment,
        pack_chain_id,
        pack_round_id,
    },
    relay::{
        error::RelayError,
        types::KeyArchive,
    },
    types::{
        Address,
        Bytes32,
        ClaimWitness,
        CohortMerklePath,
        EncryptedVoucher,
        PoolMerklePath,
        PoolWithdrawWitness,
        SignedVoucher,
    },
};

/// Pool-side state the relay needs. Production deployments back this with
/// alloy + the IPool ABI; tests can use an in-memory mock.
pub trait OnChainPool: Send + Sync {
    fn commitment_index(
        &self,
        claim_contract: &Address,
        commitment: &Bytes32,
    ) -> Result<Option<u64>, PoolError>;
    fn sub_tree_root(&self, claim_contract: &Address) -> Result<Bytes32, PoolError>;
    fn pool_merkle_path(
        &self,
        claim_contract: &Address,
        leaf_index: u64,
    ) -> Result<PoolMerklePath, PoolError>;
}

/// Cohort tree state per version.
pub trait OnChainCohort: Send + Sync {
    fn cohort_root(&self, cohort_version: u64) -> Result<Bytes32, PoolError>;
    fn cohort_merkle_path(
        &self,
        cohort_version: u64,
        cohort_position: u64,
    ) -> Result<CohortMerklePath, PoolError>;
}

pub struct Relay<P: ProofBackend, OC: OnChainPool, OR: OnChainCohort> {
    pub prover: P,
    pub keys: KeyArchive,
    pub pool: OC,
    pub cohort: OR,
    pub claim_contract: Address,
    pub relay_submitter: Address,
}

impl<P: ProofBackend, OC: OnChainPool, OR: OnChainCohort> Relay<P, OC, OR> {
    pub fn new(
        prover: P,
        keys: KeyArchive,
        pool: OC,
        cohort: OR,
        claim_contract: Address,
        relay_submitter: Address,
    ) -> Self {
        Self {
            prover,
            keys,
            pool,
            cohort,
            claim_contract,
            relay_submitter,
        }
    }

    fn decrypt(&self, env: &EncryptedVoucher) -> Result<Vec<u8>, RelayError> {
        if let Ok(plain) = decrypt_from_companion(&self.keys.current_sk, env) {
            return Ok(plain);
        }
        if let Some(prev) = &self.keys.previous_sk {
            if let Ok(plain) = decrypt_from_companion(prev, env) {
                return Ok(plain);
            }
        }
        Err(RelayError::AeadFailure(
            crate::crypto::aead::AeadError::DecryptFailed,
        ))
    }

    /// Decrypt + parse + recompute commitment + lookup leaf index + build
    /// witnesses + generate both proofs. The caller submits them on-chain.
    /// `token` and the cohort coordinates are supplied separately because
    /// the voucher does not contain them (per Design Z prime).
    pub fn submit_voucher(
        &self,
        env: &EncryptedVoucher,
        token: Address,
        cohort_version: u64,
        cohort_position: u64,
    ) -> Result<SubmissionArtifacts, RelayError> {
        let plain = self.decrypt(env)?;
        let voucher: SignedVoucher = serde_json::from_slice(&plain)
            .map_err(|e| RelayError::BadVoucherFormat(e.to_string()))?;

        let m_x_hi = fr_from_be_bytes(&voucher.m.x[..16]);
        let m_x_lo = fr_from_be_bytes(&voucher.m.x[16..32]);
        let m_y_hi = fr_from_be_bytes(&voucher.m.y[..16]);
        let m_y_lo = fr_from_be_bytes(&voucher.m.y[16..32]);
        let m_packed = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
        let r_packed = pack_round_id(
            fr_from_be_bytes(&voucher.context.round_id[..16]),
            fr_from_be_bytes(&voucher.context.round_id[16..32]),
        );
        let c_packed = pack_chain_id(
            fr_from_be_bytes(&voucher.context.chain_id.as_bytes()[..16]),
            fr_from_be_bytes(&voucher.context.chain_id.as_bytes()[16..32]),
        );
        let token_fr = fr_from_be_bytes(&pad_address(&token));
        let amount_fr =
            Fr::from_be_bytes_mod_order(voucher.context.per_recipient_amount.as_bytes());
        let commitment = hash_pool_commitment(token_fr, amount_fr, m_packed, r_packed);

        let commitment_be = fr_to_be_bytes(&commitment);
        let leaf_index = self
            .pool
            .commitment_index(&self.claim_contract, &commitment_be)
            .map_err(RelayError::Pool)?
            .ok_or(RelayError::CommitmentNotFound)?;

        let pool_root_be = self.pool.sub_tree_root(&self.claim_contract)?;
        let pool_path = self
            .pool
            .pool_merkle_path(&self.claim_contract, leaf_index)?;
        let cohort_root_be = self.cohort.cohort_root(cohort_version)?;
        let cohort_path = self
            .cohort
            .cohort_merkle_path(cohort_version, cohort_position)?;

        let derived_x = &voucher.derived_pubkey.x;
        let derived_y = &voucher.derived_pubkey.y;
        let claim_contract_fr =
            fr_from_be_bytes(&pad_address(&voucher.context.claim_contract));
        let nullifier =
            hash_claim_nullifier(m_packed, r_packed, claim_contract_fr, c_packed);

        let claim_witness = ClaimWitness {
            round_id_hi: fr_from_be_bytes(&voucher.context.round_id[..16]),
            round_id_lo: fr_from_be_bytes(&voucher.context.round_id[16..32]),
            cohort_root: fr_from_be_bytes(&cohort_root_be),
            chain_id_hi: fr_from_be_bytes(&voucher.context.chain_id.as_bytes()[..16]),
            chain_id_lo: fr_from_be_bytes(&voucher.context.chain_id.as_bytes()[16..32]),
            derived_pubkey_x_hi: fr_from_be_bytes(&derived_x[..16]),
            derived_pubkey_x_lo: fr_from_be_bytes(&derived_x[16..32]),
            derived_pubkey_y_hi: fr_from_be_bytes(&derived_y[..16]),
            derived_pubkey_y_lo: fr_from_be_bytes(&derived_y[16..32]),
            amount: amount_fr,
            nullifier,
            claim_contract_address: claim_contract_fr,
            relay_submitter: fr_from_be_bytes(&pad_address(&self.relay_submitter)),
            m_x_hi,
            m_x_lo,
            m_y_hi,
            m_y_lo,
            signature_r: voucher.signature.r,
            signature_s: voucher.signature.s,
            merkle_path: cohort_path,
        };
        let claim_proof = self.prover.generate_claim_proof(&claim_witness)?;

        let pool_witness = PoolWithdrawWitness {
            pool_root: fr_from_be_bytes(&pool_root_be),
            claim_nullifier: nullifier,
            token: token_fr,
            amount: amount_fr,
            recipient: fr_from_be_bytes(&pad_address(&voucher.destination)),
            m_x_hi,
            m_x_lo,
            m_y_hi,
            m_y_lo,
            round_id_hi: claim_witness.round_id_hi,
            round_id_lo: claim_witness.round_id_lo,
            chain_id_hi: claim_witness.chain_id_hi,
            chain_id_lo: claim_witness.chain_id_lo,
            claim_contract: claim_witness.claim_contract_address,
            merkle_path: pool_path,
        };
        let pool_proof = self.prover.generate_pool_withdraw_proof(&pool_witness)?;

        Ok(SubmissionArtifacts {
            voucher,
            claim_witness,
            claim_proof,
            pool_witness,
            pool_proof,
        })
    }
}

pub struct SubmissionArtifacts {
    pub voucher: SignedVoucher,
    pub claim_witness: ClaimWitness,
    pub claim_proof: Vec<u8>,
    pub pool_witness: PoolWithdrawWitness,
    pub pool_proof: Vec<u8>,
}

fn pad_address(addr: &Address) -> Bytes32 {
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(addr);
    padded
}

fn fr_to_be_bytes(fr: &Fr) -> Bytes32 {
    let bigint = fr.into_bigint();
    let le = bigint.to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

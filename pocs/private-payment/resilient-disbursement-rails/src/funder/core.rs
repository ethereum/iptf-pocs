//! Funder actor: builds + signs round headers; precomputes per-recipient
//! commitments off-chain (factory deposits them at `publishRound`); recovers
//! residual via a balance-accounting call (no ZK on the residual path).

use alloy::{
    primitives::{
        Address as AlloyAddress,
        Bytes,
        TxHash,
        U256,
    },
    providers::Provider,
    sol,
    sol_types::SolCall,
};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use k256::{
    SecretKey,
    ecdsa::SigningKey,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::{
    DOMAIN_HEADER,
    DOMAIN_ROSTER,
    companion::types::RelayRoster,
    crypto::multisig::{
        MultiSignature,
        address_from_verifying_key,
        encode_threshold,
        sign_digest,
    },
    funder::error::FunderError,
    poseidon::{
        fr_from_be_bytes,
        hash_m_packed,
        hash_pool_commitment,
        pack_round_id,
    },
    types::{
        Address,
        Bytes32,
        RoundHeader,
        SecpPubkey,
        U256Be,
    },
};

// alloy bindings for the on-chain Multisig and ClaimContract residual call.
sol! {
    #[sol(rpc)]
    interface IMultisig {
        function propose(address target, bytes calldata data) external returns (uint256);
        function confirm(uint256 proposalId) external;
        function execute(uint256 proposalId) external;
        function proposalCount() external view returns (uint256);
    }

    interface IClaimContract {
        function funderUnshieldResidual(uint256 roundId) external;
    }
}

pub struct Funder {
    pub multisig_signers: Vec<SigningKey>,
    pub claim_contract: Address,
    pub funder_residual_destination: Address,
    pub funder_owners: Vec<Address>,
    pub threshold: usize,
    pub multisig_address: Address,
}

impl Funder {
    /// Lightweight constructor for off-chain-only flows (commitment
    /// computation, header building) where multisig validation is not
    /// exercised. Owners/threshold are empty and `multisig_address` is the
    /// zero address. Use `with_multisig` for the production-shaped flow.
    pub fn new(
        multisig_signers: Vec<SigningKey>,
        claim_contract: Address,
        funder_residual_destination: Address,
    ) -> Self {
        Self {
            multisig_signers,
            claim_contract,
            funder_residual_destination,
            funder_owners: Vec::new(),
            threshold: 0,
            multisig_address: [0u8; 20],
        }
    }

    /// Production-shaped constructor: validates that
    /// `multisig_signers.len() >= threshold` and that each signer's derived
    /// address belongs to `funder_owners`.
    pub fn with_multisig(
        multisig_signers: Vec<SigningKey>,
        funder_owners: Vec<Address>,
        threshold: usize,
        multisig_address: Address,
        claim_contract: Address,
        funder_residual_destination: Address,
    ) -> Result<Self, FunderError> {
        if threshold == 0 {
            return Err(FunderError::ThresholdConfig(
                "threshold must be > 0".to_string(),
            ));
        }
        if multisig_signers.len() < threshold {
            return Err(FunderError::ThresholdConfig(format!(
                "have {} signers but need {}",
                multisig_signers.len(),
                threshold
            )));
        }
        for (i, sk) in multisig_signers.iter().enumerate() {
            let addr = address_from_verifying_key(sk.verifying_key());
            if !funder_owners.iter().any(|o| o == &addr) {
                return Err(FunderError::ThresholdConfig(format!(
                    "signer index {i} (address {}) not in funder_owners",
                    hex::encode(addr)
                )));
            }
        }
        Ok(Self {
            multisig_signers,
            claim_contract,
            funder_residual_destination,
            funder_owners,
            threshold,
            multisig_address,
        })
    }

    /// Construct an unsigned round header. `close_time` is a unix timestamp
    /// (seconds).
    pub fn build_round_header(
        &self,
        round_id: Bytes32,
        cohort_version: u64,
        cohort_root: Bytes32,
        per_recipient_amount: U256Be,
        cohort_size: u64,
        token: Address,
        close_time: u64,
        chain_id: U256Be,
    ) -> RoundHeader {
        RoundHeader {
            round_id,
            cohort_version,
            cohort_root,
            per_recipient_amount,
            cohort_size,
            token,
            close_time,
            claim_contract_address: self.claim_contract,
            chain_id,
        }
    }

    /// `H_header = SHA256(DOMAIN_HEADER || encode(...))` per SPEC Round
    /// Header. `firstPoolLeafIndex` is NOT in `H_header`.
    pub fn h_header(header: &RoundHeader) -> Bytes32 {
        let mut hasher = Sha256::new();
        let domain_digest: Bytes32 = {
            let mut d = [0u8; 32];
            d.copy_from_slice(&Sha256::digest(DOMAIN_HEADER));
            d
        };
        hasher.update(domain_digest);
        hasher.update(serialize_round_header(header));
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    /// Multisig sign-and-encode over `H_header`. Returns the wire-format
    /// `Vec<u8>` consumed by the on-chain `Multisig` and the off-chain
    /// `crate::crypto::multisig::decode_threshold`.
    ///
    /// Each of `self.multisig_signers[0..self.threshold]` produces an EOA
    /// ECDSA signature over the prehash. Errors if `threshold == 0`.
    pub fn sign_round_header(
        &self,
        header: &RoundHeader,
    ) -> Result<Vec<u8>, FunderError> {
        if self.threshold == 0 {
            return Err(FunderError::ThresholdConfig(
                "sign_round_header requires a non-zero threshold; use with_multisig"
                    .to_string(),
            ));
        }
        let digest = Self::h_header(header);
        let sigs: Vec<MultiSignature> = self
            .multisig_signers
            .iter()
            .take(self.threshold)
            .map(|sk| sign_digest(&signing_key_to_secret(sk), &digest))
            .collect();
        Ok(encode_threshold(&sigs))
    }

    /// Compute `roster_digest = sha256(DOMAIN_ROSTER || count_be(u32) || per
    /// relay { relay_id (32) || x25519_pub (32) || rotation_epoch_be(u64) }
    /// || signed_at_unix_be(u64))` and sign with the first `threshold`
    /// signers.
    pub fn sign_roster(&self, roster: &RelayRoster) -> Result<Vec<u8>, FunderError> {
        if self.threshold == 0 {
            return Err(FunderError::ThresholdConfig(
                "sign_roster requires a non-zero threshold; use with_multisig"
                    .to_string(),
            ));
        }
        let digest = roster_digest(roster);
        let sigs: Vec<MultiSignature> = self
            .multisig_signers
            .iter()
            .take(self.threshold)
            .map(|sk| sign_digest(&signing_key_to_secret(sk), &digest))
            .collect();
        Ok(encode_threshold(&sigs))
    }

    /// Compute per-recipient commitments off-chain from the registry's `M`
    /// values. The factory uses these to deposit into the pool sub-tree.
    pub fn compute_round_commitments(
        &self,
        header: &RoundHeader,
        m_values: &[SecpPubkey],
    ) -> Result<Vec<Bytes32>, FunderError> {
        if m_values.len() != header.cohort_size as usize {
            return Err(FunderError::RegistryMismatch);
        }
        let token_fr = {
            let mut padded = [0u8; 32];
            padded[12..].copy_from_slice(&header.token);
            fr_from_be_bytes(&padded)
        };
        let amount_fr =
            Fr::from_be_bytes_mod_order(header.per_recipient_amount.as_bytes());
        let r_packed = pack_round_id(
            fr_from_be_bytes(&header.round_id[..16]),
            fr_from_be_bytes(&header.round_id[16..32]),
        );
        let mut out = Vec::with_capacity(m_values.len());
        for m in m_values {
            let m_x_hi = fr_from_be_bytes(&m.x[..16]);
            let m_x_lo = fr_from_be_bytes(&m.x[16..32]);
            let m_y_hi = fr_from_be_bytes(&m.y[..16]);
            let m_y_lo = fr_from_be_bytes(&m.y[16..32]);
            let m_packed = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
            let commit = hash_pool_commitment(token_fr, amount_fr, m_packed, r_packed);
            out.push(fr_to_be_bytes(&commit));
        }
        Ok(out)
    }

    /// Drive the on-chain `Multisig` propose/confirm/execute flow to invoke
    /// `claimContract.funderUnshieldResidual(roundId)`.
    ///
    /// `signer_providers[i]` MUST correspond to `multisig_signers[i]` (i.e.
    /// the provider's wallet signs from that signer's EOA). Pre-wiring
    /// providers at the call site keeps alloy's nonce filler consistent
    /// across multiple txns from the same EOA. Returns the `execute`
    /// transaction hash on success.
    pub async fn recover_residual<P: Provider + Clone>(
        &self,
        round_id: U256,
        signer_providers: &[P],
    ) -> Result<TxHash, FunderError> {
        if self.threshold == 0 {
            return Err(FunderError::ThresholdConfig(
                "recover_residual requires a non-zero threshold; use with_multisig"
                    .to_string(),
            ));
        }
        if signer_providers.len() < self.threshold {
            return Err(FunderError::ThresholdConfig(format!(
                "have {} providers but need {}",
                signer_providers.len(),
                self.threshold
            )));
        }

        let multisig_addr = AlloyAddress::from_slice(&self.multisig_address);
        let claim_contract_addr = AlloyAddress::from_slice(&self.claim_contract);

        // 1. ABI-encode `funderUnshieldResidual(roundId)` calldata.
        let call_data = Bytes::from(
            IClaimContract::funderUnshieldResidualCall { roundId: round_id }.abi_encode(),
        );

        // Read the next proposal id BEFORE proposing.
        let proposal_id = IMultisig::new(multisig_addr, &signer_providers[0])
            .proposalCount()
            .call()
            .await
            .map_err(|e| FunderError::MultisigPropose(format!("proposalCount: {e}")))?;

        // 2. Signer 0 proposes.
        let propose_tx = IMultisig::new(multisig_addr, &signer_providers[0])
            .propose(claim_contract_addr, call_data)
            .send()
            .await
            .map_err(|e| FunderError::MultisigPropose(format!("send: {e}")))?;
        let propose_receipt = propose_tx
            .get_receipt()
            .await
            .map_err(|e| FunderError::MultisigPropose(format!("receipt: {e}")))?;
        if !propose_receipt.status() {
            return Err(FunderError::MultisigPropose(
                "propose tx reverted".to_string(),
            ));
        }

        // 3. Confirm from each of the `threshold` signers (Multisig.sol does
        //    NOT auto-confirm in `propose`, so signer 0 must also confirm).
        for (i, p) in signer_providers.iter().take(self.threshold).enumerate() {
            let confirm_tx = IMultisig::new(multisig_addr, p)
                .confirm(proposal_id)
                .send()
                .await
                .map_err(|e| {
                    FunderError::MultisigConfirm(format!("signer {i} send: {e}"))
                })?;
            let confirm_receipt = confirm_tx.get_receipt().await.map_err(|e| {
                FunderError::MultisigConfirm(format!("signer {i} receipt: {e}"))
            })?;
            if !confirm_receipt.status() {
                return Err(FunderError::MultisigConfirm(format!(
                    "signer {i} confirm tx reverted"
                )));
            }
        }

        // 4. Signer 0 executes; capture tx hash.
        let execute_tx = IMultisig::new(multisig_addr, &signer_providers[0])
            .execute(proposal_id)
            .send()
            .await
            .map_err(|e| FunderError::MultisigExecute(format!("send: {e}")))?;
        let execute_receipt = execute_tx
            .get_receipt()
            .await
            .map_err(|e| FunderError::MultisigExecute(format!("receipt: {e}")))?;
        if !execute_receipt.status() {
            return Err(FunderError::MultisigExecute(
                "execute tx reverted".to_string(),
            ));
        }
        Ok(execute_receipt.transaction_hash)
    }
}

/// Canonical 192-byte header layout. Mirrors the off-chain
/// `Companion::h_header` SHA-256 input field-for-field. Keep in sync with
/// the SIGN_VOUCHER APDU body's `serialized_header` slice.
// TODO(phase6-cleanup): dedupe with smartcard::apdu::serialize_round_header
// once both Wave 2 agents land.
fn serialize_round_header(h: &RoundHeader) -> [u8; 192] {
    let mut out = [0u8; 192];
    out[0..32].copy_from_slice(&h.round_id);
    out[32..40].copy_from_slice(&h.cohort_version.to_be_bytes());
    out[40..72].copy_from_slice(&h.cohort_root);
    out[72..104].copy_from_slice(h.per_recipient_amount.as_bytes());
    out[104..112].copy_from_slice(&h.cohort_size.to_be_bytes());
    out[112..132].copy_from_slice(&h.token);
    out[132..140].copy_from_slice(&h.close_time.to_be_bytes());
    out[140..160].copy_from_slice(&h.claim_contract_address);
    out[160..192].copy_from_slice(h.chain_id.as_bytes());
    out
}

/// `roster_digest = sha256(DOMAIN_ROSTER || count_be(u32) ||
/// for relay { relay_id || x25519_pub || rotation_epoch_be(u64) } ||
/// signed_at_unix_be(u64))`.
fn roster_digest(roster: &RelayRoster) -> Bytes32 {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_ROSTER);
    let count: u32 = roster.relays.len() as u32;
    hasher.update(count.to_be_bytes());
    for r in &roster.relays {
        hasher.update(r.relay_id);
        hasher.update(r.static_pub_x25519);
        hasher.update(r.rotation_epoch.to_be_bytes());
    }
    hasher.update(roster.signed_at_unix.to_be_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

fn signing_key_to_secret(sk: &SigningKey) -> SecretKey {
    SecretKey::from(sk.clone())
}

fn fr_to_be_bytes(fr: &Fr) -> Bytes32 {
    use ark_ff::BigInteger;
    let bigint = fr.into_bigint();
    let le = bigint.to_bytes_le();
    let mut be = [0u8; 32];
    for i in 0..32 {
        be[i] = le[31 - i];
    }
    be
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::rand_core::OsRng;

    use super::*;
    use crate::{
        crypto::multisig::{
            decode_threshold,
            verify_threshold,
        },
        types::U256Be,
    };

    fn fresh_signer() -> (SigningKey, Address) {
        let sk = SecretKey::random(&mut OsRng);
        let signing = SigningKey::from(sk);
        let addr = address_from_verifying_key(signing.verifying_key());
        (signing, addr)
    }

    fn sample_header() -> RoundHeader {
        RoundHeader {
            round_id: [0x42; 32],
            cohort_version: 1,
            cohort_root: [0xab; 32],
            per_recipient_amount: U256Be::from_u64(1_000_000),
            cohort_size: 2,
            token: [0xcc; 20],
            close_time: 1_700_000_000,
            claim_contract_address: [0xee; 20],
            chain_id: U256Be::from_u64(11_155_111),
        }
    }

    #[test]
    fn test_h_header_deterministic() {
        let h = sample_header();
        assert_eq!(Funder::h_header(&h), Funder::h_header(&h));
    }

    #[test]
    fn test_compute_round_commitments_matches_count() {
        let funder = Funder::new(vec![], [0xee; 20], [0xff; 20]);
        let header = sample_header();
        let m_list = vec![
            SecpPubkey {
                x: [0x01; 32],
                y: [0x02; 32],
            },
            SecpPubkey {
                x: [0x03; 32],
                y: [0x04; 32],
            },
        ];
        let commits = funder.compute_round_commitments(&header, &m_list).unwrap();
        assert_eq!(commits.len(), 2);
        assert_ne!(commits[0], commits[1]);
    }

    #[test]
    fn test_compute_round_commitments_mismatch_size() {
        let funder = Funder::new(vec![], [0xee; 20], [0xff; 20]);
        let header = sample_header();
        let m_list = vec![SecpPubkey {
            x: [0x01; 32],
            y: [0x02; 32],
        }];
        let err = funder.compute_round_commitments(&header, &m_list);
        assert!(matches!(err, Err(FunderError::RegistryMismatch)));
    }

    #[test]
    fn test_with_multisig_validates_signer_count() {
        let (sk0, addr0) = fresh_signer();
        let (_sk1, addr1) = fresh_signer();
        let owners = vec![addr0, addr1];
        let res = Funder::with_multisig(
            vec![sk0],
            owners,
            2, // threshold > signer count
            [0u8; 20],
            [0xee; 20],
            [0xff; 20],
        );
        assert!(matches!(res, Err(FunderError::ThresholdConfig(_))));
    }

    #[test]
    fn test_with_multisig_rejects_signer_not_in_owners() {
        let (sk0, _addr0) = fresh_signer();
        let (_sk1, addr1) = fresh_signer();
        let (_sk2, addr2) = fresh_signer();
        let owners = vec![addr1, addr2]; // sk0's address NOT in owners
        let res = Funder::with_multisig(
            vec![sk0],
            owners,
            1,
            [0u8; 20],
            [0xee; 20],
            [0xff; 20],
        );
        assert!(matches!(res, Err(FunderError::ThresholdConfig(_))));
    }

    #[test]
    fn test_sign_round_header_roundtrip() {
        // Given: a 4-of-7 multisig configuration and a sample header.
        let pairs: Vec<(SigningKey, Address)> = (0..7).map(|_| fresh_signer()).collect();
        let owners: Vec<Address> = pairs.iter().map(|(_, a)| *a).collect();
        let signers: Vec<SigningKey> = pairs.iter().map(|(sk, _)| sk.clone()).collect();
        let funder = Funder::with_multisig(
            signers,
            owners.clone(),
            4,
            [0xab; 20],
            [0xee; 20],
            [0xff; 20],
        )
        .expect("valid multisig config");
        let header = sample_header();

        // When: the funder signs the header.
        let bytes = funder
            .sign_round_header(&header)
            .expect("threshold > 0, must sign");

        // Then: decoding produces 4 sigs and verify_threshold passes.
        let digest = Funder::h_header(&header);
        let sigs = decode_threshold(&bytes, 4).expect("decode");
        assert_eq!(sigs.len(), 4);
        verify_threshold(&digest, &sigs, &owners, 4).expect("verify");
    }

    #[test]
    fn test_sign_roster_roundtrip() {
        // Given: a 4-of-7 multisig and a sample roster.
        let pairs: Vec<(SigningKey, Address)> = (0..7).map(|_| fresh_signer()).collect();
        let owners: Vec<Address> = pairs.iter().map(|(_, a)| *a).collect();
        let signers: Vec<SigningKey> = pairs.iter().map(|(sk, _)| sk.clone()).collect();
        let funder = Funder::with_multisig(
            signers,
            owners.clone(),
            4,
            [0xab; 20],
            [0xee; 20],
            [0xff; 20],
        )
        .expect("valid multisig config");
        let roster = RelayRoster {
            relays: vec![crate::companion::types::RelayDescriptor {
                relay_id: [0x11; 32],
                static_pub_x25519: [0x22; 32],
                rotation_epoch: 7,
            }],
            signed_at_unix: 1_700_000_000,
            signature: vec![],
        };

        // When: the funder signs the roster.
        let bytes = funder.sign_roster(&roster).expect("must sign");

        // Then: the wire-format decodes and verifies against owners.
        let digest = roster_digest(&roster);
        let sigs = decode_threshold(&bytes, 4).expect("decode");
        verify_threshold(&digest, &sigs, &owners, 4).expect("verify");
    }

    #[test]
    fn test_sign_round_header_requires_threshold() {
        // Given: a Funder constructed via `new` (threshold = 0).
        let funder = Funder::new(vec![], [0xee; 20], [0xff; 20]);
        // When/Then: sign_round_header errors.
        let err = funder.sign_round_header(&sample_header()).unwrap_err();
        assert!(matches!(err, FunderError::ThresholdConfig(_)));
    }
}

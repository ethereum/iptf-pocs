//! `SoftwareSmartcard`: in-process emulator of the JCOP-class secure
//! element. Holds the master scalar `m`; zeroize on drop. Dispatches the
//! three protocol APDUs and refuses every other INS.
//!
//! **Critical correctness invariant**: the SIGN_VOUCHER APDU body MUST
//! contain only `(authToken, voucherContext)`. The card MUST construct the
//! 308-byte SHA-256 preimage internally. Any APDU that supplies a
//! pre-hashed `H_msg` is rejected with `CardError::PreHashedHMsgRefused`.

use std::sync::atomic::{
    AtomicBool,
    Ordering,
};

use k256::SecretKey;
use sha2::{
    Digest,
    Sha256,
};

use subtle::ConstantTimeEq;

use crate::{
    DOMAIN_HEADER,
    DOMAIN_VOUCHER,
    VOUCHER_PREIMAGE_LEN,
    crypto::{
        ecdsa::{
            derive_pubkey,
            scalar_to_pubkey,
            sign_voucher,
        },
        hmac::{
            derive_auth_token,
            derive_stealth_scalar,
        },
    },
    error::CardError,
    ports::smartcard::{
        INS_EXPORT_KEY,
        INS_GENERATE_KEY,
        INS_SIGN_VOUCHER,
        Smartcard,
    },
    smartcard::apdu::{
        SERIALIZED_HEADER_LEN,
        SIGN_VOUCHER_BODY_LEN,
        VOUCHER_CTX_LEN,
    },
    types::{
        Bytes32,
        SecpPubkey,
        U256Be,
    },
};

/// SHA-256 of `DOMAIN_VOUCHER` (`b"RDR/voucher/v1"`); pinned in the SPEC
/// preimage as the first 32 bytes.
fn voucher_domain_sha256() -> Bytes32 {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(DOMAIN_VOUCHER));
    out
}

pub struct SoftwareSmartcard {
    /// `m`. `k256::SecretKey` already zeroizes its internal scalar on drop,
    /// so we don't need to wrap it; we just hold the `Option` and rely on
    /// `Drop`.
    m: Option<SecretKey>,
    /// Optional companion-pre-key shared secret for `authToken` verification.
    /// Production cards MUST authenticate the auth token; the PoC keeps a
    /// toggle for tests that want to skip the companion-side derivation.
    companion_pre_key: Option<Bytes32>,
    /// When `true`, the card refuses to sign without a verified `authToken`.
    expects_auth_token: bool,
    /// One-shot guard against the "MSE/AUTHENTICATE preimage" bypass: any
    /// future APDU that smuggles a pre-hashed digest is rejected by
    /// construction, but we also gate the sign path on this flag to make
    /// the refusal explicit.
    refuses_prehashed: AtomicBool,
}

impl SoftwareSmartcard {
    /// New software card; key is generated lazily on first GENERATE_KEY.
    pub fn new(companion_pre_key: Option<Bytes32>, expects_auth_token: bool) -> Self {
        Self {
            m: None,
            companion_pre_key,
            expects_auth_token,
            refuses_prehashed: AtomicBool::new(true),
        }
    }

    /// Test helper: pre-load `m`. Production firmware never exposes this.
    #[cfg(test)]
    pub fn with_master_key(mut self, m: SecretKey) -> Self {
        self.m = Some(m);
        self
    }

    fn ensure_key(&mut self) -> Result<&SecretKey, CardError> {
        if self.m.is_none() {
            let m = SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
            self.m = Some(m);
        }
        // SAFETY: just established `Some`.
        Ok(self.m.as_ref().unwrap())
    }

    fn handle_generate_key(&mut self) -> Result<Vec<u8>, CardError> {
        if self.m.is_none() {
            let m = SecretKey::random(&mut k256::elliptic_curve::rand_core::OsRng);
            self.m = Some(m);
        }
        Ok(vec![0x90, 0x00])
    }

    fn handle_export_key(&mut self) -> Result<Vec<u8>, CardError> {
        let m = self.m.as_ref().ok_or(CardError::KeyNotGenerated)?;
        let pk = derive_pubkey(m);
        let mut out = Vec::with_capacity(64 + 2);
        out.extend_from_slice(&pk.x);
        out.extend_from_slice(&pk.y);
        out.push(0x90);
        out.push(0x00);
        Ok(out)
    }

    fn handle_sign_voucher(&mut self, body: &[u8]) -> Result<Vec<u8>, CardError> {
        // Refusal of pre-hashed H_msg by construction: a 32-byte body looks
        // like a bare digest, reject explicitly. The auth_token-only legacy
        // path would also be 32 bytes, so this dual-purpose refusal covers
        // both.
        if !self.refuses_prehashed.load(Ordering::Relaxed) {
            return Err(CardError::PreHashedHMsgRefused);
        }
        if body.len() == 32 {
            return Err(CardError::PreHashedHMsgRefused);
        }
        if body.len() != SIGN_VOUCHER_BODY_LEN {
            return Err(CardError::BadApdu);
        }

        // Parse body: auth_token(32) || serialized_header(192) || ctx(148).
        let mut auth_token = [0u8; 32];
        auth_token.copy_from_slice(&body[..32]);
        let serialized_header = &body[32..32 + SERIALIZED_HEADER_LEN];
        let ctx_bytes = &body[32 + SERIALIZED_HEADER_LEN..];
        debug_assert_eq!(ctx_bytes.len(), VOUCHER_CTX_LEN);

        // Decode VoucherContext.
        let mut ctx_round_id = [0u8; 32];
        let mut ctx_cohort_root = [0u8; 32];
        let mut ctx_claim_contract = [0u8; 20];
        let mut ctx_amount_be = [0u8; 32];
        let mut ctx_chain_id_be = [0u8; 32];
        ctx_round_id.copy_from_slice(&ctx_bytes[0..32]);
        ctx_cohort_root.copy_from_slice(&ctx_bytes[32..64]);
        ctx_claim_contract.copy_from_slice(&ctx_bytes[64..84]);
        ctx_amount_be.copy_from_slice(&ctx_bytes[84..116]);
        ctx_chain_id_be.copy_from_slice(&ctx_bytes[116..148]);
        let amount = U256Be(ctx_amount_be);
        let chain_id = U256Be(ctx_chain_id_be);

        // Verify ctx fields agree with the corresponding bytes in the
        // serialized_header. Layout offsets must match
        // `serialize_round_header`.
        // round_id @ [0..32]
        if &serialized_header[0..32] != ctx_round_id.as_slice() {
            return Err(CardError::CtxHeaderMismatch);
        }
        // cohort_root @ [40..72]
        if &serialized_header[40..72] != ctx_cohort_root.as_slice() {
            return Err(CardError::CtxHeaderMismatch);
        }
        // per_recipient_amount @ [72..104]
        if &serialized_header[72..104] != ctx_amount_be.as_slice() {
            return Err(CardError::CtxHeaderMismatch);
        }
        // claim_contract_address @ [140..160]
        if &serialized_header[140..160] != ctx_claim_contract.as_slice() {
            return Err(CardError::CtxHeaderMismatch);
        }
        // chain_id @ [160..192]
        if &serialized_header[160..192] != ctx_chain_id_be.as_slice() {
            return Err(CardError::CtxHeaderMismatch);
        }

        // Compute h_header = sha256(domain_digest || serialized_header).
        // The card MUST recompute SHA-256 itself (no trust of any
        // externally-supplied digest).
        let mut domain_digest = [0u8; 32];
        domain_digest.copy_from_slice(&Sha256::digest(DOMAIN_HEADER));
        let mut hasher = Sha256::new();
        hasher.update(domain_digest);
        hasher.update(serialized_header);
        let mut h_header = [0u8; 32];
        h_header.copy_from_slice(&hasher.finalize());

        // Auth-token verification (production default; tests may opt out).
        if self.expects_auth_token {
            let key = self.companion_pre_key.ok_or(CardError::AuthTokenMismatch)?;
            let expected = derive_auth_token(&key, &h_header);
            // Constant-time compare guards against per-byte timing oracle.
            if expected.ct_eq(&auth_token).unwrap_u8() != 1 {
                return Err(CardError::AuthTokenMismatch);
            }
        }

        // Derive stealth scalar and pubkey from `m`.
        let m = self.ensure_key()?.clone();
        let derived =
            derive_stealth_scalar(&m, &ctx_round_id, &ctx_claim_contract, &chain_id);
        let derived_scalar = derived.to_nonzero_scalar();
        let derived_pubkey: SecpPubkey = scalar_to_pubkey(&derived_scalar);
        let m_pubkey = derive_pubkey(&m);

        // Build the 308-byte preimage internally.
        let mut preimage = [0u8; VOUCHER_PREIMAGE_LEN];
        preimage[0..32].copy_from_slice(&voucher_domain_sha256());
        preimage[32..64].copy_from_slice(&ctx_round_id);
        preimage[64..96].copy_from_slice(&ctx_cohort_root);
        preimage[96..128].copy_from_slice(chain_id.as_bytes());
        preimage[128..160].copy_from_slice(&m_pubkey.x);
        preimage[160..192].copy_from_slice(&m_pubkey.y);
        preimage[192..224].copy_from_slice(&derived_pubkey.x);
        preimage[224..256].copy_from_slice(&derived_pubkey.y);
        preimage[256..288].copy_from_slice(amount.as_bytes());
        preimage[288..308].copy_from_slice(&ctx_claim_contract);

        // SHA-256 the preimage and ECDSA-sign with `m`.
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&Sha256::digest(preimage));
        let sig = sign_voucher(&m, &digest)?;

        // Response: M_x || M_y || dx || dy || r || s || SW.
        let mut out = Vec::with_capacity(192 + 2);
        out.extend_from_slice(&m_pubkey.x);
        out.extend_from_slice(&m_pubkey.y);
        out.extend_from_slice(&derived_pubkey.x);
        out.extend_from_slice(&derived_pubkey.y);
        out.extend_from_slice(&sig.r);
        out.extend_from_slice(&sig.s);
        out.push(0x90);
        out.push(0x00);
        Ok(out)
    }
}

impl Smartcard for SoftwareSmartcard {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardError> {
        let (_, ins, _, _, body) = crate::smartcard::apdu::split_apdu(apdu)?;
        match ins {
            INS_GENERATE_KEY => self.handle_generate_key(),
            INS_EXPORT_KEY => self.handle_export_key(),
            INS_SIGN_VOUCHER => self.handle_sign_voucher(body),
            _ => Err(CardError::BadApdu),
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::Digest;

    use super::*;
    use crate::{
        crypto::ecdsa::xy_to_pubkey,
        smartcard::apdu::{
            decode_export_key_response,
            decode_generate_key_response,
            decode_sign_voucher_response,
            encode_export_key,
            encode_generate_key,
            encode_sign_voucher,
            serialize_round_header,
        },
        types::{
            RoundHeader,
            U256Be,
            VoucherContext,
        },
    };

    fn sample_header() -> RoundHeader {
        RoundHeader {
            round_id: [0xa1; 32],
            cohort_version: 1,
            cohort_root: [0xb2; 32],
            per_recipient_amount: U256Be::from_u64(1_000_000),
            cohort_size: 4,
            token: [0xdd; 20],
            close_time: 1_700_000_000,
            claim_contract_address: [0xcc; 20],
            chain_id: U256Be::from_u64(1),
        }
    }

    fn sample_ctx() -> VoucherContext {
        let h = sample_header();
        VoucherContext {
            round_id: h.round_id,
            cohort_root: h.cohort_root,
            claim_contract: h.claim_contract_address,
            per_recipient_amount: h.per_recipient_amount,
            chain_id: h.chain_id,
        }
    }

    fn h_header_for(header: &RoundHeader) -> Bytes32 {
        let domain_digest = Sha256::digest(crate::DOMAIN_HEADER);
        let serialized = serialize_round_header(header);
        let mut hasher = Sha256::new();
        hasher.update(&domain_digest);
        hasher.update(serialized);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hasher.finalize());
        out
    }

    #[test]
    fn test_generate_then_export_then_sign() {
        let mut card = SoftwareSmartcard::new(None, false);
        decode_generate_key_response(&card.transmit(&encode_generate_key()).unwrap())
            .unwrap();
        let m_pub =
            decode_export_key_response(&card.transmit(&encode_export_key()).unwrap())
                .unwrap();
        let _ = xy_to_pubkey(&m_pub).unwrap();

        let header = sample_header();
        let serialized = serialize_round_header(&header);
        let ctx = sample_ctx();
        let resp = card
            .transmit(&encode_sign_voucher([0u8; 32], &serialized, &ctx))
            .unwrap();
        let (m_pub2, dpub, sig) = decode_sign_voucher_response(&resp).unwrap();
        assert_eq!(m_pub, m_pub2);
        // Canonical-s: high bit clear.
        assert!(sig.s[0] <= 0x7f);
        // dpub != m_pub (different scalars).
        assert_ne!(m_pub.x, dpub.x);
    }

    #[test]
    fn test_export_key_before_generate_fails() {
        let mut card = SoftwareSmartcard::new(None, false);
        let resp = card.transmit(&encode_export_key());
        assert!(matches!(resp, Err(CardError::KeyNotGenerated)));
    }

    /// Critical refusal: a "32-byte body" smuggled as a pre-hashed digest
    /// must be rejected; the card constructs the preimage itself.
    #[test]
    fn test_refuses_pre_hashed_h_msg() {
        let mut card = SoftwareSmartcard::new(None, false);
        let _ = card.transmit(&encode_generate_key()).unwrap();
        // Hand-craft an APDU whose body is exactly 32 bytes (SHA-256 sized).
        let apdu = vec![
            0x80,
            INS_SIGN_VOUCHER,
            0x00,
            0x00,
            32, // header + Lc=32
            0u8,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            0xa,
            0xb,
            0xc,
            0xd,
            0xe,
            0xf, // 16 bytes
            0u8,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            9,
            0xa,
            0xb,
            0xc,
            0xd,
            0xe,
            0xf, // 16 bytes
        ];
        let resp = card.transmit(&apdu);
        assert!(matches!(resp, Err(CardError::PreHashedHMsgRefused)));
    }

    #[test]
    fn test_unknown_ins_rejected() {
        let mut card = SoftwareSmartcard::new(None, false);
        // Forge an APDU with INS=0x7f (a "spending key" bytecode that we
        // don't implement). Must be rejected.
        let apdu = vec![0x80, 0x7f, 0x00, 0x00, 0x00];
        assert!(matches!(card.transmit(&apdu), Err(CardError::BadApdu)));
    }

    #[test]
    fn test_auth_token_required_when_enabled() {
        let pre_key = [0xabu8; 32];
        let mut card = SoftwareSmartcard::new(Some(pre_key), true);
        let _ = card.transmit(&encode_generate_key()).unwrap();

        let header = sample_header();
        let serialized = serialize_round_header(&header);
        let ctx = sample_ctx();

        // Bad token: zeroes.
        let bad_apdu = encode_sign_voucher([0u8; 32], &serialized, &ctx);
        assert!(matches!(
            card.transmit(&bad_apdu),
            Err(CardError::AuthTokenMismatch)
        ));

        // Good token: HMAC(pre_key, h_header) where h_header is SHA-256 of
        // domain_digest || serialized_header — the same derivation the card
        // performs internally.
        let h_header = h_header_for(&header);
        let token = derive_auth_token(&pre_key, &h_header);
        let ok_apdu = encode_sign_voucher(token, &serialized, &ctx);
        let resp = card.transmit(&ok_apdu).unwrap();
        let _ = decode_sign_voucher_response(&resp).unwrap();
    }

    #[test]
    fn test_ctx_header_mismatch_rejected() {
        // When ctx fields disagree with the bound serialized_header, the
        // card returns CtxHeaderMismatch (regardless of expects_auth_token).
        let mut card = SoftwareSmartcard::new(None, false);
        let _ = card.transmit(&encode_generate_key()).unwrap();

        let header = sample_header();
        let serialized = serialize_round_header(&header);

        // Tamper the ctx round_id so it disagrees with header.
        let mut bad_ctx = sample_ctx();
        bad_ctx.round_id = [0x55; 32];
        let apdu = encode_sign_voucher([0u8; 32], &serialized, &bad_ctx);
        assert!(matches!(
            card.transmit(&apdu),
            Err(CardError::CtxHeaderMismatch)
        ));
    }
}

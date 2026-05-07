//! APDU encode/decode helpers. ISO-7816-4 case-3/case-4 layouts adapted to
//! the three INS bytes we use:
//!
//! ```text
//! CLA=0x80  INS=0x01  P1=0x00  P2=0x00  Lc=0    (no data)                  GENERATE_KEY
//! CLA=0x80  INS=0x02  P1=0x00  P2=0x00  Lc=0                                EXPORT_KEY
//! CLA=0x80  INS=0x03  P1=0x00  P2=0x00  Lc=372 [authToken(32) || hdr(192)   SIGN_VOUCHER
//!                                                || ctx(148)]
//! ```
//!
//! `serialized_header` for SIGN_VOUCHER is the 192-byte byte-for-byte image
//! of `RoundHeader` matching the off-chain SHA-256 input fed into
//! `H_header`. The card hashes `domain_digest || serialized_header`
//! internally; no externally-supplied digest is trusted.
//!
//! `ctx` is the 148-byte serialized `VoucherContext`: `roundId(32) ||
//! cohortRoot(32) || claimContract(20) || perRecipientAmount(32) ||
//! chainId(32)`.

use crate::{
    error::CardError,
    ports::smartcard::{
        INS_EXPORT_KEY,
        INS_GENERATE_KEY,
        INS_SIGN_VOUCHER,
    },
    types::{
        Bytes32,
        EcdsaSignature,
        RoundHeader,
        SecpPubkey,
        VoucherContext,
    },
};

const CLA: u8 = 0x80;
/// Length of the `VoucherContext` block alone (no auth token, no header).
pub const VOUCHER_CTX_LEN: usize = 32 + 32 + 20 + 32 + 32; // 148
/// Length of the serialized `RoundHeader` carried in SIGN_VOUCHER.
pub const SERIALIZED_HEADER_LEN: usize = 192;
/// Total SIGN_VOUCHER body length: auth_token(32) || serialized_header(192)
/// || voucher_ctx(148) = 372.
pub const SIGN_VOUCHER_BODY_LEN: usize = 32 + SERIALIZED_HEADER_LEN + VOUCHER_CTX_LEN;

/// Encode the GENERATE_KEY APDU.
pub fn encode_generate_key() -> Vec<u8> {
    vec![CLA, INS_GENERATE_KEY, 0x00, 0x00, 0x00]
}

/// Decode the GENERATE_KEY response. Empty body + status word `0x9000`.
pub fn decode_generate_key_response(resp: &[u8]) -> Result<(), CardError> {
    if resp.len() != 2 || resp != [0x90, 0x00] {
        return Err(CardError::BadApdu);
    }
    Ok(())
}

/// Encode the EXPORT_KEY APDU.
pub fn encode_export_key() -> Vec<u8> {
    vec![CLA, INS_EXPORT_KEY, 0x00, 0x00, 0x00]
}

/// Decode the EXPORT_KEY response: `M_x(32) || M_y(32) || SW1 SW2`.
pub fn decode_export_key_response(resp: &[u8]) -> Result<SecpPubkey, CardError> {
    if resp.len() != 64 + 2 {
        return Err(CardError::BadApdu);
    }
    if &resp[64..] != [0x90, 0x00] {
        return Err(CardError::BadApdu);
    }
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&resp[..32]);
    y.copy_from_slice(&resp[32..64]);
    Ok(SecpPubkey { x, y })
}

/// Serialize a `RoundHeader` into the canonical 192-byte big-endian form
/// fed into `H_header = SHA-256(domain_digest || serialized_header)`. Layout
/// is fixed and matches the off-chain companion / on-chain Solidity
/// derivations byte-for-byte.
///
/// | offset | size | field |
/// |--------|------|-------|
/// | 0      | 32   | round_id |
/// | 32     | 8    | cohort_version (be u64) |
/// | 40     | 32   | cohort_root |
/// | 72     | 32   | per_recipient_amount (U256 be) |
/// | 104    | 8    | cohort_size (be u64) |
/// | 112    | 20   | token (address) |
/// | 132    | 8    | close_time (be u64) |
/// | 140    | 20   | claim_contract_address |
/// | 160    | 32   | chain_id (U256 be) |
pub fn serialize_round_header(h: &RoundHeader) -> [u8; SERIALIZED_HEADER_LEN] {
    let mut out = [0u8; SERIALIZED_HEADER_LEN];
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

/// Encode the SIGN_VOUCHER APDU. The body is
/// `authToken(32) || serialized_header(192) || VoucherContext(148)`.
/// Total Lc = 372. Because 372 exceeds 255, the header uses ISO-7816
/// extended-length encoding (`00 Lc_hi Lc_lo`). `split_apdu` understands
/// both single- and extended-length forms.
pub fn encode_sign_voucher(
    auth_token: Bytes32,
    serialized_header: &[u8; SERIALIZED_HEADER_LEN],
    ctx: &VoucherContext,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(SIGN_VOUCHER_BODY_LEN);
    body.extend_from_slice(&auth_token);
    body.extend_from_slice(serialized_header);
    body.extend_from_slice(&ctx.round_id);
    body.extend_from_slice(&ctx.cohort_root);
    body.extend_from_slice(&ctx.claim_contract);
    body.extend_from_slice(ctx.per_recipient_amount.as_bytes());
    body.extend_from_slice(ctx.chain_id.as_bytes());
    debug_assert_eq!(body.len(), SIGN_VOUCHER_BODY_LEN);
    let mut apdu = Vec::with_capacity(7 + body.len());
    apdu.push(CLA);
    apdu.push(INS_SIGN_VOUCHER);
    apdu.push(0x00);
    apdu.push(0x00);
    let len = body.len();
    apdu.push(0x00);
    apdu.push((len >> 8) as u8);
    apdu.push((len & 0xff) as u8);
    apdu.extend_from_slice(&body);
    apdu
}

/// Decode the SIGN_VOUCHER response: `M_x(32) || M_y(32) || dx(32) ||
/// dy(32) || r(32) || s(32) || SW1 SW2`. Total 192 bytes payload + SW.
pub fn decode_sign_voucher_response(
    resp: &[u8],
) -> Result<(SecpPubkey, SecpPubkey, EcdsaSignature), CardError> {
    if resp.len() != 192 + 2 {
        return Err(CardError::BadApdu);
    }
    if &resp[192..] != [0x90, 0x00] {
        return Err(CardError::BadApdu);
    }
    let mut m_x = [0u8; 32];
    let mut m_y = [0u8; 32];
    let mut d_x = [0u8; 32];
    let mut d_y = [0u8; 32];
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    m_x.copy_from_slice(&resp[0..32]);
    m_y.copy_from_slice(&resp[32..64]);
    d_x.copy_from_slice(&resp[64..96]);
    d_y.copy_from_slice(&resp[96..128]);
    r.copy_from_slice(&resp[128..160]);
    s.copy_from_slice(&resp[160..192]);
    Ok((
        SecpPubkey { x: m_x, y: m_y },
        SecpPubkey { x: d_x, y: d_y },
        EcdsaSignature { r, s },
    ))
}

/// Decode the APDU header (CLA, INS, P1, P2, Lc) and split off the body.
///
/// Accepts both single-byte Lc (`Lc <= 255`, header is 5 bytes) and
/// ISO-7816-4 extended Lc (`apdu[4] == 0x00`, then `apdu[5..7]` carries the
/// 16-bit big-endian length, header is 7 bytes). Extended-length form is
/// used by `encode_sign_voucher` because its body (372 bytes) exceeds 255.
pub fn split_apdu(apdu: &[u8]) -> Result<(u8, u8, u8, u8, &[u8]), CardError> {
    if apdu.len() < 5 {
        return Err(CardError::BadApdu);
    }
    let cla = apdu[0];
    let ins = apdu[1];
    let p1 = apdu[2];
    let p2 = apdu[3];
    if cla != CLA {
        return Err(CardError::BadApdu);
    }

    // Single-byte Lc with `Lc != 0` covers GENERATE_KEY (Lc=0), EXPORT_KEY
    // (Lc=0) and any short SIGN_VOUCHER negative-test APDUs. The 0x00
    // sentinel signals extended-length form.
    let (lc, body_off) = if apdu[4] == 0x00 && apdu.len() >= 7 {
        let lc = ((apdu[5] as usize) << 8) | (apdu[6] as usize);
        (lc, 7)
    } else {
        (apdu[4] as usize, 5)
    };
    if apdu.len() != body_off + lc {
        return Err(CardError::BadApdu);
    }
    Ok((cla, ins, p1, p2, &apdu[body_off..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{
        RoundHeader,
        U256Be,
    };

    fn sample_ctx() -> VoucherContext {
        VoucherContext {
            round_id: [0xa1; 32],
            cohort_root: [0xb2; 32],
            claim_contract: [0xcc; 20],
            per_recipient_amount: U256Be::from_u64(1_000_000),
            chain_id: U256Be::from_u64(11_155_111),
        }
    }

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
            chain_id: U256Be::from_u64(11_155_111),
        }
    }

    #[test]
    fn test_encode_generate_key_shape() {
        assert_eq!(encode_generate_key(), vec![0x80, 0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_encode_sign_voucher_lc() {
        let hdr = serialize_round_header(&sample_header());
        let apdu = encode_sign_voucher([0u8; 32], &hdr, &sample_ctx());
        // header(7, extended Lc) + body(372)
        assert_eq!(apdu.len(), 7 + SIGN_VOUCHER_BODY_LEN);
        assert_eq!(apdu[0], 0x80);
        assert_eq!(apdu[1], 0x03);
        assert_eq!(apdu[4], 0x00);
        let lc = ((apdu[5] as usize) << 8) | (apdu[6] as usize);
        assert_eq!(lc, SIGN_VOUCHER_BODY_LEN);
    }

    #[test]
    fn test_split_apdu_roundtrip() {
        let hdr = serialize_round_header(&sample_header());
        let apdu = encode_sign_voucher([0xaa; 32], &hdr, &sample_ctx());
        let (cla, ins, _p1, _p2, body) = split_apdu(&apdu).unwrap();
        assert_eq!(cla, 0x80);
        assert_eq!(ins, INS_SIGN_VOUCHER);
        assert_eq!(body.len(), SIGN_VOUCHER_BODY_LEN);
    }

    #[test]
    fn test_serialize_round_header_byte_layout() {
        let hdr = sample_header();
        let bytes = serialize_round_header(&hdr);
        assert_eq!(&bytes[0..32], &hdr.round_id);
        assert_eq!(&bytes[32..40], &hdr.cohort_version.to_be_bytes());
        assert_eq!(&bytes[40..72], &hdr.cohort_root);
        assert_eq!(&bytes[72..104], hdr.per_recipient_amount.as_bytes());
        assert_eq!(&bytes[104..112], &hdr.cohort_size.to_be_bytes());
        assert_eq!(&bytes[112..132], &hdr.token);
        assert_eq!(&bytes[132..140], &hdr.close_time.to_be_bytes());
        assert_eq!(&bytes[140..160], &hdr.claim_contract_address);
        assert_eq!(&bytes[160..192], hdr.chain_id.as_bytes());
    }

    #[test]
    fn test_decode_export_key_response() {
        let mut resp = [0u8; 66];
        for i in 0..32 {
            resp[i] = 0xaa;
            resp[32 + i] = 0xbb;
        }
        resp[64] = 0x90;
        resp[65] = 0x00;
        let pk = decode_export_key_response(&resp).unwrap();
        assert_eq!(pk.x, [0xaa; 32]);
        assert_eq!(pk.y, [0xbb; 32]);
    }
}

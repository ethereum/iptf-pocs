//! Smartcard port: APDU-shaped trait. The `Smartcard` impl owns the master
//! key material; companion code only sees the APDU response.

use crate::error::CardError;

/// `INS_GENERATE_KEY` (0x01) - generate fresh master keypair `(m, M)`.
pub const INS_GENERATE_KEY: u8 = 0x01;

/// `INS_EXPORT_KEY` (0x02) - return the master public key `M = (M_x, M_y)`.
pub const INS_EXPORT_KEY: u8 = 0x02;

/// `INS_SIGN_VOUCHER` (0x03) - sign a voucher; the card builds the 308-byte
/// preimage internally from `voucherContext` plus on-card-derived `M` and
/// `derivedPubkey`. The card MUST refuse any APDU that supplies a
/// pre-hashed `H_msg`.
pub const INS_SIGN_VOUCHER: u8 = 0x03;

/// APDU-shaped trait. `apdu` and `response` are raw byte buffers per ISO
/// 7816-4. The PoC's software smartcard refuses to dispatch any INS not in
/// `{0x01, 0x02, 0x03}`. There are NO spending-key APDUs.
pub trait Smartcard: Send + Sync {
    fn transmit(&mut self, apdu: &[u8]) -> Result<Vec<u8>, CardError>;
}

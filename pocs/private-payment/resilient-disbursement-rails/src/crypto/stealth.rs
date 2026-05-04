//! Stealth-destination derivation. SPEC Voucher Construction:
//!
//! ```text
//! destination = keccak256(derivedPubkey_x || derivedPubkey_y)[-20:]
//! ```
//!
//! On-chain the claim contract recomputes the same value from the public
//! `derivedPubkey` limbs and uses it as the stealth destination.

use crate::{
    crypto::ecdsa::point_to_eth_address,
    types::{
        Address,
        SecpPubkey,
    },
};

pub fn destination_from_derived_pubkey(p: &SecpPubkey) -> Address {
    point_to_eth_address(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_destination_deterministic() {
        let p = SecpPubkey {
            x: [0x12; 32],
            y: [0x34; 32],
        };
        assert_eq!(
            destination_from_derived_pubkey(&p),
            destination_from_derived_pubkey(&p)
        );
    }

    #[test]
    fn test_destination_changes_with_input() {
        let p1 = SecpPubkey {
            x: [0x12; 32],
            y: [0x34; 32],
        };
        let p2 = SecpPubkey {
            x: [0x12; 32],
            y: [0x35; 32],
        };
        assert_ne!(
            destination_from_derived_pubkey(&p1),
            destination_from_derived_pubkey(&p2)
        );
    }
}

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

    /// Pinned reference value matching the in-circuit
    /// `circuits/lib/src/keccak.nr::test_keccak256_64_byte_pattern`. If the
    /// off-circuit Rust implementation and the in-circuit Noir
    /// implementation diverge on this input, the destination computed by
    /// the relay will not match the destination enforced by the circuit's
    /// keccak constraint, and proofs will fail (or worse, send funds to
    /// the wrong EOA). Input: x = 0x00..0x1f, y = 0x20..0x3f. Expected
    /// keccak prefix matches `cast keccak`.
    #[test]
    fn test_destination_byte_pattern_matches_circuit() {
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        for i in 0..32u8 {
            x[i as usize] = i;
            y[i as usize] = 32 + i;
        }
        let p = SecpPubkey { x, y };
        let dest = destination_from_derived_pubkey(&p);
        // Last 20 bytes of
        //   0x002030bde3d4cf89919649775cd71875c4d0ab1708a380e03fefc3a28aa24831
        // i.e. bytes [12..32].
        let expected: [u8; 20] = [
            0x5c, 0xd7, 0x18, 0x75, 0xc4, 0xd0, 0xab, 0x17, 0x08, 0xa3, 0x80, 0xe0, 0x3f,
            0xef, 0xc3, 0xa2, 0x8a, 0xa2, 0x48, 0x31,
        ];
        assert_eq!(dest, expected);
    }
}

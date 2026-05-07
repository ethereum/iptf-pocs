//! Operator registry: holds `(cardId, M, status, cohort_position)` per
//! enrolled card. Rebuilds the cohort tree from `M_packed` leaves of
//! currently-active cards in cohort-position order and publishes
//! `(cohort_root, cohort_size)` on-chain. Rejects duplicate `M` and
//! duplicate `cardId`.

use ark_bn254::Fr;
use ark_ff::{
    BigInteger,
    PrimeField,
};

use crate::{
    ports::merkle::MerkleStore,
    poseidon::{
        fr_from_be_bytes,
        hash_m_packed,
    },
    registry::{
        error::RegistryError,
        types::{
            CardRecord,
            CardStatus,
            PersonalizationPacket,
        },
    },
    types::{
        Bytes32,
        SecpPubkey,
    },
};

pub struct OperatorRegistry<M: MerkleStore> {
    pub cards: Vec<CardRecord>,
    pub tree: M,
    pub current_version: u64,
}

impl<M: MerkleStore> OperatorRegistry<M> {
    pub fn new(tree: M) -> Self {
        Self {
            cards: Vec::new(),
            tree,
            current_version: 0,
        }
    }

    /// Sequential cohort_position assignment. Rejects duplicates.
    pub fn enroll(
        &mut self,
        card_id: Bytes32,
        m: SecpPubkey,
    ) -> Result<u64, RegistryError> {
        if self.cards.iter().any(|c| c.card_id == card_id) {
            return Err(RegistryError::DuplicateCard);
        }
        if self.cards.iter().any(|c| c.m == m) {
            return Err(RegistryError::DuplicateM);
        }
        let position = self.cards.len() as u64;
        self.cards.push(CardRecord {
            card_id,
            m,
            status: CardStatus::Active,
            cohort_position: position,
        });
        Ok(position)
    }

    pub fn revoke(&mut self, card_id: Bytes32) -> Result<(), RegistryError> {
        let entry = self
            .cards
            .iter_mut()
            .find(|c| c.card_id == card_id)
            .ok_or(RegistryError::UnknownCard)?;
        entry.status = CardStatus::Revoked;
        Ok(())
    }

    /// Wipe the merkle tree state and rebuild from active cards in
    /// cohort_position order. Note that `MerkleStore::insert` is the only
    /// way to mutate the tree; revoking a card therefore requires
    /// recreating a fresh `M` instance via the constructor in production.
    /// For PoC tests we'll re-construct the registry instead.
    pub fn rebuild_tree(&mut self) {
        // For lean-imt's append-only model, "rebuild" means "the tree the
        // caller passed in must be a fresh tree". We re-insert the active
        // M_packed leaves; if there were revocations, the caller is
        // responsible for handing us a fresh tree first.
        let active: Vec<&CardRecord> = self
            .cards
            .iter()
            .filter(|c| c.status == CardStatus::Active)
            .collect();
        // Sort by cohort_position to preserve canonical ordering.
        let mut ordered = active.clone();
        ordered.sort_by_key(|c| c.cohort_position);
        for c in ordered {
            let m_x_hi = fr_from_be_bytes(&c.m.x[..16]);
            let m_x_lo = fr_from_be_bytes(&c.m.x[16..32]);
            let m_y_hi = fr_from_be_bytes(&c.m.y[..16]);
            let m_y_lo = fr_from_be_bytes(&c.m.y[16..32]);
            let leaf = hash_m_packed(m_x_hi, m_x_lo, m_y_hi, m_y_lo);
            self.tree.insert(leaf);
        }
    }

    /// Returns the current cohort root (or `None` if the tree is empty)
    /// and bumps the version counter as part of a publication.
    pub fn publish_cohort(&mut self) -> Result<(u64, Option<Fr>, u64), RegistryError> {
        self.current_version += 1;
        let size = self
            .cards
            .iter()
            .filter(|c| c.status == CardStatus::Active)
            .count() as u64;
        Ok((self.current_version, self.tree.root(), size))
    }

    /// Operator personalization: enroll the card and emit the personalization
    /// packet that the operator embeds with the smartcard for the recipient.
    pub fn personalize(
        &mut self,
        card_id: Bytes32,
        m: SecpPubkey,
    ) -> Result<PersonalizationPacket, RegistryError> {
        let position = self.enroll(card_id, m)?;
        Ok(PersonalizationPacket {
            card_id,
            m,
            cohort_position: position,
            cohort_version: self.current_version + 1,
        })
    }

    /// Convenience: serialize the cohort root as 32 bytes big-endian.
    pub fn cohort_root_bytes(&self) -> Option<Bytes32> {
        self.tree.root().map(|fr| {
            let bigint = fr.into_bigint();
            let le = bigint.to_bytes_le();
            let mut be = [0u8; 32];
            for i in 0..32 {
                be[i] = le[31 - i];
            }
            be
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::lean_imt_merkle::LeanImtMerkleStore;

    #[test]
    fn test_enroll_assigns_sequential_position() {
        let mut reg = OperatorRegistry::new(LeanImtMerkleStore::new());
        let m1 = SecpPubkey {
            x: [0x01; 32],
            y: [0x02; 32],
        };
        let m2 = SecpPubkey {
            x: [0x03; 32],
            y: [0x04; 32],
        };
        assert_eq!(reg.enroll([0xa1; 32], m1).unwrap(), 0);
        assert_eq!(reg.enroll([0xa2; 32], m2).unwrap(), 1);
    }

    #[test]
    fn test_duplicate_card_rejected() {
        let mut reg = OperatorRegistry::new(LeanImtMerkleStore::new());
        let m1 = SecpPubkey {
            x: [0x01; 32],
            y: [0x02; 32],
        };
        let m2 = SecpPubkey {
            x: [0x03; 32],
            y: [0x04; 32],
        };
        reg.enroll([0xa1; 32], m1).unwrap();
        let err = reg.enroll([0xa1; 32], m2);
        assert!(matches!(err, Err(RegistryError::DuplicateCard)));
    }

    #[test]
    fn test_duplicate_m_rejected() {
        let mut reg = OperatorRegistry::new(LeanImtMerkleStore::new());
        let m1 = SecpPubkey {
            x: [0x01; 32],
            y: [0x02; 32],
        };
        reg.enroll([0xa1; 32], m1).unwrap();
        let err = reg.enroll([0xa2; 32], m1);
        assert!(matches!(err, Err(RegistryError::DuplicateM)));
    }

    #[test]
    fn test_personalize_emits_position_and_next_version() {
        let mut reg = OperatorRegistry::new(LeanImtMerkleStore::new());
        let m = SecpPubkey {
            x: [0x01; 32],
            y: [0x02; 32],
        };
        let pkt = reg.personalize([0xa1; 32], m).unwrap();
        assert_eq!(pkt.cohort_position, 0);
        assert_eq!(pkt.cohort_version, 1);
    }

    #[test]
    fn test_rebuild_then_publish_yields_root() {
        let mut reg = OperatorRegistry::new(LeanImtMerkleStore::new());
        let m1 = SecpPubkey {
            x: [0x01; 32],
            y: [0x02; 32],
        };
        let m2 = SecpPubkey {
            x: [0x03; 32],
            y: [0x04; 32],
        };
        reg.enroll([0xa1; 32], m1).unwrap();
        reg.enroll([0xa2; 32], m2).unwrap();
        reg.rebuild_tree();
        let (version, root, size) = reg.publish_cohort().unwrap();
        assert_eq!(version, 1);
        assert_eq!(size, 2);
        assert!(root.is_some());
    }

    #[test]
    fn test_revoke_marks_inactive() {
        let mut reg = OperatorRegistry::new(LeanImtMerkleStore::new());
        let m = SecpPubkey {
            x: [0x01; 32],
            y: [0x02; 32],
        };
        reg.enroll([0xa1; 32], m).unwrap();
        reg.revoke([0xa1; 32]).unwrap();
        assert_eq!(reg.cards[0].status, CardStatus::Revoked);
    }
}

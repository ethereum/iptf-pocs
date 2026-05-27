//! Organizer actor: assembles and validates a `PetitionDraft`.

use crate::{
    MAX_CLASS_SET_LEN,
    MAX_SIGNING_WINDOW_BLOCKS,
    error::PredicateError,
    organizer::{
        error::OrganizerError,
        types::PetitionDraft,
    },
    predicate::PredicateDef,
    types::{
        Address,
        Bytes32,
        ClassTag,
        U256Be,
    },
};

pub struct Organizer {
    pub organizer_address: Address,
}

impl Organizer {
    pub fn new(organizer_address: Address) -> Self {
        Self { organizer_address }
    }

    /// Assemble a `PetitionDraft`, mirroring every Registry structural check.
    #[allow(clippy::too_many_arguments)]
    pub fn build_petition(
        &self,
        r_root: Bytes32,
        predicate_def: PredicateDef,
        salt: Bytes32,
        class_set: Vec<ClassTag>,
        class_thresholds: Vec<u64>,
        class_index: u8,
        registration_block: u64,
        close_at_block: u64,
        bounty: U256Be,
    ) -> Result<PetitionDraft, OrganizerError> {
        if class_set.is_empty() || class_set.len() > MAX_CLASS_SET_LEN {
            return Err(OrganizerError::ClassSetSize(
                class_set.len(),
                MAX_CLASS_SET_LEN,
            ));
        }
        if !class_set.windows(2).all(|w| w[0] < w[1]) {
            return Err(OrganizerError::ClassSetNotSorted);
        }
        if class_thresholds.len() != class_set.len() {
            return Err(OrganizerError::ThresholdLenMismatch {
                thresholds: class_thresholds.len(),
                class_set: class_set.len(),
            });
        }

        if class_index as usize >= MAX_CLASS_SET_LEN {
            return Err(OrganizerError::ClassIndexOutOfRange(class_index));
        }

        predicate_def.validate()?;
        let operand = predicate_def.find_class_binding_operand(class_index)?;
        if !class_set.contains(&operand) {
            return Err(OrganizerError::Predicate(
                PredicateError::MissingClassBinding,
            ));
        }

        if close_at_block <= registration_block {
            return Err(OrganizerError::CloseInPast);
        }
        if close_at_block - registration_block > MAX_SIGNING_WINDOW_BLOCKS {
            return Err(OrganizerError::SigningWindowTooLong);
        }

        Ok(PetitionDraft {
            organizer: self.organizer_address,
            r_root,
            predicate_def,
            salt,
            class_set,
            class_thresholds,
            class_index,
            close_at_block,
            bounty,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        predicate::{
            Op,
            PredicateDef,
            Tuple,
        },
        types::{
            Comparator,
            OpCode,
            TypeTag,
        },
    };

    fn class_tag_operand(tag: ClassTag) -> Bytes32 {
        let mut b = [0u8; 32];
        b[30..].copy_from_slice(&tag.to_be_bytes());
        b
    }

    fn class_only_predicate(class_index: u8, class_tag: ClassTag) -> PredicateDef {
        PredicateDef {
            tuples: vec![Tuple {
                claim_index: class_index,
                operand: class_tag_operand(class_tag),
                type_tag: TypeTag::Int64,
                comparator: Comparator::Eq,
            }],
            ops: vec![Op {
                code: OpCode::PushTuple,
                operand: 0,
            }],
        }
    }

    #[test]
    fn test_build_petition_basic_success() {
        let org = Organizer::new([0xab; 20]);
        let draft = org
            .build_petition(
                [0x77; 32],
                class_only_predicate(2, 840),
                [0x99; 32],
                vec![840],
                vec![100],
                2,
                1000,
                2000,
                U256Be::from_u64(1_000_000),
            )
            .unwrap();
        assert_eq!(draft.class_set, vec![840]);
    }

    #[test]
    fn test_build_petition_rejects_empty_class_set() {
        let org = Organizer::new([0xab; 20]);
        let err = org.build_petition(
            [0x77; 32],
            class_only_predicate(2, 840),
            [0x99; 32],
            vec![],
            vec![],
            2,
            1000,
            2000,
            U256Be::from_u64(1_000_000),
        );
        assert!(matches!(err, Err(OrganizerError::ClassSetSize(0, _))));
    }

    #[test]
    fn test_build_petition_rejects_unsorted_class_set() {
        let org = Organizer::new([0xab; 20]);
        let err = org.build_petition(
            [0x77; 32],
            class_only_predicate(2, 840),
            [0x99; 32],
            vec![900, 840],
            vec![1, 1],
            2,
            1000,
            2000,
            U256Be::from_u64(1_000_000),
        );
        assert!(matches!(err, Err(OrganizerError::ClassSetNotSorted)));
    }

    #[test]
    fn test_build_petition_rejects_threshold_mismatch() {
        let org = Organizer::new([0xab; 20]);
        let err = org.build_petition(
            [0x77; 32],
            class_only_predicate(2, 840),
            [0x99; 32],
            vec![840, 900],
            vec![100],
            2,
            1000,
            2000,
            U256Be::from_u64(1_000_000),
        );
        assert!(matches!(
            err,
            Err(OrganizerError::ThresholdLenMismatch { .. })
        ));
    }

    #[test]
    fn test_build_petition_rejects_close_in_past() {
        let org = Organizer::new([0xab; 20]);
        let err = org.build_petition(
            [0x77; 32],
            class_only_predicate(2, 840),
            [0x99; 32],
            vec![840],
            vec![1],
            2,
            1000,
            999,
            U256Be::from_u64(1_000_000),
        );
        assert!(matches!(err, Err(OrganizerError::CloseInPast)));
    }

    #[test]
    fn test_build_petition_rejects_long_signing_window() {
        let org = Organizer::new([0xab; 20]);
        let err = org.build_petition(
            [0x77; 32],
            class_only_predicate(2, 840),
            [0x99; 32],
            vec![840],
            vec![1],
            2,
            1000,
            1000 + MAX_SIGNING_WINDOW_BLOCKS + 1,
            U256Be::from_u64(1_000_000),
        );
        assert!(matches!(err, Err(OrganizerError::SigningWindowTooLong)));
    }
}

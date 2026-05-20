//! Predicate grammar, encoding, evaluator, canonical hashing (SPEC Predicate).

use ark_bn254::Fr;
use serde::{
    Deserialize,
    Serialize,
};

use crate::{
    PREDICATE_BYTES_MAX,
    PREDICATE_OP_MAX,
    PREDICATE_TUPLE_MAX,
    error::PredicateError,
    poseidon::fr_from_be_bytes,
    types::{
        Bytes32,
        ClassTag,
        Comparator,
        OpCode,
        TypeTag,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tuple {
    pub claim_index: u8,
    pub operand: Bytes32,
    pub type_tag: TypeTag,
    pub comparator: Comparator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Op {
    pub code: OpCode,
    pub operand: u8,
}

/// In-memory predicate definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateDef {
    pub tuples: Vec<Tuple>,
    pub ops: Vec<Op>,
}

impl PredicateDef {
    pub fn op_count(&self) -> usize {
        self.ops.len()
    }
    pub fn tuple_count(&self) -> usize {
        self.tuples.len()
    }

    /// Structural validation; class binding via `validate_class_binding`.
    pub fn validate(&self) -> Result<(), PredicateError> {
        if !(1..=PREDICATE_TUPLE_MAX).contains(&self.tuples.len()) {
            return Err(PredicateError::TupleCountOutOfRange(self.tuples.len()));
        }
        if !(1..=PREDICATE_OP_MAX).contains(&self.ops.len()) {
            return Err(PredicateError::OpCountOutOfRange(self.ops.len()));
        }
        for op in &self.ops {
            if op.code == OpCode::PushTuple {
                if (op.operand as usize) >= self.tuples.len() {
                    return Err(PredicateError::OperandOutOfRange(
                        op.operand,
                        self.tuples.len() as u8,
                    ));
                }
            } else if op.operand != 0 {
                return Err(PredicateError::Malformed(format!(
                    "non-PUSH op {:?} has nonzero operand {}",
                    op.code, op.operand
                )));
            }
        }
        for (i, t) in self.tuples.iter().enumerate() {
            match (t.type_tag, t.comparator) {
                (TypeTag::Int64, _) => {
                    if !is_int64_in_range(&t.operand) {
                        return Err(PredicateError::Int64OperandOutOfRange);
                    }
                }
                (TypeTag::Hash, Comparator::Eq) => {}
                (TypeTag::Hash, _) => {
                    return Err(PredicateError::TypeMismatch(format!(
                        "tuple {i}: HASH supports `==` only"
                    )));
                }
                (TypeTag::Bool, Comparator::Eq) => {
                    if !is_bool_operand(&t.operand) {
                        return Err(PredicateError::TypeMismatch(format!(
                            "tuple {i}: BOOL operand must be 0 or 1"
                        )));
                    }
                }
                (TypeTag::Bool, _) => {
                    return Err(PredicateError::TypeMismatch(format!(
                        "tuple {i}: BOOL supports `==` only"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Serialized length: `1 + tuple_count * 35 + 1 + op_count * 2`.
    pub fn serialized_len(&self) -> usize {
        1 + self.tuples.len() * 35 + 1 + self.ops.len() * 2
    }

    /// Wire encoding per SPEC Predicate.
    pub fn encode(&self) -> Result<Vec<u8>, PredicateError> {
        self.validate()?;
        let len = self.serialized_len();
        if len > PREDICATE_BYTES_MAX {
            return Err(PredicateError::TooLarge);
        }
        let mut out = Vec::with_capacity(len);
        out.push(self.tuples.len() as u8);
        for t in &self.tuples {
            out.push(t.claim_index);
            out.extend_from_slice(&t.operand);
            out.push(t.type_tag as u8);
            out.push(t.comparator as u8);
        }
        out.push(self.ops.len() as u8);
        for o in &self.ops {
            out.push(o.code as u8);
            out.push(o.operand);
        }
        Ok(out)
    }

    /// Wire decoding per SPEC Predicate.
    pub fn decode(bytes: &[u8]) -> Result<Self, PredicateError> {
        if bytes.len() > PREDICATE_BYTES_MAX {
            return Err(PredicateError::TooLarge);
        }
        if bytes.len() < 2 {
            return Err(PredicateError::Malformed("buffer too short".into()));
        }
        let tuple_count = bytes[0] as usize;
        if tuple_count > PREDICATE_TUPLE_MAX {
            return Err(PredicateError::TupleCountOutOfRange(tuple_count));
        }
        let expected_tuple_bytes = tuple_count * 35;
        if bytes.len() < 1 + expected_tuple_bytes + 1 {
            return Err(PredicateError::Malformed("truncated tuples".into()));
        }
        let mut idx = 1usize;
        let mut tuples = Vec::with_capacity(tuple_count);
        for _ in 0..tuple_count {
            let claim_index = bytes[idx];
            idx += 1;
            let mut operand = [0u8; 32];
            operand.copy_from_slice(&bytes[idx..idx + 32]);
            idx += 32;
            let type_tag =
                TypeTag::try_from(bytes[idx]).map_err(PredicateError::BadTypeTag)?;
            idx += 1;
            let comparator = Comparator::try_from(bytes[idx])
                .map_err(PredicateError::BadComparator)?;
            idx += 1;
            tuples.push(Tuple {
                claim_index,
                operand,
                type_tag,
                comparator,
            });
        }
        let op_count = bytes[idx] as usize;
        idx += 1;
        let expected_op_bytes = op_count * 2;
        if bytes.len() < idx + expected_op_bytes {
            return Err(PredicateError::Malformed("truncated ops".into()));
        }
        let mut ops = Vec::with_capacity(op_count);
        for _ in 0..op_count {
            let code = OpCode::try_from(bytes[idx]).map_err(PredicateError::BadOpcode)?;
            idx += 1;
            let operand = bytes[idx];
            idx += 1;
            ops.push(Op { code, operand });
        }
        let def = Self { tuples, ops };
        def.validate()?;
        Ok(def)
    }

    /// Evaluate the predicate over `attr_vector`.
    pub fn evaluate(&self, attr_vector: &[Fr]) -> Result<bool, PredicateError> {
        self.validate()?;
        let mut stack: Vec<bool> = Vec::with_capacity(self.ops.len());
        for (i, op) in self.ops.iter().enumerate() {
            let pop_two =
                |stack: &mut Vec<bool>| -> Result<(bool, bool), PredicateError> {
                    let b = stack.pop().ok_or(PredicateError::StackUnderflow(i))?;
                    let a = stack.pop().ok_or(PredicateError::StackUnderflow(i))?;
                    Ok((a, b))
                };
            match op.code {
                OpCode::PushTuple => {
                    let t = &self.tuples[op.operand as usize];
                    stack.push(eval_tuple(t, attr_vector)?);
                }
                OpCode::And => {
                    let (a, b) = pop_two(&mut stack)?;
                    stack.push(a && b);
                }
                OpCode::Or => {
                    let (a, b) = pop_two(&mut stack)?;
                    stack.push(a || b);
                }
                OpCode::Not => {
                    let a = stack.pop().ok_or(PredicateError::StackUnderflow(i))?;
                    stack.push(!a);
                }
                OpCode::Nop => {}
            }
        }
        if stack.len() != 1 {
            return Err(PredicateError::NonSingletonResult(stack.len()));
        }
        Ok(stack[0])
    }

    /// Strict variant: predicate binds `class_index` to the specific `class_tag`
    /// at top level outside any OR.
    pub fn validate_class_binding(
        &self,
        class_index: u8,
        class_tag: ClassTag,
    ) -> Result<(), PredicateError> {
        let mut class_tag_be = [0u8; 32];
        class_tag_be[30..].copy_from_slice(&class_tag.to_be_bytes());
        let binding_tuple_indices: Vec<usize> = self
            .tuples
            .iter()
            .enumerate()
            .filter_map(|(i, t)| {
                (t.claim_index == class_index
                    && t.comparator == Comparator::Eq
                    && t.operand == class_tag_be)
                    .then_some(i)
            })
            .collect();
        if binding_tuple_indices.is_empty() {
            return Err(PredicateError::MissingClassBinding);
        }
        match evaluate_class_binding_taint(&self.ops, &binding_tuple_indices)? {
            Tag::Bound => Ok(()),
            _ => Err(PredicateError::MissingClassBinding),
        }
    }

    /// Loose variant: returns one of the class-binding tuple's `class_tag` operands.
    /// Mirrors `PetitionRegistry._validateClassBinding`: every tuple matching
    /// `(claim_index, EQ, high-30-zero)` is treated as Bound, so multi-class
    /// predicates like `attr[i] == A OR attr[i] == B` succeed.
    pub fn find_class_binding_operand(
        &self,
        class_index: u8,
    ) -> Result<ClassTag, PredicateError> {
        let mut binding_tuple_indices = Vec::new();
        let mut binding_operands = Vec::new();
        for (i, t) in self.tuples.iter().enumerate() {
            if t.claim_index == class_index
                && t.comparator == Comparator::Eq
                && t.operand[..30].iter().all(|&b| b == 0)
            {
                binding_tuple_indices.push(i);
                binding_operands.push(u16::from_be_bytes([t.operand[30], t.operand[31]]));
            }
        }
        if binding_tuple_indices.is_empty() {
            return Err(PredicateError::MissingClassBinding);
        }
        match evaluate_class_binding_taint(&self.ops, &binding_tuple_indices)? {
            Tag::Bound => Ok(binding_operands[0]),
            _ => Err(PredicateError::MissingClassBinding),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tag {
    Bound,
    Free,
    Tainted,
}

/// Shared taint-analysis for `validate_class_binding` and `find_class_binding_operand`.
/// `OR(Bound, Free) -> Tainted` (mirroring the Solidity rule), `OR(Bound, Bound) -> Bound`.
fn evaluate_class_binding_taint(
    ops: &[Op],
    binding_tuple_indices: &[usize],
) -> Result<Tag, PredicateError> {
    let mut stack: Vec<Tag> = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        match op.code {
            OpCode::PushTuple => {
                if binding_tuple_indices.contains(&(op.operand as usize)) {
                    stack.push(Tag::Bound);
                } else {
                    stack.push(Tag::Free);
                }
            }
            OpCode::And => {
                let (b, a) = pop_two(&mut stack, i)?;
                stack.push(match (a, b) {
                    (Tag::Bound, _) | (_, Tag::Bound) => Tag::Bound,
                    (Tag::Tainted, _) | (_, Tag::Tainted) => Tag::Tainted,
                    _ => Tag::Free,
                });
            }
            OpCode::Or => {
                let (b, a) = pop_two(&mut stack, i)?;
                stack.push(if a == Tag::Bound && b == Tag::Bound {
                    Tag::Bound
                } else if a == Tag::Bound
                    || b == Tag::Bound
                    || a == Tag::Tainted
                    || b == Tag::Tainted
                {
                    Tag::Tainted
                } else {
                    Tag::Free
                });
            }
            OpCode::Not => {
                let a = stack.pop().ok_or(PredicateError::StackUnderflow(i))?;
                stack.push(match a {
                    Tag::Bound => Tag::Tainted,
                    other => other,
                });
            }
            OpCode::Nop => {}
        }
    }
    if stack.len() != 1 {
        return Err(PredicateError::NonSingletonResult(stack.len()));
    }
    Ok(stack[0])
}

fn pop_two(stack: &mut Vec<Tag>, op_idx: usize) -> Result<(Tag, Tag), PredicateError> {
    let b = stack.pop().ok_or(PredicateError::StackUnderflow(op_idx))?;
    let a = stack.pop().ok_or(PredicateError::StackUnderflow(op_idx))?;
    Ok((b, a))
}

fn is_int64_in_range(bytes: &Bytes32) -> bool {
    bytes[..24].iter().all(|&b| b == 0)
}

fn is_bool_operand(bytes: &Bytes32) -> bool {
    bytes[..31].iter().all(|&b| b == 0) && bytes[31] <= 1
}

fn eval_tuple(t: &Tuple, attr_vector: &[Fr]) -> Result<bool, PredicateError> {
    if (t.claim_index as usize) >= attr_vector.len() {
        return Err(PredicateError::Malformed(format!(
            "claim_index {} out of range (attr_count {})",
            t.claim_index,
            attr_vector.len()
        )));
    }
    let attr_fr = attr_vector[t.claim_index as usize];
    let operand_fr = fr_from_be_bytes(&t.operand);

    match (t.type_tag, t.comparator) {
        (TypeTag::Bool, Comparator::Eq) | (TypeTag::Hash, Comparator::Eq) => {
            Ok(attr_fr == operand_fr)
        }
        (TypeTag::Int64, Comparator::Eq) => Ok(attr_fr == operand_fr),
        (TypeTag::Int64, Comparator::Le) => {
            let attr_u = fr_to_u64_low(&attr_fr);
            let op_u = u64::from_be_bytes(t.operand[24..32].try_into().unwrap());
            Ok(attr_u <= op_u)
        }
        (TypeTag::Int64, Comparator::Ge) => {
            let attr_u = fr_to_u64_low(&attr_fr);
            let op_u = u64::from_be_bytes(t.operand[24..32].try_into().unwrap());
            Ok(attr_u >= op_u)
        }
        _ => Err(PredicateError::TypeMismatch(format!(
            "tuple type {:?} comparator {:?} not allowed",
            t.type_tag, t.comparator
        ))),
    }
}

fn fr_to_u64_low(fr: &Fr) -> u64 {
    let be = crate::poseidon::fr_to_be_bytes(fr);
    u64::from_be_bytes(be[24..32].try_into().unwrap())
}

/// Canonical scalar decomposition: 34 BN254 scalars (SPEC Predicate).
/// First segment holds a u16-BE length marker then up to 29 content bytes;
/// remaining 33 segments hold up to 31 content bytes each (1052 total capacity).
pub fn canonical_scalars(encoded: &[u8]) -> Result<Vec<Fr>, PredicateError> {
    const SEGMENTS: usize = 34;
    const FIRST_CONTENT_BYTES: usize = 29;
    const LATER_CONTENT_BYTES: usize = 31;
    const CAPACITY_BYTES: usize =
        FIRST_CONTENT_BYTES + (SEGMENTS - 1) * LATER_CONTENT_BYTES;
    const _: () = assert!(PREDICATE_BYTES_MAX <= CAPACITY_BYTES);

    if encoded.len() > PREDICATE_BYTES_MAX {
        return Err(PredicateError::TooLarge);
    }
    let mut scalars: Vec<Fr> = Vec::with_capacity(SEGMENTS);
    let mut cursor = 0usize;
    for seg in 0..SEGMENTS {
        let mut buf = [0u8; 32];
        let (content_off, content_max) = if seg == 0 {
            buf[1] = ((encoded.len() >> 8) & 0xff) as u8;
            buf[2] = (encoded.len() & 0xff) as u8;
            (3, FIRST_CONTENT_BYTES)
        } else {
            (1, LATER_CONTENT_BYTES)
        };
        let n = content_max.min(encoded.len().saturating_sub(cursor));
        buf[content_off..content_off + n].copy_from_slice(&encoded[cursor..cursor + n]);
        cursor += n;
        scalars.push(fr_from_be_bytes(&buf));
    }
    Ok(scalars)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class_tag_operand(tag: ClassTag) -> Bytes32 {
        let mut b = [0u8; 32];
        b[30..].copy_from_slice(&tag.to_be_bytes());
        b
    }

    fn int64_operand(v: u64) -> Bytes32 {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&v.to_be_bytes());
        b
    }

    fn bool_operand(v: bool) -> Bytes32 {
        let mut b = [0u8; 32];
        b[31] = if v { 1 } else { 0 };
        b
    }

    fn simple_class_only_predicate(class_index: u8, class_tag: ClassTag) -> PredicateDef {
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
    fn test_simple_class_only_validates_and_evaluates() {
        let p = simple_class_only_predicate(2, 840);
        p.validate().unwrap();
        p.validate_class_binding(2, 840).unwrap();
        let attrs = vec![
            Fr::from(1u64),
            Fr::from(0u64),
            Fr::from(840u64),
            Fr::from(0u64),
        ];
        assert!(p.evaluate(&attrs).unwrap());
    }

    #[test]
    fn test_class_binding_with_extra_and_clause() {
        let p = PredicateDef {
            tuples: vec![
                Tuple {
                    claim_index: 0,
                    operand: int64_operand(65),
                    type_tag: TypeTag::Int64,
                    comparator: Comparator::Le,
                },
                Tuple {
                    claim_index: 2,
                    operand: class_tag_operand(840),
                    type_tag: TypeTag::Int64,
                    comparator: Comparator::Eq,
                },
            ],
            ops: vec![
                Op {
                    code: OpCode::PushTuple,
                    operand: 0,
                },
                Op {
                    code: OpCode::PushTuple,
                    operand: 1,
                },
                Op {
                    code: OpCode::And,
                    operand: 0,
                },
            ],
        };
        p.validate().unwrap();
        p.validate_class_binding(2, 840).unwrap();
        let attrs = vec![
            Fr::from(30u64),
            Fr::from(0u64),
            Fr::from(840u64),
            Fr::from(0u64),
        ];
        assert!(p.evaluate(&attrs).unwrap());
        let attrs_fail = vec![
            Fr::from(99u64),
            Fr::from(0u64),
            Fr::from(840u64),
            Fr::from(0u64),
        ];
        assert!(!p.evaluate(&attrs_fail).unwrap());
    }

    #[test]
    fn test_class_binding_inside_or_rejected() {
        let p = PredicateDef {
            tuples: vec![
                Tuple {
                    claim_index: 0,
                    operand: int64_operand(65),
                    type_tag: TypeTag::Int64,
                    comparator: Comparator::Le,
                },
                Tuple {
                    claim_index: 2,
                    operand: class_tag_operand(840),
                    type_tag: TypeTag::Int64,
                    comparator: Comparator::Eq,
                },
            ],
            ops: vec![
                Op {
                    code: OpCode::PushTuple,
                    operand: 0,
                },
                Op {
                    code: OpCode::PushTuple,
                    operand: 1,
                },
                Op {
                    code: OpCode::Or,
                    operand: 0,
                },
            ],
        };
        let err = p.validate_class_binding(2, 840);
        assert!(matches!(err, Err(PredicateError::MissingClassBinding)));
    }

    #[test]
    fn test_validate_rejects_too_many_tuples() {
        let tuples = (0..21)
            .map(|_| Tuple {
                claim_index: 0,
                operand: bool_operand(true),
                type_tag: TypeTag::Bool,
                comparator: Comparator::Eq,
            })
            .collect::<Vec<_>>();
        let ops = vec![Op {
            code: OpCode::PushTuple,
            operand: 0,
        }];
        let p = PredicateDef { tuples, ops };
        let err = p.validate();
        assert!(matches!(err, Err(PredicateError::TupleCountOutOfRange(_))));
    }

    #[test]
    fn test_validate_rejects_push_operand_out_of_range() {
        let p = PredicateDef {
            tuples: vec![Tuple {
                claim_index: 0,
                operand: bool_operand(true),
                type_tag: TypeTag::Bool,
                comparator: Comparator::Eq,
            }],
            ops: vec![Op {
                code: OpCode::PushTuple,
                operand: 5,
            }],
        };
        let err = p.validate();
        assert!(matches!(err, Err(PredicateError::OperandOutOfRange(5, 1))));
    }

    #[test]
    fn test_encode_decode_roundtrip() {
        let p = simple_class_only_predicate(2, 840);
        let encoded = p.encode().unwrap();
        assert_eq!(encoded.len(), p.serialized_len());
        let restored = PredicateDef::decode(&encoded).unwrap();
        assert_eq!(restored, p);
    }

    #[test]
    fn test_decode_rejects_truncated_buffer() {
        let p = simple_class_only_predicate(2, 840);
        let encoded = p.encode().unwrap();
        let trunc = &encoded[..encoded.len() - 1];
        let err = PredicateDef::decode(trunc);
        assert!(matches!(err, Err(PredicateError::Malformed(_))));
    }

    #[test]
    fn test_canonical_scalars_returns_34_segments() {
        let p = simple_class_only_predicate(2, 840);
        let encoded = p.encode().unwrap();
        let scalars = canonical_scalars(&encoded).unwrap();
        assert_eq!(scalars.len(), 34);
    }

    #[test]
    fn test_canonical_scalars_changes_with_inputs() {
        let p1 = simple_class_only_predicate(2, 840);
        let p2 = simple_class_only_predicate(2, 250);
        let e1 = p1.encode().unwrap();
        let e2 = p2.encode().unwrap();
        let s1 = canonical_scalars(&e1).unwrap();
        let s2 = canonical_scalars(&e2).unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_int64_operand_out_of_range_rejected() {
        let bad_operand = {
            let mut b = [0u8; 32];
            b[10] = 1;
            b
        };
        let p = PredicateDef {
            tuples: vec![Tuple {
                claim_index: 0,
                operand: bad_operand,
                type_tag: TypeTag::Int64,
                comparator: Comparator::Eq,
            }],
            ops: vec![Op {
                code: OpCode::PushTuple,
                operand: 0,
            }],
        };
        let err = p.validate();
        assert!(matches!(err, Err(PredicateError::Int64OperandOutOfRange)));
    }

    #[test]
    fn test_hash_only_equality() {
        let p = PredicateDef {
            tuples: vec![Tuple {
                claim_index: 0,
                operand: [0xaa; 32],
                type_tag: TypeTag::Hash,
                comparator: Comparator::Le,
            }],
            ops: vec![Op {
                code: OpCode::PushTuple,
                operand: 0,
            }],
        };
        let err = p.validate();
        assert!(matches!(err, Err(PredicateError::TypeMismatch(_))));
    }

    #[test]
    fn test_bool_only_eq_and_0_or_1() {
        let p_bad = PredicateDef {
            tuples: vec![Tuple {
                claim_index: 0,
                operand: int64_operand(2),
                type_tag: TypeTag::Bool,
                comparator: Comparator::Eq,
            }],
            ops: vec![Op {
                code: OpCode::PushTuple,
                operand: 0,
            }],
        };
        let err = p_bad.validate();
        assert!(matches!(err, Err(PredicateError::TypeMismatch(_))));
    }

    #[test]
    fn test_not_op_evaluates() {
        let p = PredicateDef {
            tuples: vec![
                Tuple {
                    claim_index: 0,
                    operand: bool_operand(true),
                    type_tag: TypeTag::Bool,
                    comparator: Comparator::Eq,
                },
                Tuple {
                    claim_index: 1,
                    operand: class_tag_operand(840),
                    type_tag: TypeTag::Int64,
                    comparator: Comparator::Eq,
                },
            ],
            ops: vec![
                Op {
                    code: OpCode::PushTuple,
                    operand: 0,
                },
                Op {
                    code: OpCode::Not,
                    operand: 0,
                },
                Op {
                    code: OpCode::PushTuple,
                    operand: 1,
                },
                Op {
                    code: OpCode::And,
                    operand: 0,
                },
            ],
        };
        p.validate().unwrap();
        p.validate_class_binding(1, 840).unwrap();
    }
}

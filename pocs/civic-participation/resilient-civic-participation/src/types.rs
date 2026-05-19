//! Domain types shared across actors (SPEC byte and field-element layer).

use ark_bn254::Fr;
use serde::{
    Deserialize,
    Serialize,
};

pub type Address = [u8; 20];
pub type Bytes32 = [u8; 32];
pub type FieldBytes = Bytes32;
pub type PetitionId = Bytes32;

/// 256-bit unsigned integer, big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct U256Be(pub Bytes32);

impl U256Be {
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }
    pub fn from_u128(v: u128) -> Self {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        Self(out)
    }
    pub fn from_u64(v: u64) -> Self {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&v.to_be_bytes());
        Self(out)
    }
    pub fn as_bytes(&self) -> &Bytes32 {
        &self.0
    }
    pub fn into_bytes(self) -> Bytes32 {
        self.0
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for i in (0..32).rev() {
            let s = self.0[i] as u16 + rhs.0[i] as u16 + carry;
            out[i] = (s & 0xff) as u8;
            carry = s >> 8;
        }
        if carry == 0 { Some(Self(out)) } else { None }
    }
}

/// Class tag (uint16) partitioning signatures into classes.
pub type ClassTag = u16;

/// SPEC Lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PetitionState {
    Registered,
    SigningOpen,
    SigningClosed,
    Cooldown,
    DisputeWindow,
    Resolved,
    Unresolved,
}

/// SPEC Batch Record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BatchState {
    Active,
    Repudiated,
}

/// SPEC Predicate: per-attribute type tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum TypeTag {
    Int64 = 0x01,
    Hash = 0x02,
    Bool = 0x03,
}

impl TryFrom<u8> for TypeTag {
    type Error = u8;
    fn try_from(b: u8) -> Result<Self, u8> {
        match b {
            0x01 => Ok(Self::Int64),
            0x02 => Ok(Self::Hash),
            0x03 => Ok(Self::Bool),
            other => Err(other),
        }
    }
}

/// SPEC Predicate: comparator byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Comparator {
    Eq = 0x10,
    Le = 0x11,
    Ge = 0x12,
}

impl TryFrom<u8> for Comparator {
    type Error = u8;
    fn try_from(b: u8) -> Result<Self, u8> {
        match b {
            0x10 => Ok(Self::Eq),
            0x11 => Ok(Self::Le),
            0x12 => Ok(Self::Ge),
            other => Err(other),
        }
    }
}

/// SPEC Predicate: postfix op code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum OpCode {
    PushTuple = 0x20,
    And = 0x21,
    Or = 0x22,
    Not = 0x23,
    Nop = 0xff,
}

impl TryFrom<u8> for OpCode {
    type Error = u8;
    fn try_from(b: u8) -> Result<Self, u8> {
        match b {
            0x20 => Ok(Self::PushTuple),
            0x21 => Ok(Self::And),
            0x22 => Ok(Self::Or),
            0x23 => Ok(Self::Not),
            0xff => Ok(Self::Nop),
            other => Err(other),
        }
    }
}

/// SPEC Petition Record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PetitionRecord {
    pub petition_id: PetitionId,
    pub slot: u32,
    pub r_root: Bytes32,
    pub predicate_def: Vec<u8>,
    pub predicate_hash: Bytes32,
    pub salt: Bytes32,
    pub class_set: Vec<ClassTag>,
    pub class_thresholds: Vec<u64>,
    pub class_index: u8,
    pub close_at_block: u64,
    pub bounty: U256Be,
    pub alpha_at_registration: u64,
    pub organizer: Address,
    pub running_root: Bytes32,
    pub identity_tag_set_root: Bytes32,
    pub leaf_count: u64,
    pub next_batch_index: u32,
    pub resolution_proof: Vec<u8>,
    pub b: bool,
    pub b_per_class: Vec<bool>,
    pub state: PetitionState,
    pub registration_block: u64,
}

/// SPEC Batch Record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRecord {
    pub petition_id: PetitionId,
    pub batch_index: u32,
    pub batch_versioned_hash: Bytes32,
    pub new_running_root: Bytes32,
    pub new_identity_tag_set_root: Bytes32,
    pub prior_running_root: Bytes32,
    pub prior_identity_tag_set_root: Bytes32,
    pub prior_leaf_count: u64,
    pub new_leaf_count: u64,
    pub relayer: Address,
    pub submitted_at_block: u64,
    pub state: BatchState,
}

/// SPEC Global Registry State.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalState {
    pub s: u32,
    pub alpha: u64,
    pub alpha_min: u64,
    pub alpha_max: u64,
    pub srs_hash: Bytes32,
    pub chain_id: u64,
    pub n: u8,
}

/// SPEC Blob Payload, decoded form (4 BLS12-381 field elements per record).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEntry {
    pub nullifier: Bytes32,
    pub identity_tag: Bytes32,
    pub class_tag: ClassTag,
}

/// Signer SNARK public inputs, ordered per SPEC Signer SNARK.
#[derive(Debug, Clone)]
pub struct SignerPublicInputs {
    pub r_root: Fr,
    pub petition_id: Fr,
    pub predicate_hash: Fr,
    pub class_index: Fr,
    pub class_tag: Fr,
    pub slot: Fr,
    pub nullifier: Fr,
    pub identity_tag: Fr,
}

/// Signer SNARK private inputs (witness).
#[derive(Debug, Clone)]
pub struct SignerPrivateInputs {
    /// Per-signer secret, CSPRNG-sampled at enrollment. Mixed into
    /// `attr_hash` (pinning the RI leaf) and into `nullifier` (binding
    /// per-petition signatures). Without this, an attacker who learned
    /// `s_0` alone could enroll under the same RI leaf as the victim.
    pub identity_secret: Fr,
    pub attr_vector: Vec<Fr>,
    pub attr_version: u32,
    pub chain_root: Fr,
    pub ri_path_siblings: Vec<Fr>,
    pub ri_path_indices: Vec<u8>,
    pub s_slot: Fr,
    pub chain_path_siblings: Vec<Fr>,
    pub chain_path_indices: Vec<u8>,
    pub salt: Fr,
    /// Structured predicate def for the signer circuit's postfix evaluator.
    pub predicate_def: crate::predicate::PredicateDef,
}

/// Bundled signer SNARK plus the public tuple needed to enter a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerSubmission {
    pub petition_id: PetitionId,
    pub r_root: Bytes32,
    pub predicate_hash: Bytes32,
    pub class_index: u8,
    pub slot: u32,
    pub nullifier: Bytes32,
    pub identity_tag: Bytes32,
    pub class_tag: ClassTag,
    pub proof_bytes: Vec<u8>,
}

/// Batch SNARK public inputs (SPEC section Batch SNARK).
#[derive(Debug, Clone)]
pub struct BatchPublicInputs {
    pub petition_id: Fr,
    pub r_root: Fr,
    pub predicate_hash: Fr,
    pub class_index: Fr,
    pub slot: Fr,
    pub batch_size: Fr,
    pub prior_running_root: Fr,
    pub new_running_root: Fr,
    pub prior_identity_tag_set_root: Fr,
    pub new_identity_tag_set_root: Fr,
    pub prior_leaf_count: Fr,
    pub new_leaf_count: Fr,
    pub batch_versioned_hash: Fr,
    /// Cross-field decompositions of the batch records per SPEC
    /// constraint 8. Length = `BATCH_SIZE_MAX * FE_PER_RECORD` = 24.
    /// `bls_fields[4*i + j]` is the `j`-th BLS12-381 field element of
    /// record `i` per SPEC section Blob Payload. The contract verifies
    /// each value via a KZG point-evaluation against `batch_versioned_hash`.
    pub bls_fields: Vec<Fr>,
    /// Deploy-pinned hash of the signer SNARK's verification key.
    /// Without this binding, a malicious relayer could supply their own
    /// signer VK and prove arbitrary leaves.
    pub signer_vk_hash: Fr,
}

/// Resolution SNARK public inputs (SPEC section Resolution SNARK).
#[derive(Debug, Clone)]
pub struct ResolutionPublicInputs {
    pub predicate_hash: Fr,
    pub r_root: Fr,
    pub running_root: Fr,
    pub leaf_count: Fr,
    pub class_set: Vec<Fr>,
    pub class_thresholds: Vec<Fr>,
    pub b: Fr,
    pub b_per_class: Vec<Fr>,
    /// Petition's class_index. Binds the resolution proof to the
    /// specific attribute slot the petition was registered with.
    pub class_index: Fr,
}

/// Per-leaf IMT membership witness in circuit form.
///
/// `next_index` and `next_value` are the linked-list pointers of the
/// IMT leaf at the time the witness is captured. The resolution
/// circuit recomputes `imt_leaf = hash_imt_leaf(value, next_index,
/// next_value)` and verifies the path against `running_root`, so
/// these must reflect the *final* IMT state (post-all-inserts), not
/// the state at the time the leaf was first inserted.
#[derive(Debug, Clone)]
pub struct ImtMembershipFr {
    pub leaf_hash: Fr,
    pub leaf_index: u32,
    pub next_index: u32,
    pub next_value: Fr,
    pub siblings: Vec<Fr>,
    pub indices: Vec<u8>,
}

/// Resolution SNARK private inputs (witness).
#[derive(Debug, Clone)]
pub struct ResolutionPrivateInputs {
    pub leaves: Vec<Fr>,
    pub imt_membership_paths: Vec<ImtMembershipFr>,
    pub witness_pairs: Vec<(Fr, Fr)>,
}

/// Bundled batch SNARK plus the state it claims.
#[derive(Debug, Clone)]
pub struct BatchSubmission {
    pub public_inputs: BatchPublicInputs,
    pub records: Vec<RecordEntry>,
    pub proof_bytes: Vec<u8>,
}

/// Bundled resolution SNARK plus its public inputs.
#[derive(Debug, Clone)]
pub struct ResolutionSubmission {
    pub public_inputs: ResolutionPublicInputs,
    pub proof_bytes: Vec<u8>,
}

/// SPEC Dispute: violation type byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum ViolationType {
    ClassTagOutOfSet = 0x01,
    IntraBatchDuplicateIdentityTag = 0x02,
    LeafOrderingViolation = 0x03,
}

impl TryFrom<u8> for ViolationType {
    type Error = u8;
    fn try_from(b: u8) -> Result<Self, u8> {
        match b {
            0x01 => Ok(Self::ClassTagOutOfSet),
            0x02 => Ok(Self::IntraBatchDuplicateIdentityTag),
            0x03 => Ok(Self::LeafOrderingViolation),
            other => Err(other),
        }
    }
}

/// KZG point-evaluation opening against `batch_versioned_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KzgOpening {
    pub field_element_index: u32,
    pub claimed_value: Bytes32,
    pub proof_bytes: Vec<u8>,
}

/// SPEC Dispute envelope; record content is derived from `openings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dispute {
    pub petition_id: PetitionId,
    pub batch_index: u32,
    pub violation_type: ViolationType,
    pub position_i: u32,
    pub position_j: Option<u32>,
    pub openings: Vec<KzgOpening>,
}

/// SPEC Off-Chain Signer State (840 bytes, journaled per advance).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerStateBytes {
    pub s_curr: Bytes32,
    pub t: u32,
    pub caterpillar: [Bytes32; crate::FSRT_DEPTH],
    pub chain_root: Bytes32,
    pub attr_version: u32,
}

/// Per-signer credential metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerCredentials {
    /// CSPRNG-sampled at enrollment; mixed into `attr_hash` and
    /// `nullifier` (see hash_attr / hash_nullifier).
    pub identity_secret: Bytes32,
    pub attr_vector: Vec<Bytes32>,
    pub ri_leaf_index: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u256_be_addition() {
        let a = U256Be::from_u64(100);
        let b = U256Be::from_u64(50);
        let c = a.checked_add(b).unwrap();
        assert_eq!(c, U256Be::from_u64(150));
    }

    #[test]
    fn test_u256_be_overflow_returns_none() {
        let max = U256Be([0xff; 32]);
        let one = U256Be::from_u64(1);
        assert!(max.checked_add(one).is_none());
    }

    #[test]
    fn test_u256_be_is_zero() {
        assert!(U256Be::zero().is_zero());
        assert!(!U256Be::from_u64(1).is_zero());
    }

    #[test]
    fn test_type_tag_roundtrip() {
        for t in [TypeTag::Int64, TypeTag::Hash, TypeTag::Bool] {
            assert_eq!(TypeTag::try_from(t as u8), Ok(t));
        }
        assert!(TypeTag::try_from(0x09).is_err());
    }

    #[test]
    fn test_comparator_roundtrip() {
        for t in [Comparator::Eq, Comparator::Le, Comparator::Ge] {
            assert_eq!(Comparator::try_from(t as u8), Ok(t));
        }
        assert!(Comparator::try_from(0xee).is_err());
    }

    #[test]
    fn test_opcode_roundtrip() {
        for op in [
            OpCode::PushTuple,
            OpCode::And,
            OpCode::Or,
            OpCode::Not,
            OpCode::Nop,
        ] {
            assert_eq!(OpCode::try_from(op as u8), Ok(op));
        }
        assert!(OpCode::try_from(0x99).is_err());
    }

    #[test]
    fn test_violation_type_roundtrip() {
        for v in [
            ViolationType::ClassTagOutOfSet,
            ViolationType::IntraBatchDuplicateIdentityTag,
            ViolationType::LeafOrderingViolation,
        ] {
            assert_eq!(ViolationType::try_from(v as u8), Ok(v));
        }
        assert!(ViolationType::try_from(0x99).is_err());
    }

    #[test]
    fn test_signer_state_default_is_zeroed() {
        let s = SignerStateBytes::default();
        assert_eq!(s.t, 0);
        assert_eq!(s.s_curr, [0u8; 32]);
        for level in &s.caterpillar {
            assert_eq!(level, &[0u8; 32]);
        }
    }
}

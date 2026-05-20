//! Resilient Civic Participation: Rust crate. See `SPEC.md`.

pub mod adapters;
pub mod blob;
pub mod clock;
pub mod disputant;
pub mod error;
pub mod fsrt;
pub mod imt;
pub mod organizer;
pub mod ports;
pub mod poseidon;
pub mod predicate;
pub mod registry;
pub mod relayer;
pub mod resolver;
pub mod signer;
pub mod types;

// Domain separator strings; scalar form lives in `poseidon::domain`.
pub const DOMAIN_NULLIFIER: &[u8] = b"RCP/nullifier/v1";
pub const DOMAIN_IDTAG: &[u8] = b"RCP/identity_tag/v1";
pub const DOMAIN_LEAF: &[u8] = b"RCP/leaf/v1";
pub const DOMAIN_FSRT_PRG: &[u8] = b"RCP/fsrt_prg/v1";
pub const DOMAIN_PRED: &[u8] = b"RCP/predicate/v1";
pub const DOMAIN_ATTR: &[u8] = b"RCP/attr_hash/v1";
pub const DOMAIN_BATCH_SNARK: &[u8] = b"RCP/batch_snark/v1";
pub const DOMAIN_PETITION: &[u8] = b"RCP/petition_id/v1";
pub const DOMAIN_RESOLUTION_SNARK: &[u8] = b"RCP/resolution_snark/v1";

pub const FSRT_DEPTH: usize = 24;
pub const FSRT_SLOT_COUNT: u32 = 1u32 << FSRT_DEPTH as u32;
/// PoC batch cap. SPEC permits up to 100; the recursive batch SNARK's
/// circuit size scales linearly in this value, so the PoC caps it at 6.
/// Must match `BATCH_SIZE_MAX` in `circuits/lib/src/lib.nr`.
pub const BATCH_SIZE_MAX: usize = 6;
pub const RECORDS_PER_BLOB: usize = 1000;
pub const ATTR_COUNT: usize = 4;
pub const PREDICATE_OP_MAX: usize = 20;
pub const PREDICATE_TUPLE_MAX: usize = 20;
pub const PREDICATE_BYTES_MAX: usize = 1024;
pub const RECORD_LEN: usize = 96;

pub const BLOCKS_PER_DAY: u64 = 24 * 60 * 60 / 12;
pub const MAX_SIGNING_WINDOW_BLOCKS: u64 = 11 * BLOCKS_PER_DAY + BLOCKS_PER_DAY / 2;
pub const COOLDOWN_BLOCKS: u64 = 2 * 60 * 60 / 12;
pub const RESOLUTION_DEADLINE_BLOCKS: u64 = 14 * BLOCKS_PER_DAY;
pub const MIN_R_AGE_BLOCKS: u64 = 30 * BLOCKS_PER_DAY;
pub const IMT_DEPTH: usize = 24;
pub const RESOLUTION_CLASS_MAX: usize = 16;
/// Maximum cardinality of an Organizer's `class_set`. The Solidity registry
/// stores this as a `uint16[]`; this cap mirrors the off-chain organizer check.
pub const MAX_CLASS_SET_LEN: usize = 32;

// Const-coupling assertions: these constants are hardcoded in Noir
// circuit literals (e.g., `[bool; 24]`, `[Field; 4]`, `CLASS_MAX = 16`)
// and in Solidity (`RESOLUTION_CLASS_MAX`, `BATCH_SIZE_MAX`). Any change
// requires regenerating verifiers via `scripts/generate-verifiers.sh`
// and updating the Noir + Solidity literals. The arrays below force
// a compile error if a value drifts.
const _IMT_DEPTH_COUPLING: [(); 24] = [(); IMT_DEPTH];
const _FSRT_DEPTH_COUPLING: [(); 24] = [(); FSRT_DEPTH];
const _ATTR_COUNT_COUPLING: [(); 4] = [(); ATTR_COUNT];
const _BATCH_SIZE_MAX_COUPLING: [(); 6] = [(); BATCH_SIZE_MAX];
const _CLASS_MAX_COUPLING: [(); 16] = [(); RESOLUTION_CLASS_MAX];

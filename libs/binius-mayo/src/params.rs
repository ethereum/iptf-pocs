//! MAYO-2 parameters and constants.
//!
//! Reference: MAYO-C `include/mayo.h` (MAYO_2_*) and the MAYO spec.

/// Total number of variables in the MQ system.
pub(crate) const N: usize = 81;

/// Number of equations / output dimension of the public map.
pub(crate) const M: usize = 64;

/// "Oil" dimension.
pub(crate) const O: usize = 17;

/// "Vinegar" dimension = N - O.
pub(crate) const V: usize = N - O; // 64

/// Whipping factor = number of signature blocks.
pub(crate) const K: usize = 4;

pub(crate) const SALT_BYTES: usize = 24;
pub(crate) const PK_SEED_BYTES: usize = 16;

/// Packed signature scalar block: K*N nibbles = 162 bytes for MAYO-2.
pub(crate) const S_BYTES: usize = (K * N) / 2;

/// MAYO-2 signature size in bytes: (k*n)/2 + salt = 162 + 24 = 186.
pub(crate) const SIG_BYTES: usize = S_BYTES + SALT_BYTES;

/// MAYO-2 compact public key size in bytes: 16 + P3_BYTES = 4912.
pub(crate) const CPK_BYTES: usize = PK_SEED_BYTES + P3_BYTES;

// Each P^(*)[i,j] entry is an m-vector of GF(16) (length M = 64 nibbles = 32 bytes).
// MAYO-C represents an m-vector as 4 packed u64 limbs ("m-vec limbs"); 16 nibbles per u64.

/// Number of bytes per packed m-vector (32 = M/2).
pub(crate) const M_VEC_BYTES: usize = M / 2;

/// P^(1) is upper-triangular over [V] x [V]. Number of entries.
pub(crate) const P1_ENTRIES: usize = V * (V + 1) / 2; // 2080

/// P^(2) is rectangular over [V] x [O]. Number of entries.
pub(crate) const P2_ENTRIES: usize = V * O; // 1088

/// P^(3) is upper-triangular over [O] x [O]. Number of entries.
pub(crate) const P3_ENTRIES: usize = O * (O + 1) / 2; // 153

pub(crate) const P1_BYTES: usize = P1_ENTRIES * M_VEC_BYTES; // 66_560
pub(crate) const P2_BYTES: usize = P2_ENTRIES * M_VEC_BYTES; // 34_816
pub(crate) const P3_BYTES: usize = P3_ENTRIES * M_VEC_BYTES; // 4_896

/// Total size of expanded public key (P^(1) ‖ P^(2) ‖ P^(3)) in bytes.
pub(crate) const EXPANDED_PK_BYTES: usize = P1_BYTES + P2_BYTES + P3_BYTES; // 106_272

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_mayo2() {
        assert_eq!(SIG_BYTES, 186);
        assert_eq!(S_BYTES, 162);
        assert_eq!(CPK_BYTES, 4912);
        assert_eq!(P1_BYTES, 66_560);
        assert_eq!(P2_BYTES, 34_816);
        assert_eq!(P3_BYTES, 4_896);
        assert_eq!(EXPANDED_PK_BYTES, 106_272);
        assert_eq!(M_VEC_BYTES, 32);
    }
}

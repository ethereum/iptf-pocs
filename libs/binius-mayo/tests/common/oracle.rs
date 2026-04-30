//! Pure-Rust MAYO-2 signature verifier, used as a reference oracle for
//! the in-circuit verifier in this crate.
//!
//! Cross-checked against MAYO-C (`/tmp/MAYO-C/src/mayo.c` `mayo_verify`,
//! `eval_public_map`, `compute_rhs`, `expand_P1_P2`). All scalar GF(16)
//! arithmetic is over GF(2)[x]/(x^4 + x + 1).

#![deny(unsafe_code)]
#![allow(dead_code)]

use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

// MAYO-2 parameters: re-derived locally so the oracle compiles even
// while sibling library modules (`src/gf16`, `src/shake256`, …) are
// still in flight in parallel work.
//
// These match `src/params.rs`. Values come from MAYO-C
// `include/mayo.h` (MAYO_2_*).
pub const N: usize = 81;
pub const M: usize = 64;
pub const O: usize = 17;
pub const V: usize = N - O; // 64
pub const K: usize = 4;

pub const SALT_BYTES: usize = 24;
pub const DIGEST_BYTES: usize = 32;
pub const M_BYTES: usize = M / 2; // 32
pub const PK_SEED_BYTES: usize = 16;

pub const SIG_BYTES: usize = (K * N) / 2 + SALT_BYTES; // 186
pub const P1_ENTRIES: usize = V * (V + 1) / 2; // 2080
pub const P2_ENTRIES: usize = V * O; // 1088
pub const P3_ENTRIES: usize = O * (O + 1) / 2; // 153
pub const P1_BYTES: usize = P1_ENTRIES * M_BYTES; // 66_560
pub const P2_BYTES: usize = P2_ENTRIES * M_BYTES; // 34_816
pub const P3_BYTES: usize = P3_ENTRIES * M_BYTES; // 4_896
pub const CPK_BYTES: usize = PK_SEED_BYTES + P3_BYTES; // 4_912

/// `f(z) = z^M + 8 + 2 z^2 + 8 z^3` for MAYO-2 (from `F_TAIL_64` in
/// `include/mayo.h`). 8 = x^3 in GF(16)/(x^4+x+1); 2 = x.
pub const F_TAIL: [u8; 4] = [8, 0, 2, 8];

// Public API

/// Fully expanded MAYO-2 public key: every P^(*)[i,j] entry is stored as
/// a length-`M=64` vector of GF(16) nibbles (one nibble per byte slot,
/// in 0..16).
#[derive(Clone)]
pub struct ExpandedPk {
    /// `P^(1)[i, j]` for `0 <= i <= j < V` indexed by `idx_p1(i, j)`.
    /// `V * (V + 1) / 2 = 2080` entries.
    pub p1: Vec<[u8; M]>,
    /// `P^(2)[i, j]` for `i in [V], j in [O]`, indexed `i * O + j`.
    /// `V * O = 1088` entries.
    pub p2: Vec<[u8; M]>,
    /// `P^(3)[i, j]` for `0 <= i <= j < O`, indexed by `idx_p3(i, j)`.
    /// `O * (O + 1) / 2 = 153` entries.
    pub p3: Vec<[u8; M]>,
}

/// AES-128-CTR expand of `pk_seed` to (P^(1) ‖ P^(2)), plus unpack of P^(3)
/// from the cpk tail.
pub fn expand_pk(cpk: &[u8; CPK_BYTES]) -> ExpandedPk {
    // Split cpk: first 16 B = pk_seed; remaining 4896 B = packed P^(3).
    let pk_seed: &[u8; PK_SEED_BYTES] = (&cpk[..PK_SEED_BYTES])
        .try_into()
        .expect("CPK_BYTES >= PK_SEED_BYTES");
    let p3_packed = &cpk[PK_SEED_BYTES..CPK_BYTES];

    // Expand P^(1) ‖ P^(2) via AES-128-CTR(key = pk_seed, IV = 0).
    let total = P1_BYTES + P2_BYTES;
    let keystream = aes128_ctr_keystream(pk_seed, total);

    let p1 = unpack_m_vec_array(&keystream[..P1_BYTES], P1_ENTRIES);
    let p2 = unpack_m_vec_array(&keystream[P1_BYTES..P1_BYTES + P2_BYTES], P2_ENTRIES);
    let p3 = unpack_m_vec_array(p3_packed, P3_ENTRIES);

    ExpandedPk { p1, p2, p3 }
}

/// Evaluate `y = P^*(s)`: the public quadratic map applied to the
/// 4-block signature `s`. Returns 64 GF(16) nibbles (each in 0..16).
pub fn eval_public_map(p: &ExpandedPk, s: &[[u8; N]; K]) -> [u8; M] {
    // 1. PS[j][col] = sum_{r >= j} P[j][r] · s[col][r]  (upper-triangular P).
    //    P[j][r] is split: V×V upper-triangular P^(1), V×O P^(2), O×O upper-triangular P^(3).
    //    Bottom-left block is zero.
    let mut ps = vec![[0u8; M]; N * K];

    // Top-left block: P^(1) over [V] x [V] upper-triangular.
    let mut p1_idx = 0usize;
    for j in 0..V {
        for r in j..V {
            let p_jr = &p.p1[p1_idx];
            for col in 0..K {
                let s_col_r = s[col][r];
                if s_col_r != 0 {
                    let dst = &mut ps[j * K + col];
                    mvec_mul_add(dst, p_jr, s_col_r);
                }
            }
            p1_idx += 1;
        }
        // Top-right block: P^(2) over [V] x [O] (full rectangle).
        for r in 0..O {
            let p_jr = &p.p2[j * O + r];
            for col in 0..K {
                let s_col_r = s[col][V + r];
                if s_col_r != 0 {
                    let dst = &mut ps[j * K + col];
                    mvec_mul_add(dst, p_jr, s_col_r);
                }
            }
        }
    }

    // Bottom-right block: P^(3) over [O] x [O] upper-triangular.
    let mut p3_idx = 0usize;
    for j in 0..O {
        for r in j..O {
            let p_jr = &p.p3[p3_idx];
            for col in 0..K {
                let s_col_r = s[col][V + r];
                if s_col_r != 0 {
                    let dst = &mut ps[(V + j) * K + col];
                    mvec_mul_add(dst, p_jr, s_col_r);
                }
            }
            p3_idx += 1;
        }
    }

    // 2. SPS[row][col] = sum_j s[row][j] · PS[j][col]
    let mut sps = vec![[0u8; M]; K * K];
    for row in 0..K {
        for j in 0..N {
            let s_row_j = s[row][j];
            if s_row_j == 0 {
                continue;
            }
            for col in 0..K {
                let ps_jcol = ps[j * K + col];
                let dst = &mut sps[row * K + col];
                mvec_mul_add(dst, &ps_jcol, s_row_j);
            }
        }
    }

    // 3. Whipping: combine the K*K SPS lanes into a single length-M m-vec
    //    by treating it as a polynomial in GF(16)[z] / f(z), where
    //    f(z) = z^M + sum tail[i] * z^i. This mirrors `compute_rhs` in
    //    MAYO-C: outer loop i = K-1 down to 0, inner j = i..K, and at
    //    each step we multiply the running accumulator by z (reducing
    //    mod f(z)) before XOR-ing in SPS[i][j] (and SPS[j][i] when i!=j).
    let mut acc = [0u8; M];
    for i in (0..K).rev() {
        for j in i..K {
            // Multiply acc by z, reducing mod f(z).
            let top = acc[M - 1];
            for ell in (1..M).rev() {
                acc[ell] = acc[ell - 1];
            }
            acc[0] = 0;
            for tau in 0..F_TAIL.len() {
                let coeff = F_TAIL[tau];
                if coeff != 0 {
                    acc[tau] ^= mul_gf16(top, coeff);
                }
            }
            // XOR in SPS[i][j] (and SPS[j][i] when distinct).
            let ij = &sps[i * K + j];
            for ell in 0..M {
                acc[ell] ^= ij[ell];
            }
            if i != j {
                let ji = &sps[j * K + i];
                for ell in 0..M {
                    acc[ell] ^= ji[ell];
                }
            }
        }
    }

    acc
}

/// Verify a MAYO-2 signature. Returns `true` iff it is valid.
pub fn verify(pk: &[u8; CPK_BYTES], msg: &[u8], sig: &[u8; SIG_BYTES]) -> bool {
    let expanded = expand_pk(pk);

    // digest = SHAKE256(msg, 32)
    let digest = shake256(msg, DIGEST_BYTES);

    // salt = sig[162..186]
    let salt = &sig[(SIG_BYTES - SALT_BYTES)..SIG_BYTES];

    // t_packed = SHAKE256(digest ‖ salt, 32) → unpack 64 nibbles
    let mut t_input = Vec::with_capacity(DIGEST_BYTES + SALT_BYTES);
    t_input.extend_from_slice(&digest);
    t_input.extend_from_slice(salt);
    let t_packed = shake256(&t_input, M_BYTES);
    let t = unpack_nibbles(&t_packed, M);

    // Decode the K signature blocks: 162 bytes → 324 nibbles → 4 × 81.
    let s_bytes = &sig[..(K * N) / 2];
    let s_flat = unpack_nibbles(s_bytes, K * N);
    let mut s = [[0u8; N]; K];
    for col in 0..K {
        s[col].copy_from_slice(&s_flat[col * N..(col + 1) * N]);
    }

    let y = eval_public_map(&expanded, &s);

    // Constant-time-ish comparison is not required for an oracle.
    let mut t_arr = [0u8; M];
    t_arr.copy_from_slice(&t);
    y == t_arr
}

// Helpers (visible for tests)

/// SHAKE-256(input) → output_len bytes.
pub fn shake256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut out = vec![0u8; output_len];
    reader.read(&mut out);
    out
}

/// Unpack `n_nibbles` low-then-high nibbles from `packed` bytes.
///
/// Matches MAYO-C `decode`: byte i contributes nibble `2i` in low 4 bits
/// and nibble `2i+1` in high 4 bits.
pub fn unpack_nibbles(packed: &[u8], n_nibbles: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(n_nibbles);
    let full = n_nibbles / 2;
    for i in 0..full {
        let b = packed[i];
        out.push(b & 0x0f);
        out.push(b >> 4);
    }
    if n_nibbles % 2 == 1 {
        out.push(packed[full] & 0x0f);
    }
    out
}

/// Pack a sequence of GF(16) nibbles into bytes (low-then-high).
/// Matches MAYO-C `encode`.
pub fn pack_nibbles(nibbles: &[u8]) -> Vec<u8> {
    let n = nibbles.len();
    let full = n / 2;
    let mut out = Vec::with_capacity((n + 1) / 2);
    for i in 0..full {
        out.push(nibbles[2 * i] | (nibbles[2 * i + 1] << 4));
    }
    if n % 2 == 1 {
        out.push(nibbles[full * 2]);
    }
    out
}

/// Scalar GF(16) multiplication, GF(2)[x]/(x^4 + x + 1).
///
/// Bit-for-bit identical to MAYO-C `mul_f`.
pub fn mul_gf16(a: u8, b: u8) -> u8 {
    let a = a & 0x0f;
    let b = b & 0x0f;
    // Carryless multiply.
    let p = ((a & 1).wrapping_mul(b))
        ^ ((a & 2).wrapping_mul(b))
        ^ ((a & 4).wrapping_mul(b))
        ^ ((a & 8).wrapping_mul(b));
    // Reduce mod x^4 + x + 1.
    let top = p & 0xf0;
    (p ^ (top >> 4) ^ (top >> 3)) & 0x0f
}

/// AES-128-CTR with key = `pk_seed`, IV = 0, big-endian 32-bit counter
/// in bytes 12..16 of each AES input block.
///
/// Matches MAYO-C `AES_128_CTR` (counter convention drawn from the C
/// fallback `aes_c.c`: `iv[16] = {0}` and `ivw[3] = swap32(cc)` →
/// counter occupies bytes 12..15 big-endian, starting at 0).
fn aes128_ctr_keystream(pk_seed: &[u8; PK_SEED_BYTES], output_len: usize) -> Vec<u8> {
    let key = GenericArray::from_slice(pk_seed);
    let cipher = Aes128::new(key);

    let n_full = output_len / 16;
    let tail = output_len % 16;
    let mut out = vec![0u8; output_len];

    for i in 0..n_full {
        let mut block = [0u8; 16];
        block[12..16].copy_from_slice(&(i as u32).to_be_bytes());
        let mut blk = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut blk);
        out[i * 16..(i + 1) * 16].copy_from_slice(blk.as_slice());
    }
    if tail > 0 {
        let mut block = [0u8; 16];
        block[12..16].copy_from_slice(&(n_full as u32).to_be_bytes());
        let mut blk = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut blk);
        out[n_full * 16..n_full * 16 + tail].copy_from_slice(&blk.as_slice()[..tail]);
    }
    out
}

/// Unpack a contiguous byte slice into `n_entries` length-`M` m-vec
/// nibble arrays. Each m-vec consumes `M_BYTES = 32` bytes.
fn unpack_m_vec_array(packed: &[u8], n_entries: usize) -> Vec<[u8; M]> {
    debug_assert_eq!(packed.len(), n_entries * M_BYTES);
    let mut out = Vec::with_capacity(n_entries);
    for i in 0..n_entries {
        let mut e = [0u8; M];
        let off = i * M_BYTES;
        for b in 0..M_BYTES {
            let byte = packed[off + b];
            e[2 * b] = byte & 0x0f;
            e[2 * b + 1] = byte >> 4;
        }
        out.push(e);
    }
    out
}

/// `dst[ell] ^= mul_gf16(scalar, src[ell])` for ell in 0..M.
#[inline]
fn mvec_mul_add(dst: &mut [u8; M], src: &[u8; M], scalar: u8) {
    // `scalar != 0` already filtered by caller; small over-pessimization
    // here is harmless.
    for ell in 0..M {
        dst[ell] ^= mul_gf16(scalar, src[ell]);
    }
}

// Sanity tests for the helpers (run as part of the integration test crate
// since `tests/common` is consumed via `mod common`).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf16_mul_associative_sample() {
        // Sanity: mul_gf16 against a known reduction. x * x = x^2 (=4).
        assert_eq!(mul_gf16(2, 2), 4);
        // x^3 * x = x^4 = x + 1 = 3.
        assert_eq!(mul_gf16(8, 2), 3);
        // 1 is multiplicative identity.
        for a in 0u8..16 {
            assert_eq!(mul_gf16(a, 1), a);
            assert_eq!(mul_gf16(1, a), a);
        }
    }

    #[test]
    fn unpack_pack_roundtrip() {
        let nibbles: Vec<u8> = (0..32).map(|i| (i as u8) & 0x0f).collect();
        let packed = pack_nibbles(&nibbles);
        let unpacked = unpack_nibbles(&packed, nibbles.len());
        assert_eq!(unpacked, nibbles);
    }
}

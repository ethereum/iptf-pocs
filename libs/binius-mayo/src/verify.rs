//! Top-level MAYO-2 SNARK verifier.
//!
//! ## SNARK statement
//!
//! ```text
//! public:  c     : 32 bytes  = keccak256(DOMAIN_C  ‖ m)
//!          pk_id : 32 bytes  = keccak256(DOMAIN_PK ‖ canonical_packed(P^(1) ‖ P^(2) ‖ P^(3)))
//!
//! private: m            : 32 bytes               // the MAYO digest the sig authenticates
//!          expanded_pk  : 3321 bitsliced m-vecs  // block-decomposed P
//!          (s, salt)    : K * N nibbles + 24 B   // the MAYO-2 signature
//!
//! constraints:
//!   keccak256(DOMAIN_C  ‖ m)                    ?== c
//!   keccak256(DOMAIN_PK ‖ canonical_packed(P))  ?== pk_id
//!   t = SHAKE-256(m ‖ salt, 32 bytes)
//!   PS  = compute_ps(P, s)
//!   SPS = compute_sps(s, PS)
//!   y   = compute_rhs(SPS)
//!   y == bitslice(unpack_nibbles(t))
//! ```
//!
//! `DOMAIN_C` and `DOMAIN_PK` are 8-byte (one Word) domain-separation tags
//! defined in [`crate::api::DOMAIN_TAG_C`] / [`crate::api::DOMAIN_TAG_PK`].
//! Word-aligned tags keep the in-circuit byte layout simple and add a single
//! constant Word to each keccak preimage.

use binius_core::word::Word;
use binius_frontend::{CircuitBuilder, Wire, WitnessFiller};

use crate::api::{
    DOMAIN_TAG_C_WORD, DOMAIN_TAG_LEN, DOMAIN_TAG_PK_WORD, compute_c_from_digest, pk_id_from_lanes,
};
use crate::gf16::transpose::{bitsliced_to_packed, packed_to_bitsliced};
use crate::params::{
    EXPANDED_PK_BYTES, K, M, M_VEC_BYTES, N, P1_ENTRIES, P2_ENTRIES, P3_ENTRIES, S_BYTES,
    SALT_BYTES, SIG_BYTES,
};
use crate::quadratic::{ExpandedPkWires, SigBroadcasts, compute_ps, compute_sps};
use crate::shake256::shake256_56_to_32;
use crate::util::write_le_words;
use crate::whipping::compute_rhs;

const N_DIGEST_WORDS: usize = 4;
const N_SALT_WORDS: usize = SALT_BYTES / 8;

/// Top-level MAYO-2 SNARK verifier.
///
/// Build the circuit once with [`Mayo2Verify::new`]; reuse the same
/// `CircuitBuilder::build()` output across many witnesses by calling
/// [`Mayo2Verify::populate`] on a fresh `WitnessFiller` for each input.
pub struct Mayo2Verify {
    /// Public input: `c = keccak256(DOMAIN_C ‖ m)`. 4 Words = 32 bytes; word
    /// `i` holds bytes `[8*i, 8*i + 8)` in little-endian order.
    pub c: [Wire; N_DIGEST_WORDS],
    /// Public input:
    /// `pk_id = keccak256(DOMAIN_PK ‖ canonical_packed(P^(1) ‖ P^(2) ‖ P^(3)))`.
    /// Same little-endian byte ordering as `c`.
    pub pk_id: [Wire; N_DIGEST_WORDS],

    msg_wires: [Wire; N_DIGEST_WORDS],
    pk_wires: ExpandedPkWires,
    sig: SigBroadcasts,
    salt_wires: [Wire; N_SALT_WORDS],
}

impl Mayo2Verify {
    /// Build the full MAYO-2 verifier circuit. Allocates all wires (public
    /// inputs, witness, intermediate) and emits every constraint.
    pub fn new(builder: &CircuitBuilder) -> Self {
        let b = builder.subcircuit("mayo2/verify");

        let c: [Wire; N_DIGEST_WORDS] = core::array::from_fn(|_| b.add_inout());
        let pk_id: [Wire; N_DIGEST_WORDS] = core::array::from_fn(|_| b.add_inout());

        let msg_wires: [Wire; N_DIGEST_WORDS] = core::array::from_fn(|_| b.add_witness());
        let pk_wires = ExpandedPkWires::new_witness(&b);
        let sig = SigBroadcasts::new_witness(&b);
        let salt_wires: [Wire; N_SALT_WORDS] = core::array::from_fn(|_| b.add_witness());

        // Constraint 1: keccak256(DOMAIN_C ‖ m) == c.
        //
        // The domain tag is a compile-time constant Word prepended to the
        // message-digest wires. Total preimage length = 8 + 32 = 40 bytes.
        {
            let bb = b.subcircuit("hash_message");
            let tag = bb.add_constant(Word(DOMAIN_TAG_C_WORD));
            let mut input: [Wire; N_DIGEST_WORDS + 1] = [tag; N_DIGEST_WORDS + 1];
            input[1..].copy_from_slice(&msg_wires);
            let c_hat =
                binius_circuits::keccak::fixed_length::keccak256(&bb, &input, DOMAIN_TAG_LEN + 32);
            for i in 0..N_DIGEST_WORDS {
                bb.assert_eq(format!("c[{i}]"), c_hat[i], c[i]);
            }
        }

        // Constraint 2: keccak256(DOMAIN_PK ‖ canonical_packed(P)) == pk_id.
        //
        // Canonical layout: for each m-vec entry of P^(1), P^(2), P^(3) in
        // their MAYO-C row-major upper-triangular orderings (matching
        // `idx_p1` / `idx_p2` / `idx_p3` in `quadratic.rs`), emit
        // `bitsliced_to_packed` to recover 4 packed Words (= 32 bytes), then
        // append in order. Total: 3321 entries × 4 words = 13284 packed words
        // = 106272 bytes, exactly `EXPANDED_PK_BYTES`. The 8-byte domain tag
        // brings the keccak preimage to `DOMAIN_TAG_LEN + EXPANDED_PK_BYTES`.
        {
            let bb = b.subcircuit("hash_pk");
            let total_words = (P1_ENTRIES + P2_ENTRIES + P3_ENTRIES) * (M_VEC_BYTES / 8);
            let mut packed: Vec<Wire> = Vec::with_capacity(1 + total_words);
            packed.push(bb.add_constant(Word(DOMAIN_TAG_PK_WORD)));
            for mvec in pk_wires
                .p1
                .iter()
                .chain(pk_wires.p2.iter())
                .chain(pk_wires.p3.iter())
            {
                let words = bitsliced_to_packed(&bb, mvec);
                packed.extend_from_slice(&words);
            }
            assert_eq!(packed.len(), 1 + total_words);
            let pk_id_hat = binius_circuits::keccak::fixed_length::keccak256(
                &bb,
                &packed,
                DOMAIN_TAG_LEN + EXPANDED_PK_BYTES,
            );
            for i in 0..N_DIGEST_WORDS {
                bb.assert_eq(format!("pk_id[{i}]"), pk_id_hat[i], pk_id[i]);
            }
        }

        // Constraint 3: t = SHAKE-256(m ‖ salt, 32).
        //
        // Approach E: `m` is already a 32-byte digest (the MAYO digest the
        // signature authenticates), so we feed it straight into the SHAKE-256
        // call. Input layout: 7 Words = 32 + 24 = 56 bytes, where bytes 0..32
        // are `m` and bytes 32..56 are `salt`.
        let in56: [Wire; 7] = [
            msg_wires[0],
            msg_wires[1],
            msg_wires[2],
            msg_wires[3],
            salt_wires[0],
            salt_wires[1],
            salt_wires[2],
        ];
        let t_packed: [Wire; 4] = shake256_56_to_32(&b, &in56);
        let t = packed_to_bitsliced(&b, &t_packed);

        // Constraint 4: y = MayoEvalPublicMap(P, s).
        let ps = compute_ps(&b, &pk_wires, &sig);
        let sps = compute_sps(&b, &sig, &ps);
        let y = compute_rhs(&b, &sps);

        // Constraint 5: y == t.
        y.assert_eq(&b, &t);

        Self {
            c,
            pk_id,
            msg_wires,
            pk_wires,
            sig,
            salt_wires,
        }
    }

    /// Populate the witness from raw inputs.
    ///
    /// `m` is the 32-byte MAYO digest the signature authenticates. For the
    /// NIST KAT path, the caller computes `m = SHAKE-256(msg, 32)` off-circuit
    /// before calling this.
    ///
    /// `p1_lanes`/`p2_lanes`/`p3_lanes` are the AES-CTR-expanded MAYO-2 public
    /// key in lane form: one `[u8; M]` per upper-triangular entry of
    /// `P^(1)`/`P^(3)` and per rectangular entry of `P^(2)`, in the orderings
    /// used by `idx_p1`/`idx_p2`/`idx_p3`.
    ///
    /// Both public inputs (`c` and `pk_id`) are computed inside this function
    /// from `m` and the lane arrays, then written to their respective wires;
    /// callers do not need to pre-compute them.
    pub fn populate(
        &self,
        w: &mut WitnessFiller,
        m: &[u8; 32],
        p1_lanes: &[[u8; M]],
        p2_lanes: &[[u8; M]],
        p3_lanes: &[[u8; M]],
        sig: &[u8; SIG_BYTES],
    ) {
        // 1. Message wires.
        write_le_words(w, &self.msg_wires, m);

        // 2. Expanded public-key wires.
        self.pk_wires.populate(w, p1_lanes, p2_lanes, p3_lanes);

        // 3. Signature scalar block + salt.
        //
        //    sig[0..S_BYTES] holds K*N nibbles, packed two-per-byte (low-then-high,
        //    matches MAYO-C `decode`). With N odd, column boundaries fall mid-byte,
        //    so we unpack the full nibble stream first and then slice it by N.
        //    sig[S_BYTES..SIG_BYTES] is the 24-byte salt.
        let s_bytes = &sig[..S_BYTES];
        let salt_bytes = &sig[S_BYTES..SIG_BYTES];

        let mut nibbles = [0u8; K * N];
        for (i, &byte) in s_bytes.iter().enumerate() {
            nibbles[2 * i] = byte & 0x0F;
            nibbles[2 * i + 1] = (byte >> 4) & 0x0F;
        }
        let mut s_lanes: [[u8; N]; K] = [[0; N]; K];
        for (col, lane_row) in s_lanes.iter_mut().enumerate() {
            lane_row.copy_from_slice(&nibbles[col * N..(col + 1) * N]);
        }
        self.sig.populate(w, &s_lanes);

        write_le_words(w, &self.salt_wires, salt_bytes);

        // 4. Public inputs `c` and `pk_id`. Both reuse the streaming hashers
        //    in `api.rs` to avoid materialising the keccak preimages.
        let c_bytes = *compute_c_from_digest(m).as_bytes();
        write_le_words(w, &self.c, &c_bytes);

        let pk_id_bytes = *pk_id_from_lanes(p1_lanes, p2_lanes, p3_lanes).as_bytes();
        write_le_words(w, &self.pk_id, &pk_id_bytes);
    }
}

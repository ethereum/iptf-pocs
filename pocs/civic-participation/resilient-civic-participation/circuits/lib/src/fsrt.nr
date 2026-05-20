// Forward-Secure Ratchet Tree (FSRT) PRG step.
//
// `(v_i, s_{i+1}) = Poseidon1Sponge.absorb(DOMAIN_FSRT_PRG, s_i).squeeze(2)`.
//
// The Noir `poseidon` crate exposes a low-level permutation rather than
// a length-padded sponge. For the PoC we model the absorb-squeeze of two
// elements with two independent width-5 hashes salted by output index
// (0, 1). This matches the Rust `Poseidon1Sponge` two-output convention
// implemented in `src/poseidon.rs`.

use crate::domain;
use poseidon::poseidon::bn254::hash_5;

pub fn fsrt_prg_step(s_i: Field) -> (Field, Field) {
    let v_i = hash_5([domain::DOMAIN_FSRT_PRG, s_i, 0, 0, 0]);
    let s_next = hash_5([domain::DOMAIN_FSRT_PRG, s_i, 1, 0, 0]);
    (v_i, s_next)
}

// Derive v_slot given s_slot. The signer's witness threads s_slot in
// directly; this is the absorb-squeeze that the SPEC mandates.
pub fn derive_v_slot(s_slot: Field) -> Field {
    let (v, _) = fsrt_prg_step(s_slot);
    v
}

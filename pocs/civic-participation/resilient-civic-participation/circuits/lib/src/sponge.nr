// Poseidon1 sponge (SPEC Primitives): rate r = 4, capacity c = 1,
// `t = 5`, 0x80-prefixed length-padding to a multiple of r scalars.
// Built on `poseidon::poseidon::permute` over the bn254 x5_5 instance;
// produces outputs identical to the Rust `Poseidon1Sponge` in
// `src/poseidon.rs` (pinned by `tests::sponge_fsrt_matches_rust`).

use poseidon::poseidon::bn254::consts::x5_5_config;
use poseidon::poseidon::permute;

pub struct Poseidon1Sponge {
    state: [Field; 5],
}

impl Poseidon1Sponge {
    pub fn with_domain(domain: Field) -> Self {
        Self { state: [domain, 0, 0, 0, 0] }
    }

    // Absorb a single field element with 0x80-prefix padding to one
    // rate-block. SPEC `absorb(DOMAIN, x)` for the FSRT PRG step.
    pub fn absorb_one(&mut self, m: Field) {
        self.state[1] += m;
        self.state[2] += 0x80;
        self.state = permute(x5_5_config(), self.state);
    }

    // Squeeze the first two rate positions. rate = 4 means two outputs
    // are available from a single permutation; SPEC `squeeze(2)` does
    // not invoke a second permute.
    pub fn squeeze_two(self) -> [Field; 2] {
        [self.state[1], self.state[2]]
    }
}

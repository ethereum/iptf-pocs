// Domain separation tags for Poseidon1. PoC simplification:
// SPEC defines these as Poseidon1_t2(0, SHA256("RDR/<purpose>/v1") mod r_BN254);
// the implementation uses small distinct constants. Recorded as a divergence
// in README.md.
pub global LEAF_DOMAIN_TAG: Field = 1;
pub global COMMITMENT_DOMAIN_TAG: Field = 2;
pub global NULL_DOMAIN_TAG: Field = 3;

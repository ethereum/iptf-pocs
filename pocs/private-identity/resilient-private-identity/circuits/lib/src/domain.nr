/// Domain separation tags for Poseidon hashing.
/// Each tag is the first input element to the hash call, ensuring
/// cross-context collision resistance.

pub global DOMAIN_LEAF: Field = 1;
pub global DOMAIN_NULLIFIER: Field = 2;
pub global DOMAIN_ENROLLMENT_NULL: Field = 3;
pub global DOMAIN_ATTR: Field = 4;
pub global DOMAIN_EXTERNAL_NULLIFIER: Field = 5;
pub global DOMAIN_NAME: Field = 6;
pub global DOMAIN_LINK: Field = 7;
pub global DOMAIN_H2C: Field = 8;

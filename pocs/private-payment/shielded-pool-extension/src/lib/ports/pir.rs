// PIR client port. Used for the single PIR'd read: the commitment-tree path.
// Phantom-epoch lookups bypass PIR (cleartext is safe by the phantom argument),
// and the active nullifier tree is never queried by the spender (the relayer
// reads it directly to build the insertion proof). Backend-agnostic — see
// SPEC.md "PIR Backend Selection".
//
// TODO: implement.

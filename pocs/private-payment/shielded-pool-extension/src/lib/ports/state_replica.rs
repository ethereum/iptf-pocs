// State-replica server port: phantom-epoch witness lookups served in clear,
// the commitment-tree path served via PIR (the only PIR'd read), and the
// relayer path that builds insertion witnesses from the active-tree replica
// and produces the insertion proof. Untrusted for correctness; every returned
// node is rechecked in-circuit against the light-client-verified root. See
// SPEC.md "Off-Chain State-Replica Server".
//
// TODO: implement.

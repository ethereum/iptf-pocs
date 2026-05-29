// HTTP adapter to the off-chain state-replica server.
//
// Deferred: per the "in-process core first" decision, Slice 1.3 builds the
// StateReplica core (adapters::state_replica) and queries it in-process. This
// HTTP transport (the wallet's network client + the server binary's request
// handlers) is wired in the e2e slice, where the server runs against anvil. The
// wallet-facing seams it will implement are unchanged: PirClient (commitment
// path) and StateReplicaQuery (phantom witnesses).
//
// TODO: implement (e2e slice).

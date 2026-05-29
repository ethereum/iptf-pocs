// Barretenberg prover adapter. Three artifacts:
//  - outer spend (transfer / withdraw / deposit): EVM-verifiable, keccak oracle.
//  - outer insertion (relayer-produced active-tree update): EVM-verifiable,
//    keccak oracle, need not be zk.
//  - inner (chain-update): recursion-friendly, no Solidity verifier needed.
//
// TODO: implement.

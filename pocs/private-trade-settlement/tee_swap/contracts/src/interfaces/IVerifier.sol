// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IVerifier
/// @notice Interface for ZK proof verification (single unified circuit)
interface IVerifier {
    /// @notice Verify a transfer proof
    /// @param proof The ZK proof bytes
    /// @param publicInputs Public inputs (9 fields): [nullifier, root, newCommitment, timeout, pkStealth, hSwap, hR, hMeta, hEnc]
    /// @return True if the proof is valid
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

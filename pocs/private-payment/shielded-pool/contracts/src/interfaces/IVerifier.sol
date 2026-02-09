// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IVerifier
/// @notice Interface for ZK proof verification (auto-generated from Noir circuits)
interface IVerifier {
    /// @notice Verify a deposit proof
    /// @param proof The ZK proof bytes
    /// @param publicInputs Public inputs: [commitment, token, amount, attestation_root]
    /// @return True if the proof is valid
    function verifyDeposit(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);

    /// @notice Verify a transfer proof
    /// @param proof The ZK proof bytes
    /// @param publicInputs Public inputs: [nullifier1, nullifier2, commitment1, commitment2, commitment_root]
    /// @return True if the proof is valid
    function verifyTransfer(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);

    /// @notice Verify a withdraw proof
    /// @param proof The ZK proof bytes
    /// @param publicInputs Public inputs: [nullifier, token, amount, recipient, commitment_root]
    /// @return True if the proof is valid
    function verifyWithdraw(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

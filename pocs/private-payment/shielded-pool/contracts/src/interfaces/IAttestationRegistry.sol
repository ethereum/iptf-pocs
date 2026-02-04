// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IAttestationRegistry
/// @notice Interface for querying attestation state
interface IAttestationRegistry {
    /// @notice Get the current attestation Merkle root
    /// @return The current root of the attestation tree
    function attestationRoot() external view returns (bytes32);

    /// @notice Check if an attestation leaf exists
    /// @param leaf The attestation leaf hash
    /// @return True if the attestation exists and has not been revoked
    function attestationLeaves(bytes32 leaf) external view returns (bool);
}

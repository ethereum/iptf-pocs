// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title IVerifier
/// @notice Aztec Honk verifier ABI. Each circuit-specific verifier contract
///         exposes this single `verify` entry point.
interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool);
}

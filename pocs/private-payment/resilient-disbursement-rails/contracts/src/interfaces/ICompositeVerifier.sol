// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title ICompositeVerifier
/// @notice Wraps the two circuit verifiers (claim, pool-withdraw) behind a
///         single facade.
interface ICompositeVerifier {
    function verifyClaim(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
    function verifyPoolWithdraw(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ICompositeVerifier} from "../interfaces/ICompositeVerifier.sol";

/// @title MockCompositeVerifier
/// @notice Configurable mock composite verifier. Each method returns the
///         flag set via `setClaimResult` / `setPoolWithdrawResult`. Records
///         call counts and last inputs for assertions.
contract MockCompositeVerifier is ICompositeVerifier {
    bool public claimResult = true;
    bool public poolWithdrawResult = true;
    uint256 public claimCalls;
    uint256 public poolWithdrawCalls;
    bytes32[] public lastClaimPublicInputs;
    bytes32[] public lastPoolWithdrawPublicInputs;

    function setClaimResult(bool r) external {
        claimResult = r;
    }

    function setPoolWithdrawResult(bool r) external {
        poolWithdrawResult = r;
    }

    function verifyClaim(bytes calldata, bytes32[] calldata publicInputs) external returns (bool) {
        claimCalls++;
        delete lastClaimPublicInputs;
        for (uint256 i = 0; i < publicInputs.length; i++) {
            lastClaimPublicInputs.push(publicInputs[i]);
        }
        return claimResult;
    }

    function verifyPoolWithdraw(bytes calldata, bytes32[] calldata publicInputs) external returns (bool) {
        poolWithdrawCalls++;
        delete lastPoolWithdrawPublicInputs;
        for (uint256 i = 0; i < publicInputs.length; i++) {
            lastPoolWithdrawPublicInputs.push(publicInputs[i]);
        }
        return poolWithdrawResult;
    }
}

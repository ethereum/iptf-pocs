// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @title MockVerifier
/// @notice Configurable mock implementing the generic `IVerifier` for tests.
///         Returns `result` (default true) regardless of proof or inputs.
contract MockVerifier is IVerifier {
    bool public result = true;

    function setResult(bool result_) external {
        result = result_;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return result;
    }
}

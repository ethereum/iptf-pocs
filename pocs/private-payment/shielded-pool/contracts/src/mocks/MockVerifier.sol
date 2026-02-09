// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IUltraVerifier} from "../interfaces/IUltraVerifier.sol";

/// @title MockVerifier
/// @notice Configurable mock verifier for testing
contract MockVerifier is IUltraVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

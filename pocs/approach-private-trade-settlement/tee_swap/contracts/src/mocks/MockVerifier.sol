// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @title MockVerifier
/// @notice Configurable mock verifier for testing
contract MockVerifier is IVerifier {
    bool public result = true;

    function setResult(bool _result) external {
        result = _result;
    }

    function verify(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return result;
    }
}

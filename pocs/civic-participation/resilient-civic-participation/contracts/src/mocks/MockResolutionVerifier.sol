// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "../interfaces/IVerifier.sol";

/// Test-only mock. NOT for production deployment. Deploy scripts are
/// gated by `use_mock_verifier`.
contract MockResolutionVerifier is IVerifier {
    bool public result;

    constructor() {
        result = true;
    }

    function setResult(bool r) external {
        result = r;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return result;
    }
}

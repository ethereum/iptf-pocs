// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @title MockClaimVerifier
/// @notice Configurable mock for the claim circuit verifier. Returns the
///         configured boolean.
contract MockClaimVerifier is IVerifier {
    bool public result = true;
    uint256 public callCount;
    bytes public lastProof;
    bytes32[] public lastPublicInputs;

    function setResult(bool r) external {
        result = r;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool) {
        callCount++;
        lastProof = proof;
        delete lastPublicInputs;
        for (uint256 i = 0; i < publicInputs.length; i++) {
            lastPublicInputs.push(publicInputs[i]);
        }
        return result;
    }
}

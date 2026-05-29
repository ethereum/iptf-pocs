// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        view
        returns (bool);
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IIdentityTree {
    function isRecentRoot(uint256 root) external view returns (bool);
}

interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

contract IdentityVerifier {
    IIdentityTree public identityTree;
    IVerifier public verifier;

    mapping(uint256 => bool) public usedNullifiers;

    event ProofVerified(uint256 indexed nullifier, uint256 root, uint256 externalNullifier, uint256 version);

    error StaleRoot();
    error NullifierUsed();
    error InvalidAttrIndex();
    error InvalidProof();

    constructor(address _identityTree, address _verifier) {
        identityTree = IIdentityTree(_identityTree);
        verifier = IVerifier(_verifier);
    }

    function verifyProof(
        bytes calldata proof,
        uint256 root,
        uint256 nullifier,
        uint256 externalNullifier,
        uint256 version,
        uint256 predicateType,
        uint256 predicateAttrIndex,
        uint256 predicateValue,
        uint256 predicateResult
    ) external {
        if (!identityTree.isRecentRoot(root)) revert StaleRoot();
        if (usedNullifiers[nullifier]) revert NullifierUsed();
        if (predicateAttrIndex >= 2) revert InvalidAttrIndex();

        bytes32[] memory publicInputs = new bytes32[](8);
        publicInputs[0] = bytes32(root);
        publicInputs[1] = bytes32(nullifier);
        publicInputs[2] = bytes32(externalNullifier);
        publicInputs[3] = bytes32(version);
        publicInputs[4] = bytes32(predicateType);
        publicInputs[5] = bytes32(predicateAttrIndex);
        publicInputs[6] = bytes32(predicateValue);
        publicInputs[7] = bytes32(predicateResult);

        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        usedNullifiers[nullifier] = true;

        emit ProofVerified(nullifier, root, externalNullifier, version);
    }
}

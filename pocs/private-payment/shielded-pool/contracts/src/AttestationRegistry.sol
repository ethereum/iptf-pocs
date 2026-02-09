// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAttestationRegistry} from "./interfaces/IAttestationRegistry.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";
import {PoseidonT5} from "poseidon-solidity/PoseidonT5.sol";

/// @title AttestationRegistry
/// @notice Manages KYC attestations for the shielded pool
/// @dev Attestations are stored as leaves in a LeanIMT Merkle tree for ZK proof inclusion
contract AttestationRegistry is IAttestationRegistry {
    using LeanIMT for LeanIMTData;

    /// @notice LeanIMT tree data storage
    LeanIMTData internal _tree;

    /// @notice Mapping of attestation leaf hash to existence status
    mapping(bytes32 => bool) public override attestationLeaves;

    /// @notice Mapping of leaf index to leaf hash (for retrieval)
    mapping(uint40 => bytes32) public leafAtIndex;

    /// @notice Mapping of authorized attesters (compliance authorities)
    mapping(address => bool) public authorizedAttesters;

    /// @notice Contract owner
    address public owner;

    // Events
    event AttestationAdded(
        bytes32 indexed leaf,
        bytes32 indexed subjectPubkeyHash,
        address indexed attester,
        uint64 issuedAt,
        uint64 expiresAt
    );
    event AttestationRevoked(bytes32 indexed leaf, address indexed revokedBy);
    event AttesterAdded(address indexed attester);
    event AttesterRemoved(address indexed attester);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Errors
    error OnlyOwner();
    error OnlyAuthorizedAttester();
    error AttestationAlreadyExists();
    error AttestationDoesNotExist();
    error AttesterAlreadyAuthorized();
    error AttesterNotAuthorized();
    error ZeroAddress();

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert OnlyOwner();
    }

    modifier onlyAuthorizedAttester() {
        _onlyAuthorizedAttester();
        _;
    }

    function _onlyAuthorizedAttester() internal view {
        if (!authorizedAttesters[msg.sender]) revert OnlyAuthorizedAttester();
    }

    constructor() {
        owner = msg.sender;
        // LeanIMT doesn't require explicit initialization
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Get the current attestation Merkle root
    /// @return The current root of the attestation tree
    function attestationRoot() external view override returns (bytes32) {
        return bytes32(_tree.root());
    }

    /// @notice Add a new attestation for a subject
    /// @param subjectPubkeyHash Hash of the subject's spending public key
    /// @param expiresAt Expiration timestamp (0 = no expiry)
    /// @return leaf The attestation leaf hash
    function addAttestation(bytes32 subjectPubkeyHash, uint64 expiresAt)
        external
        onlyAuthorizedAttester
        returns (bytes32 leaf)
    {
        uint64 issuedAt = uint64(block.timestamp);

        // Compute attestation leaf: poseidon(subjectPubkeyHash, attester, issuedAt, expiresAt)
        uint256 leafValue = PoseidonT5.hash(
            [uint256(subjectPubkeyHash), uint256(uint160(msg.sender)), uint256(issuedAt), uint256(expiresAt)]
        );
        leaf = bytes32(leafValue);

        if (attestationLeaves[leaf]) revert AttestationAlreadyExists();

        attestationLeaves[leaf] = true;
        uint256 index = _tree.size;
        leafAtIndex[uint40(index)] = leaf;
        _tree.insert(leafValue);

        emit AttestationAdded(leaf, subjectPubkeyHash, msg.sender, issuedAt, expiresAt);
    }

    /// @notice Revoke an existing attestation
    /// @dev LeanIMT requires sibling nodes for updates, computed off-chain
    /// @param oldLeaf The attestation leaf value to revoke
    /// @param siblingNodes The sibling nodes required to verify the leaf
    function revokeAttestation(uint256 oldLeaf, uint256[] calldata siblingNodes) external onlyAuthorizedAttester {
        bytes32 leaf = bytes32(oldLeaf);
        if (!attestationLeaves[leaf]) revert AttestationDoesNotExist();
        attestationLeaves[leaf] = false;

        // LeanIMT update sets the leaf to 0 (removal)
        _tree.remove(oldLeaf, siblingNodes);

        emit AttestationRevoked(leaf, msg.sender);
    }

    /// @notice Add an authorized attester
    /// @param attester Address to authorize
    function addAttester(address attester) external onlyOwner {
        if (attester == address(0)) revert ZeroAddress();
        if (authorizedAttesters[attester]) revert AttesterAlreadyAuthorized();

        authorizedAttesters[attester] = true;
        emit AttesterAdded(attester);
    }

    /// @notice Remove an authorized attester
    /// @param attester Address to remove
    function removeAttester(address attester) external onlyOwner {
        if (!authorizedAttesters[attester]) revert AttesterNotAuthorized();

        authorizedAttesters[attester] = false;
        emit AttesterRemoved(attester);
    }

    /// @notice Check if an address is an authorized attester
    /// @param attester Address to check
    /// @return True if authorized
    function isAuthorizedAttester(address attester) external view returns (bool) {
        return authorizedAttesters[attester];
    }

    /// @notice Get the total number of attestations
    /// @return The count of attestations
    function getAttestationCount() external view returns (uint256) {
        return _tree.size;
    }

    /// @notice Transfer ownership of the contract
    /// @param newOwner Address of the new owner
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

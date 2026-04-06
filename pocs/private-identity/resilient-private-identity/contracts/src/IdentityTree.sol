// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

contract IdentityTree {
    using LeanIMT for LeanIMTData;

    LeanIMTData private tree;

    uint256[1000] public recentRoots;
    uint256 public rootIndex;

    mapping(uint256 => bool) public insertedLeaves;
    mapping(uint256 => bool) public usedEnrollmentNullifiers;
    mapping(address => bool) public authorized;

    address public governance;
    bool public paused;

    event LeafInserted(uint256 indexed index, uint256 leaf, uint256 enrollmentNullifier, uint256 newRoot);

    error NotGovernance();
    error NotAuthorized();
    error ContractPaused();
    error DuplicateLeaf();
    error DuplicateEnrollmentNullifier();

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    modifier onlyAuthorized() {
        if (!authorized[msg.sender]) revert NotAuthorized();
        _;
    }

    modifier whenNotPaused() {
        if (paused) revert ContractPaused();
        _;
    }

    constructor(address _governance) {
        governance = _governance;
    }

    function insertLeaf(uint256 leaf, uint256 enrollmentNullifier) external onlyAuthorized whenNotPaused {
        if (insertedLeaves[leaf]) revert DuplicateLeaf();
        if (usedEnrollmentNullifiers[enrollmentNullifier]) revert DuplicateEnrollmentNullifier();

        insertedLeaves[leaf] = true;
        usedEnrollmentNullifiers[enrollmentNullifier] = true;

        uint256 index = tree.size;
        tree.insert(leaf);
        uint256 newRoot = tree.root();

        rootIndex = (rootIndex + 1) % 1000;
        recentRoots[rootIndex] = newRoot;

        emit LeafInserted(index, leaf, enrollmentNullifier, newRoot);
    }

    function isRecentRoot(uint256 root) public view returns (bool) {
        if (root == 0) return false;
        for (uint256 i = 0; i < 1000; i++) {
            if (recentRoots[i] == root) return true;
        }
        return false;
    }

    function addAuthorized(address addr) external onlyGovernance {
        authorized[addr] = true;
    }

    function removeAuthorized(address addr) external onlyGovernance {
        authorized[addr] = false;
    }

    function pause() external onlyGovernance {
        paused = true;
    }

    function unpause() external onlyGovernance {
        paused = false;
    }
}

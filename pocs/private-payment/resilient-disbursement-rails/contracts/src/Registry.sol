// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IRegistry} from "./interfaces/IRegistry.sol";

/// @title Registry
/// @notice Versioned cohort commitment store. Operator publishes
///         `cohortRoot` and `cohortSize` per version. Per-card enrollment
///         state lives off-chain in the operator's `OperatorRegistry`.
contract Registry is IRegistry {
    /// @notice Current cohort version. Bumped on every `publishCohort`.
    uint64 public override currentVersion;

    /// @notice cohortRoot per version.
    mapping(uint64 => uint256) public override cohortRoot;

    /// @notice cohortSize per version.
    mapping(uint64 => uint256) public override cohortSize;

    /// @notice Address authorized to call `publishCohort`.
    address public operatorKey;

    /// @notice Address authorized to rotate the operator key (under timelock).
    address public governance;

    /// @notice Pending operator-key rotation.
    address public pendingOperatorKey;
    uint256 public pendingOperatorKeyActivation;

    /// @notice Timelock for operator-key rotation.
    uint256 public constant OPERATOR_KEY_TIMELOCK_BLOCKS = 14400;

    event CohortPublished(uint64 indexed version, uint256 root, uint256 size);
    event OperatorKeyProposed(address indexed newKey, uint256 activationBlock);
    event OperatorKeyUpdated(address indexed oldKey, address indexed newKey);

    error NotGovernance();
    error NotOperator();
    error EmptyRoot();
    error EmptySize();
    error NoPendingKey();
    error TimelockNotExpired();
    error KeyAlreadyPending();
    error ZeroAddress();

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    modifier onlyOperator() {
        if (msg.sender != operatorKey) revert NotOperator();
        _;
    }

    constructor(address _operatorKey, address _governance) {
        if (_operatorKey == address(0) || _governance == address(0)) revert ZeroAddress();
        operatorKey = _operatorKey;
        governance = _governance;
    }

    /// @notice Publish a new cohort version. Past versions remain immutable.
    function publishCohort(uint256 root, uint256 size) external onlyOperator {
        if (root == 0) revert EmptyRoot();
        if (size == 0) revert EmptySize();

        uint64 v = currentVersion + 1;
        currentVersion = v;
        cohortRoot[v] = root;
        cohortSize[v] = size;

        emit CohortPublished(v, root, size);
    }

    /// @notice Propose a rotation of the operator key. Activates after the
    ///         timelock. Governance-only.
    function proposeOperatorKey(address newKey) external onlyGovernance {
        if (newKey == address(0)) revert ZeroAddress();
        if (pendingOperatorKeyActivation != 0) revert KeyAlreadyPending();

        pendingOperatorKey = newKey;
        pendingOperatorKeyActivation = block.number + OPERATOR_KEY_TIMELOCK_BLOCKS;

        emit OperatorKeyProposed(newKey, pendingOperatorKeyActivation);
    }

    /// @notice Finalize a pending operator-key rotation after the timelock.
    function finalizeOperatorKey() external onlyGovernance {
        if (pendingOperatorKeyActivation == 0) revert NoPendingKey();
        if (block.number < pendingOperatorKeyActivation) revert TimelockNotExpired();

        address oldKey = operatorKey;
        operatorKey = pendingOperatorKey;
        pendingOperatorKey = address(0);
        pendingOperatorKeyActivation = 0;

        emit OperatorKeyUpdated(oldKey, operatorKey);
    }

    /// @notice Cancel a pending operator-key rotation.
    function cancelPendingOperatorKey() external onlyGovernance {
        if (pendingOperatorKeyActivation == 0) revert NoPendingKey();
        pendingOperatorKey = address(0);
        pendingOperatorKeyActivation = 0;
    }
}

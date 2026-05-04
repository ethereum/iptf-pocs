// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title IRegistry
/// @notice Versioned cohort commitment store with per-card cohort_position.
interface IRegistry {
    function currentVersion() external view returns (uint64);
    function cohortRoot(uint64 version) external view returns (uint256);
    function cohortSize(uint64 version) external view returns (uint256);
    function cohortPosition(uint64 version, bytes32 cardId) external view returns (uint64);
}

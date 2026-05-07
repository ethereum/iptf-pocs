// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title IPool
/// @notice Per-claim-contract partitioned shielded ERC-20 pool. Each registered
///         claim contract has its own commitment sub-tree.
interface IPool {
    /// @notice Deposit a commitment for the given claim contract's sub-tree.
    /// @dev Authorized: factory only. Pulls `amount` of the pool token from
    ///      msg.sender and inserts `commitment` into the claim contract's
    ///      LeanIMT sub-tree.
    function deposit(address claimContract, uint256 commitment, uint256 amount, uint256 roundId) external;

    /// @notice Unshield from the given claim contract's sub-tree.
    /// @dev Authorized: msg.sender == claimContract. Asserts `subTreeRoot`
    ///      is known for `claimContract` (current or recent), verifies the
    ///      pool-withdraw proof, and transfers `amount` of `token` to
    ///      `recipient`. The claim contract is responsible for asserting
    ///      cross-proof binding before calling.
    function unshield(
        address claimContract,
        bytes calldata withdrawProof,
        uint256 subTreeRoot,
        uint256 claimNullifier,
        address token,
        uint256 amount,
        address recipient,
        uint256 roundId
    ) external;

    /// @notice Recover residual balance for a closed round.
    /// @dev Authorized: msg.sender == claim contract registered at deposit
    ///      time. Pays at most once per (claim contract, roundId).
    function recoverResidual(uint256 roundId, uint256 amount, address recipient) external;

    /// @notice Whether the given root is current or in the recent-roots window
    ///         for the given claim contract's sub-tree.
    function isKnownRoot(address claimContract, uint256 root) external view returns (bool);

    /// @notice Returns leafIndex+1 (0 means unknown) for the given commitment
    ///         under the given claim contract.
    function commitmentIndex(address claimContract, uint256 commitment) external view returns (uint256);

    /// @notice The factory authorized to call `deposit`.
    function authorizedFactory() external view returns (address);
}

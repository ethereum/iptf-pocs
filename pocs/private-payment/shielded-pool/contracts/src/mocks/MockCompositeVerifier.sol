// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "../interfaces/IVerifier.sol";

/// @title MockVerifier
/// @notice Configurable mock verifier for testing
contract MockVerifier is IVerifier {
    bool public depositResult = true;
    bool public transferResult = true;
    bool public withdrawResult = true;

    uint256 public depositCallCount;
    uint256 public transferCallCount;
    uint256 public withdrawCallCount;

    function setDepositResult(bool _result) external {
        depositResult = _result;
    }

    function setTransferResult(bool _result) external {
        transferResult = _result;
    }

    function setWithdrawResult(bool _result) external {
        withdrawResult = _result;
    }

    function verifyDeposit(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return depositResult;
    }

    function verifyTransfer(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return transferResult;
    }

    function verifyWithdraw(bytes calldata, bytes32[] calldata) external view override returns (bool) {
        return withdrawResult;
    }

    function incrementDepositCount() external {
        depositCallCount++;
    }

    function incrementTransferCount() external {
        transferCallCount++;
    }

    function incrementWithdrawCount() external {
        withdrawCallCount++;
    }
}

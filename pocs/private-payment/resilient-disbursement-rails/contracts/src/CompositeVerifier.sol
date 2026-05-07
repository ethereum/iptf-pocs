// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {ICompositeVerifier} from "./interfaces/ICompositeVerifier.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

/// @title CompositeVerifier
/// @notice Wraps the two circuit verifiers (claim, pool-withdraw) generated
///         by Noir/Barretenberg behind the ICompositeVerifier facade.
contract CompositeVerifier is ICompositeVerifier {
    address public immutable claimVerifier;
    address public immutable withdrawVerifier;

    error ZeroAddress();

    constructor(address _claimVerifier, address _withdrawVerifier) {
        if (_claimVerifier == address(0) || _withdrawVerifier == address(0)) revert ZeroAddress();
        claimVerifier = _claimVerifier;
        withdrawVerifier = _withdrawVerifier;
    }

    /// @inheritdoc ICompositeVerifier
    function verifyClaim(bytes calldata proof, bytes32[] calldata publicInputs) external override returns (bool) {
        return IVerifier(claimVerifier).verify(proof, publicInputs);
    }

    /// @inheritdoc ICompositeVerifier
    function verifyPoolWithdraw(bytes calldata proof, bytes32[] calldata publicInputs)
        external
        override
        returns (bool)
    {
        return IVerifier(withdrawVerifier).verify(proof, publicInputs);
    }
}

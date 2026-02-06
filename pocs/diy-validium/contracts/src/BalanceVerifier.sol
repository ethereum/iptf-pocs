// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title BalanceVerifier
/// @notice On-chain verifier for RISC Zero balance proofs (Phase 2).
/// @dev See SPEC.md § Phase 2: Balance Proof for the full protocol.
///      Stub implementation — all functions revert or return defaults.
contract BalanceVerifier {
    /// @notice The RISC Zero verifier contract used to validate proofs.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Merkle root of the accounts tree.
    bytes32 public accountsRoot;

    /// @notice Image ID of the guest program. Placeholder until guest ELF is compiled.
    bytes32 public constant IMAGE_ID = bytes32(0);

    /// @notice Emitted when a balance proof is successfully verified.
    event BalanceProofVerified(bytes32 indexed root, uint64 requiredAmount);

    constructor(IRiscZeroVerifier _verifier, bytes32 _accountsRoot) {
        verifier = _verifier;
        accountsRoot = _accountsRoot;
    }

    /// @notice Verify a balance proof against the accounts root.
    /// @param seal The RISC Zero proof seal.
    /// @param journalRoot The Merkle root committed in the proof journal.
    /// @param requiredAmount The minimum balance that must be proven.
    /// @return True if verification succeeds.
    function verifyBalance(bytes calldata seal, bytes32 journalRoot, uint64 requiredAmount)
        external
        view
        returns (bool)
    {
        // Stub: revert so TDD tests fail until implemented.
        revert("Not implemented");
    }
}

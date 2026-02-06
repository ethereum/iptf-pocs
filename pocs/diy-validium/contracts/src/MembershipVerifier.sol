// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title MembershipVerifier
/// @notice On-chain verifier for RISC Zero membership proofs (Phase 1).
/// @dev See SPEC.md § Phase 1: Membership Proof for the full protocol.
contract MembershipVerifier {
    /// @notice The RISC Zero verifier contract used to validate proofs.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Merkle root of the allowlisted addresses.
    bytes32 public allowlistRoot;

    /// @notice Image ID of the guest program. Placeholder until guest ELF is compiled.
    bytes32 public constant IMAGE_ID = bytes32(0);

    /// @notice Tracks used nullifiers to prevent proof replay.
    mapping(bytes32 => bool) public usedNullifiers;

    constructor(IRiscZeroVerifier _verifier, bytes32 _allowlistRoot) {
        verifier = _verifier;
        allowlistRoot = _allowlistRoot;
    }

    /// @notice Verify a membership proof against the allowlist root.
    /// @param seal The RISC Zero proof seal.
    /// @param journalRoot The Merkle root committed in the proof journal.
    /// @return True if verification succeeds.
    function verifyMembership(
        bytes calldata seal,
        bytes32 journalRoot
    ) external returns (bool) {
        require(journalRoot == allowlistRoot, "Root mismatch");

        bytes memory journal = abi.encodePacked(journalRoot);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        return true;
    }
}

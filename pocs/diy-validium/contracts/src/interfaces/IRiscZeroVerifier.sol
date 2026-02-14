// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @notice Minimal interface for the RISC Zero verifier contract.
/// @dev Extracted from risc0-ethereum. Only the `verify` function is needed
/// by MembershipVerifier; Receipt structs and verifyIntegrity are omitted.
interface IRiscZeroVerifier {
    /// @notice Verify a RISC Zero proof.
    /// @param seal The encoded cryptographic proof (SNARK or otherwise).
    /// @param imageId The identifier for the guest program (ELF binary hash).
    /// @param journalDigest The SHA-256 digest of the journal output.
    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external;
}

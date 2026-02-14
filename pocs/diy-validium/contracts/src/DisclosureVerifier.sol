// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title DisclosureVerifier
/// @notice On-chain verifier for RISC Zero disclosure proofs (Phase 4).
/// @dev See SPEC.md § Phase 4: Regulatory Disclosure for the full protocol.
contract DisclosureVerifier {
    /// @notice The RISC Zero verifier contract used to validate proofs.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Merkle root of the current account state.
    bytes32 public stateRoot;

    /// @notice Image ID of the guest program. Placeholder until guest ELF is compiled.
    /// @dev Placeholder — real image ID requires `cargo risczero build` with riscv32im target.
    ///      See SPEC.md Limitations section for the production deployment path.
    bytes32 public constant IMAGE_ID = bytes32(0);

    /// @notice Emitted when a disclosure proof is successfully verified.
    event DisclosureVerified(bytes32 indexed root, uint64 threshold, bytes32 indexed disclosureKeyHash);

    constructor(IRiscZeroVerifier _verifier, bytes32 _stateRoot) {
        verifier = _verifier;
        stateRoot = _stateRoot;
    }

    /// @notice Verify a regulatory disclosure proof without mutating state.
    /// @param seal The RISC Zero proof seal.
    /// @param root The Merkle root committed in the proof.
    /// @param threshold The balance threshold committed in the proof.
    /// @param disclosureKeyHash The hash of the disclosure key committed in the proof.
    function verifyDisclosure(bytes calldata seal, bytes32 root, uint64 threshold, bytes32 disclosureKeyHash) external {
        require(root == stateRoot, "Root mismatch");

        // Journal: root(32) + threshold_be(8) + disclosureKeyHash(32) = 72 bytes
        bytes memory journal = abi.encodePacked(root, threshold, disclosureKeyHash);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        emit DisclosureVerified(root, threshold, disclosureKeyHash);
    }
}

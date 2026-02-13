// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title TransferVerifier
/// @notice On-chain verifier for RISC Zero transfer proofs.
/// @dev See SPEC.md § Transfer for the full protocol.
///      Double-spend prevention relies on sequential root checks:
///      each operation changes stateRoot, making stale proofs instantly invalid.
contract TransferVerifier {
    /// @notice The RISC Zero verifier contract used to validate proofs.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Merkle root of the current account state.
    bytes32 public stateRoot;

    /// @notice Address of the operator who deployed the contract.
    address public operator;

    /// @notice Image ID of the guest program. Placeholder until guest ELF is compiled.
    /// @dev Placeholder — real image ID requires `cargo risczero build` with riscv32im target.
    ///      See SPEC.md Limitations section for the production deployment path.
    bytes32 public constant IMAGE_ID = bytes32(0);

    /// @notice Emitted when oldRoot does not match the current stateRoot.
    error StaleState(bytes32 expected, bytes32 provided);

    /// @notice Emitted when a transfer proof is successfully verified and state is updated.
    event Transfer(bytes32 indexed oldRoot, bytes32 indexed newRoot);

    constructor(IRiscZeroVerifier _verifier, bytes32 _initialRoot) {
        verifier = _verifier;
        stateRoot = _initialRoot;
        operator = msg.sender;
    }

    /// @notice Execute a private transfer by verifying its ZK proof and updating state.
    /// @param seal The RISC Zero proof seal.
    /// @param oldRoot The pre-transition Merkle root committed in the proof.
    /// @param newRoot The post-transition Merkle root committed in the proof.
    function executeTransfer(bytes calldata seal, bytes32 oldRoot, bytes32 newRoot) external {
        if (oldRoot != stateRoot) {
            revert StaleState(stateRoot, oldRoot);
        }

        // Journal encodes: oldRoot (32 bytes) + newRoot (32 bytes)
        bytes memory journal = abi.encodePacked(oldRoot, newRoot);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        stateRoot = newRoot;

        emit Transfer(oldRoot, newRoot);
    }
}

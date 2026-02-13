// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title TransferVerifier
/// @notice On-chain verifier for RISC Zero transfer proofs (Phase 3).
/// @dev See SPEC.md § Phase 3: Private Transfers for the full protocol.
contract TransferVerifier {
    /// @notice The RISC Zero verifier contract used to validate proofs.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Merkle root of the current account state.
    bytes32 public stateRoot;

    /// @notice Tracks used nullifiers to prevent double-spending.
    mapping(bytes32 => bool) public nullifiers;

    /// @notice Address of the operator who deployed the contract.
    address public operator;

    /// @notice Image ID of the guest program. Placeholder until guest ELF is compiled.
    /// @dev Placeholder — real image ID requires `cargo risczero build` with riscv32im target.
    ///      See SPEC.md Limitations section for the production deployment path.
    bytes32 public constant IMAGE_ID = bytes32(0);

    /// @notice Emitted when oldRoot does not match the current stateRoot.
    error StaleState(bytes32 expected, bytes32 provided);

    /// @notice Emitted when a nullifier has already been used.
    error NullifierAlreadyUsed(bytes32 nullifier);

    /// @notice Emitted when a transfer proof is successfully verified and state is updated.
    event Transfer(bytes32 indexed oldRoot, bytes32 indexed newRoot, bytes32 indexed nullifier);

    constructor(IRiscZeroVerifier _verifier, bytes32 _initialRoot) {
        verifier = _verifier;
        stateRoot = _initialRoot;
        operator = msg.sender;
    }

    /// @notice Execute a private transfer by verifying its ZK proof and updating state.
    /// @param seal The RISC Zero proof seal.
    /// @param oldRoot The pre-transition Merkle root committed in the proof.
    /// @param newRoot The post-transition Merkle root committed in the proof.
    /// @param nullifier The nullifier committed in the proof to prevent double-spend.
    function executeTransfer(bytes calldata seal, bytes32 oldRoot, bytes32 newRoot, bytes32 nullifier) external {
        if (oldRoot != stateRoot) {
            revert StaleState(stateRoot, oldRoot);
        }
        if (nullifiers[nullifier]) {
            revert NullifierAlreadyUsed(nullifier);
        }

        // Journal encodes: oldRoot (32 bytes) + newRoot (32 bytes) + nullifier (32 bytes)
        bytes memory journal = abi.encodePacked(oldRoot, newRoot, nullifier);
        verifier.verify(seal, IMAGE_ID, sha256(journal));

        stateRoot = newRoot;
        nullifiers[nullifier] = true;

        emit Transfer(oldRoot, newRoot, nullifier);
    }
}

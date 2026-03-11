// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IVerifier} from "./interfaces/IVerifier.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @title PrivateUTXO
/// @notice Commitment tree + nullifier set with unified transfer supporting lock, claim, refund, and standard transfer
/// @dev Deployed on each chain. Mode discrimination is based on public inputs (timeout + pkStealth + hSwap).
contract PrivateUTXO {
    using LeanIMT for LeanIMTData;

    /// @notice Maximum number of historical roots to store
    uint256 public constant MAX_HISTORICAL_ROOTS = 100;

    /// @notice LeanIMT tree data storage for commitments
    LeanIMTData internal _tree;

    /// @notice Historical roots stored in a circular buffer
    bytes32[100] public historicalRoots;

    /// @notice Current index in the historical roots buffer
    uint256 public historicalRootIndex;

    /// @notice Mapping of root to validity status
    mapping(bytes32 => bool) public validRoots;

    /// @notice Spent nullifiers (double-spend prevention)
    mapping(bytes32 => bool) public nullifiers;

    /// @notice ZK proof verifier
    IVerifier public immutable verifier;

    // Events
    event SwapNoteLocked(
        bytes32 indexed commitment,
        uint256 timeout,
        bytes32 pkStealth,
        bytes32 hSwap,
        bytes32 hR,
        bytes32 hMeta,
        bytes32 hEnc
    );
    event NoteCreated(bytes32 indexed commitment);
    event NoteSpent(bytes32 indexed nullifier);

    /// @notice Contract owner
    address public owner;

    // Errors
    error InvalidProof();
    error NullifierAlreadySpent();
    error InvalidRoot();
    error ClaimExpired();
    error RefundNotReady();
    error OnlyOwner();

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert OnlyOwner();
    }

    constructor(address _verifier) {
        verifier = IVerifier(_verifier);
        owner = msg.sender;
    }

    /// @notice Get the current commitment Merkle root
    function commitmentRoot() public view returns (bytes32) {
        return bytes32(_tree.root());
    }

    /// @notice Get the number of commitments in the tree
    function getCommitmentCount() external view returns (uint256) {
        return _tree.size;
    }

    /// @notice Check if a root is known (current or historical)
    function isKnownRoot(bytes32 root) public view returns (bool) {
        if (root == bytes32(0)) return false;
        if (root == commitmentRoot()) return true;
        return validRoots[root];
    }

    /// @notice PoC-only: insert commitment without proof (initial funding)
    /// @param commitment The note commitment to insert
    function fund(bytes32 commitment) external onlyOwner {
        _insertCommitment(uint256(commitment));
        emit NoteCreated(commitment);
    }

    /// @notice Unified transfer: handles lock, claim, refund, and standard transfer
    /// @param proof ZK proof bytes
    /// @param nullifier Input note nullifier
    /// @param root Merkle root for input note inclusion
    /// @param newCommitment Output note commitment
    /// @param timeout Lock mode: output timeout. Spend mode: input timeout. 0 for standard transfer.
    /// @param pkStealth Lock: stealth x-coord. Claim: in_owner. Refund/Transfer: 0.
    /// @param hSwap Lock: binding commitment. All other modes: 0.
    /// @param hR Lock: binding commitment. All other modes: 0.
    /// @param hMeta Lock: binding commitment. All other modes: 0.
    /// @param hEnc Lock: binding commitment. All other modes: 0.
    function transfer(
        bytes calldata proof,
        bytes32 nullifier,
        bytes32 root,
        bytes32 newCommitment,
        uint256 timeout,
        bytes32 pkStealth,
        bytes32 hSwap,
        bytes32 hR,
        bytes32 hMeta,
        bytes32 hEnc
    ) external {
        // Validate root
        if (!isKnownRoot(root)) revert InvalidRoot();

        // Check nullifier hasn't been spent
        if (nullifiers[nullifier]) revert NullifierAlreadySpent();

        // Build public inputs for verification
        bytes32[] memory publicInputs = new bytes32[](9);
        publicInputs[0] = nullifier;
        publicInputs[1] = root;
        publicInputs[2] = newCommitment;
        publicInputs[3] = bytes32(timeout);
        publicInputs[4] = pkStealth;
        publicInputs[5] = hSwap;
        publicInputs[6] = hR;
        publicInputs[7] = hMeta;
        publicInputs[8] = hEnc;

        // Verify proof
        if (!verifier.verify(proof, publicInputs)) revert InvalidProof();

        // Mode discrimination & timeout enforcement
        if (timeout > 0) {
            if (pkStealth != bytes32(0)) {
                if (hSwap == bytes32(0)) {
                    // Claim mode: require block.timestamp <= timeout
                    if (block.timestamp > timeout) revert ClaimExpired();
                }
                // Lock mode (hSwap != 0): no time check
            } else {
                // Refund mode: require block.timestamp > timeout
                if (block.timestamp <= timeout) revert RefundNotReady();
            }
        }
        // timeout == 0: standard transfer, no time check

        // Mark nullifier as spent
        nullifiers[nullifier] = true;

        // Insert output commitment
        _insertCommitment(uint256(newCommitment));

        // Emit events
        if (timeout > 0 && pkStealth != bytes32(0) && hSwap != bytes32(0)) {
            emit SwapNoteLocked(newCommitment, timeout, pkStealth, hSwap, hR, hMeta, hEnc);
        }

        emit NoteCreated(newCommitment);
        emit NoteSpent(nullifier);
    }

    /// @notice Insert a commitment and track the root
    function _insertCommitment(uint256 commitment) internal {
        // Store current root as historical before inserting
        bytes32 currentRoot = commitmentRoot();
        if (currentRoot != bytes32(0)) {
            // Evict the old root being overwritten from the valid set
            bytes32 evictedRoot = historicalRoots[historicalRootIndex];
            if (evictedRoot != bytes32(0)) {
                delete validRoots[evictedRoot];
            }

            validRoots[currentRoot] = true;
            historicalRoots[historicalRootIndex] = currentRoot;
            historicalRootIndex = (historicalRootIndex + 1) % MAX_HISTORICAL_ROOTS;
        }

        // Insert the new commitment
        _tree.insert(commitment);
    }
}

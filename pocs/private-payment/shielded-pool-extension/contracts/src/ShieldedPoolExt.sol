// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @title ShieldedPoolExt
/// @notice Privacy-preserving payment pool extended with epoch-based nullifiers
///         and PIR-served reads (research prototype). See ../../SPEC.md.
/// @dev Current scope: deposits + epoch rollover. `currentEpoch` advances via
///      `rolloverEpoch()`, freezing each epoch's active-nullifier root. The
///      two-proof spend path (wallet spend proof + relayer insertion proof) that
///      advances `activeNullifierRoot`/`activeLeafCount` arrives in a later slice.
contract ShieldedPoolExt {
    using SafeERC20 for IERC20;
    using LeanIMT for LeanIMTData;

    /// @notice Maximum number of historical commitment roots retained.
    uint256 public constant MAX_HISTORICAL_ROOTS = 100;

    /// @notice LeanIMT commitment tree (append-only; membership only).
    LeanIMTData internal _tree;

    // Historical commitment-root buffer. Deposits populate it now; it is
    // *consumed* at spend time, when transfer/withdraw verify a proof against a
    // recent root (Slice 1.5c). Recorded by the deposit path here so the root
    // history is already in place when the spend path lands.
    /// @notice Historical commitment roots (circular buffer).
    bytes32[100] public historicalRoots;
    /// @notice Next write index into the historical-roots buffer.
    uint256 public historicalRootIndex;
    /// @notice Superseded commitment roots still accepted in proofs.
    mapping(bytes32 => bool) public validRoots;

    /// @notice Tokens accepted by the pool.
    mapping(address => bool) public supportedTokens;

    /// @notice Verifier for the deposit proof (IVerifier.verify).
    IVerifier public depositVerifier;

    /// @notice Contract owner (PoC: also the epoch-rollover trigger in later slices).
    address public owner;

    /// @notice Current epoch, bound into each deposited note's commitment as
    ///         `epoch_created`. Advanced by `rolloverEpoch()`.
    uint64 public currentEpoch;

    /// @notice Frozen active-nullifier-tree root per past epoch `e`.
    mapping(uint64 => bytes32) public frozenNullifierRoots;

    /// @notice Root of the current epoch's active nullifier tree. Advanced by the
    ///         spend path (later slice); reset to `emptyImtRoot` on rollover.
    bytes32 public activeNullifierRoot;

    /// @notice Next free leaf index in the active nullifier tree (canonical append
    ///         index). Starts at 1: index 0 is the indexed tree's genesis leaf
    ///         (the bootstrap low-leaf for sorted-low-leaf insertion), so real
    ///         nullifiers append from index 1. NB: the SPEC's rolloverEpoch
    ///         pseudocode resets this to 0; the genesis-leaf bootstrap makes 1 the
    ///         correct value (reconciliation flagged in review).
    uint64 public activeLeafCount;

    /// @notice Root of an empty active nullifier tree (genesis-leaf-only tree).
    ///         The SPEC's `EMPTY_IMT_ROOT`; fixed at deployment.
    bytes32 public immutable emptyImtRoot;

    event Deposit(bytes32 indexed commitment, address indexed token, uint256 amount, bytes encryptedNote);
    event EpochRollover(uint64 indexed epoch, bytes32 root);
    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event DepositVerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error OnlyOwner();
    error UnsupportedToken();
    error ZeroAmount();
    error InvalidProof();
    error ZeroAddress();
    error TokenAlreadySupported();
    error TokenNotSupported();

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) revert OnlyOwner();
    }

    constructor(address _depositVerifier, bytes32 _emptyImtRoot) {
        if (_depositVerifier == address(0)) revert ZeroAddress();
        depositVerifier = IVerifier(_depositVerifier);
        emptyImtRoot = _emptyImtRoot;
        activeNullifierRoot = _emptyImtRoot;
        activeLeafCount = 1; // index 0 is the indexed tree's genesis leaf
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Current commitment-tree root.
    function commitmentRoot() public view returns (bytes32) {
        return bytes32(_tree.root());
    }

    /// @notice Number of commitments inserted into the tree.
    function getCommitmentCount() external view returns (uint256) {
        return _tree.size;
    }

    /// @notice Deposit tokens, minting a note committed at the current epoch.
    /// @dev Deposit-proof public inputs are [commitment, token, amount, currentEpoch].
    ///      The contract supplies `currentEpoch` as the final input, so a valid
    ///      proof enforces `epoch_created == currentEpoch` on the new commitment.
    /// @param proof Deposit ZK proof.
    /// @param commitment The note commitment (binds `epoch_created`).
    /// @param token ERC-20 token address.
    /// @param amount Amount to deposit.
    /// @param encryptedNote Encrypted note payload for viewing-key holders.
    function deposit(
        bytes calldata proof,
        bytes32 commitment,
        address token,
        uint256 amount,
        bytes calldata encryptedNote
    ) external {
        if (!supportedTokens[token]) revert UnsupportedToken();
        if (amount == 0) revert ZeroAmount();

        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = commitment;
        publicInputs[1] = bytes32(uint256(uint160(token)));
        publicInputs[2] = bytes32(amount);
        publicInputs[3] = bytes32(uint256(currentEpoch));

        if (!depositVerifier.verify(proof, publicInputs)) revert InvalidProof();

        _insertCommitment(uint256(commitment));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        emit Deposit(commitment, token, amount, encryptedNote);
    }

    /// @notice Roll over to the next epoch: freeze the current active-nullifier
    ///         root and reset the active tree. PoC: owner-only; production would
    ///         use a decentralized trigger.
    /// @dev Emits `EpochRollover(frozenEpoch, frozenRoot)`.
    function rolloverEpoch() external onlyOwner {
        uint64 frozenEpoch = currentEpoch;
        bytes32 frozenRoot = activeNullifierRoot;

        frozenNullifierRoots[frozenEpoch] = frozenRoot;
        activeNullifierRoot = emptyImtRoot;
        activeLeafCount = 1;
        currentEpoch = frozenEpoch + 1;

        emit EpochRollover(frozenEpoch, frozenRoot);
    }

    /// @notice Add a supported token.
    function addSupportedToken(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (supportedTokens[token]) revert TokenAlreadySupported();
        supportedTokens[token] = true;
        emit TokenAdded(token);
    }

    /// @notice Remove a supported token.
    function removeSupportedToken(address token) external onlyOwner {
        if (!supportedTokens[token]) revert TokenNotSupported();
        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /// @notice True if `root` is the current or a retained historical root.
    function isKnownRoot(bytes32 root) public view returns (bool) {
        if (root == commitmentRoot()) return true;
        return validRoots[root];
    }

    /// @notice Update the deposit verifier.
    function setDepositVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        emit DepositVerifierUpdated(address(depositVerifier), newVerifier);
        depositVerifier = IVerifier(newVerifier);
    }

    /// @notice Transfer ownership of the contract.
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @dev Insert a commitment, retaining the superseded root as historical.
    function _insertCommitment(uint256 commitment) internal {
        bytes32 currentRoot = commitmentRoot();
        if (currentRoot != bytes32(0)) {
            bytes32 evictedRoot = historicalRoots[historicalRootIndex];
            if (evictedRoot != bytes32(0)) {
                delete validRoots[evictedRoot];
            }
            validRoots[currentRoot] = true;
            historicalRoots[historicalRootIndex] = currentRoot;
            historicalRootIndex = (historicalRootIndex + 1) % MAX_HISTORICAL_ROOTS;
        }
        _tree.insert(commitment);
    }
}

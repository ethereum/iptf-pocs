// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";
import {IAttestationRegistry} from "./interfaces/IAttestationRegistry.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

/// @title ShieldedPool
/// @notice Privacy-preserving payment pool with KYC-gated entry
/// @dev Implements UTXO model with commitments/nullifiers for unlinkable transfers
contract ShieldedPool {
    using SafeERC20 for IERC20;
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

    /// @notice Supported tokens for the pool
    mapping(address => bool) public supportedTokens;

    /// @notice ZK proof verifier
    IVerifier public verifier;

    /// @notice Attestation registry for KYC verification
    IAttestationRegistry public attestationRegistry;

    /// @notice Contract owner
    address public owner;

    // Events
    event Deposit(bytes32 indexed commitment, address indexed token, uint256 amount, bytes encryptedNote);
    event Transfer(
        bytes32 indexed nullifier1,
        bytes32 indexed nullifier2,
        bytes32 commitment1,
        bytes32 commitment2,
        bytes encryptedNotes
    );
    event Withdraw(bytes32 indexed nullifier, address indexed recipient, address indexed token, uint256 amount);
    event TokenAdded(address indexed token);
    event TokenRemoved(address indexed token);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);
    event AttestationRegistryUpdated(address indexed oldRegistry, address indexed newRegistry);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    // Errors
    error OnlyOwner();
    error UnsupportedToken();
    error ZeroAmount();
    error InvalidProof();
    error NullifierAlreadySpent();
    error IdenticalNullifiers();
    error InvalidRoot();
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

    constructor(address _verifier, address _attestationRegistry) {
        if (_verifier == address(0) || _attestationRegistry == address(0)) {
            revert ZeroAddress();
        }
        verifier = IVerifier(_verifier);
        attestationRegistry = IAttestationRegistry(_attestationRegistry);
        owner = msg.sender;
        // LeanIMT doesn't require explicit initialization
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Get the current commitment Merkle root
    /// @return The current root of the commitment tree
    function commitmentRoot() public view returns (bytes32) {
        return bytes32(_tree.root());
    }

    /// @notice Get the number of commitments in the tree
    /// @return The commitment count
    function getCommitmentCount() external view returns (uint256) {
        return _tree.size;
    }

    /// @notice Deposit tokens into the shielded pool
    /// @param proof ZK proof of valid deposit
    /// @param commitment The note commitment
    /// @param token ERC-20 token address
    /// @param amount Amount to deposit
    /// @param encryptedNote Encrypted note for viewing key holders
    function deposit(
        bytes calldata proof,
        bytes32 commitment,
        address token,
        uint256 amount,
        bytes calldata encryptedNote
    ) external {
        if (!supportedTokens[token]) revert UnsupportedToken();
        if (amount == 0) revert ZeroAmount();

        // Build public inputs for verification
        bytes32[] memory publicInputs = new bytes32[](4);
        publicInputs[0] = commitment;
        publicInputs[1] = bytes32(uint256(uint160(token)));
        publicInputs[2] = bytes32(amount);
        publicInputs[3] = attestationRegistry.attestationRoot();

        // Verify the deposit proof
        if (!verifier.verifyDeposit(proof, publicInputs)) revert InvalidProof();

        // Add commitment to tree and update root tracking
        _insertCommitment(uint256(commitment));

        // Transfer tokens from sender to pool
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        emit Deposit(commitment, token, amount, encryptedNote);
    }

    /// @notice Transfer notes within the shielded pool (2-in-2-out)
    /// @param proof ZK proof of valid transfer
    /// @param inputNullifiers Nullifiers for the two input notes
    /// @param outputCommitments Commitments for the two output notes
    /// @param root Commitment tree root used for the proof
    /// @param encryptedNotes Encrypted notes for viewing key holders
    function transfer(
        bytes calldata proof,
        bytes32[2] calldata inputNullifiers,
        bytes32[2] calldata outputCommitments,
        bytes32 root,
        bytes calldata encryptedNotes
    ) external {
        // Check nullifiers are not identical
        if (inputNullifiers[0] == inputNullifiers[1]) {
            revert IdenticalNullifiers();
        }

        // Check nullifiers haven't been spent
        if (nullifiers[inputNullifiers[0]]) revert NullifierAlreadySpent();
        if (nullifiers[inputNullifiers[1]]) revert NullifierAlreadySpent();

        // Verify root is valid (current or historical)
        if (!isKnownRoot(root)) revert InvalidRoot();

        // Build public inputs for verification
        bytes32[] memory publicInputs = new bytes32[](5);
        publicInputs[0] = inputNullifiers[0];
        publicInputs[1] = inputNullifiers[1];
        publicInputs[2] = outputCommitments[0];
        publicInputs[3] = outputCommitments[1];
        publicInputs[4] = root;

        // Verify the transfer proof
        if (!verifier.verifyTransfer(proof, publicInputs)) {
            revert InvalidProof();
        }

        // Mark nullifiers as spent
        nullifiers[inputNullifiers[0]] = true;
        nullifiers[inputNullifiers[1]] = true;

        // Add new commitments
        _insertCommitment(uint256(outputCommitments[0]));
        _insertCommitment(uint256(outputCommitments[1]));

        emit Transfer(
            inputNullifiers[0], inputNullifiers[1], outputCommitments[0], outputCommitments[1], encryptedNotes
        );
    }

    /// @notice Withdraw tokens from the shielded pool
    /// @param proof ZK proof of valid withdrawal
    /// @param nullifier Nullifier for the note being spent
    /// @param token ERC-20 token address
    /// @param amount Amount to withdraw
    /// @param recipient Address to receive tokens
    /// @param root Commitment tree root used for the proof
    function withdraw(
        bytes calldata proof,
        bytes32 nullifier,
        address token,
        uint256 amount,
        address recipient,
        bytes32 root
    ) external {
        if (!supportedTokens[token]) revert UnsupportedToken();
        if (amount == 0) revert ZeroAmount();
        if (recipient == address(0)) revert ZeroAddress();

        // Check nullifier hasn't been spent
        if (nullifiers[nullifier]) revert NullifierAlreadySpent();

        // Verify root is valid
        if (!isKnownRoot(root)) revert InvalidRoot();

        // Build public inputs for verification
        bytes32[] memory publicInputs = new bytes32[](5);
        publicInputs[0] = nullifier;
        publicInputs[1] = bytes32(uint256(uint160(token)));
        publicInputs[2] = bytes32(amount);
        publicInputs[3] = bytes32(uint256(uint160(recipient)));
        publicInputs[4] = root;

        // Verify the withdraw proof
        if (!verifier.verifyWithdraw(proof, publicInputs)) {
            revert InvalidProof();
        }

        // Mark nullifier as spent
        nullifiers[nullifier] = true;

        // Transfer tokens to recipient (checks-effects-interactions)
        IERC20(token).safeTransfer(recipient, amount);

        emit Withdraw(nullifier, recipient, token, amount);
    }

    /// @notice Add a supported token
    /// @param token ERC-20 token address to add
    function addSupportedToken(address token) external onlyOwner {
        if (token == address(0)) revert ZeroAddress();
        if (supportedTokens[token]) revert TokenAlreadySupported();

        supportedTokens[token] = true;
        emit TokenAdded(token);
    }

    /// @notice Remove a supported token
    /// @param token ERC-20 token address to remove
    function removeSupportedToken(address token) external onlyOwner {
        if (!supportedTokens[token]) revert TokenNotSupported();

        supportedTokens[token] = false;
        emit TokenRemoved(token);
    }

    /// @notice Check if a root is known (current or historical)
    /// @param root The root to check
    /// @return True if the root is valid
    function isKnownRoot(bytes32 root) public view returns (bool) {
        if (root == commitmentRoot()) return true;
        return validRoots[root];
    }

    /// @notice Update the verifier address
    /// @param newVerifier New verifier contract address
    function setVerifier(address newVerifier) external onlyOwner {
        if (newVerifier == address(0)) revert ZeroAddress();
        emit VerifierUpdated(address(verifier), newVerifier);
        verifier = IVerifier(newVerifier);
    }

    /// @notice Update the attestation registry address
    /// @param newRegistry New attestation registry address
    function setAttestationRegistry(address newRegistry) external onlyOwner {
        if (newRegistry == address(0)) revert ZeroAddress();
        emit AttestationRegistryUpdated(address(attestationRegistry), newRegistry);
        attestationRegistry = IAttestationRegistry(newRegistry);
    }

    /// @notice Transfer ownership of the contract
    /// @param newOwner Address of the new owner
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }

    /// @notice Insert a commitment and track the root
    /// @param commitment The commitment value to insert
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

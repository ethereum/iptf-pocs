// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "forge-std/src/interfaces/IERC20.sol";
import {IRiscZeroVerifier} from "./interfaces/IRiscZeroVerifier.sol";

/// @title ValidiumBridge
/// @notice Bridge contract for depositing and withdrawing ERC20 tokens using
///         RISC Zero ZK proofs for membership verification and withdrawal authorization.
/// @dev See SPEC.md for the full protocol specification.
///      Double-spend prevention relies on sequential root checks:
///      each operation changes stateRoot, making stale proofs instantly invalid.
contract ValidiumBridge {
    // TODO: Production should use OpenZeppelin SafeERC20 for safe token transfers
    // See: https://docs.openzeppelin.com/contracts/5.x/api/token/erc20#SafeERC20

    /// @notice The ERC20 token managed by this bridge.
    IERC20 public immutable token;

    /// @notice The RISC Zero verifier contract used to validate proofs.
    IRiscZeroVerifier public immutable verifier;

    /// @notice Merkle root of the current account state.
    bytes32 public stateRoot;

    /// @notice Address of the operator who deployed the contract.
    address public operator;

    /// @notice Merkle root of the allowlist used for membership verification.
    bytes32 public allowlistRoot;

    /// @notice Image ID for the membership proof guest program. Placeholder until guest ELF is compiled.
    /// @dev Placeholder — real image ID requires `cargo risczero build` with riscv32im target.
    ///      See SPEC.md Limitations section for the production deployment path.
    bytes32 public constant MEMBERSHIP_IMAGE_ID = bytes32(0);

    /// @notice Image ID for the withdrawal proof guest program. Placeholder until guest ELF is compiled.
    /// @dev Placeholder — real image ID requires `cargo risczero build` with riscv32im target.
    ///      See SPEC.md Limitations section for the production deployment path.
    bytes32 public constant WITHDRAWAL_IMAGE_ID = bytes32(0);

    /// @notice Emitted when oldRoot does not match the current stateRoot.
    error StaleState(bytes32 expected, bytes32 provided);

    /// @notice Emitted when amount is zero.
    error InvalidAmount();

    /// @notice Emitted when a deposit is made.
    event Deposit(address indexed depositor, bytes32 pubkey, uint256 amount);

    /// @notice Emitted when a withdrawal is made.
    event Withdrawal(address indexed recipient, uint256 amount);

    constructor(IERC20 _token, IRiscZeroVerifier _verifier, bytes32 _initialRoot, bytes32 _allowlistRoot) {
        token = _token;
        verifier = _verifier;
        stateRoot = _initialRoot;
        allowlistRoot = _allowlistRoot;
        operator = msg.sender;
    }

    /// @notice Deposit tokens into the bridge after verifying membership proof.
    /// @param amount The number of tokens to deposit.
    /// @param pubkey The depositor's public key for the off-chain account.
    /// @param membershipSeal The RISC Zero proof seal for membership verification.
    function deposit(uint256 amount, bytes32 pubkey, bytes calldata membershipSeal) external {
        if (amount == 0) revert InvalidAmount();

        // Verify membership proof: journal = abi.encodePacked(allowlistRoot)
        bytes memory membershipJournal = abi.encodePacked(allowlistRoot);
        verifier.verify(membershipSeal, MEMBERSHIP_IMAGE_ID, sha256(membershipJournal));

        require(token.transferFrom(msg.sender, address(this), amount), "Deposit transfer failed");

        emit Deposit(msg.sender, pubkey, amount);
    }

    /// @notice Withdraw tokens from the bridge by verifying a withdrawal proof.
    /// @param seal The RISC Zero proof seal.
    /// @param oldRoot The pre-transition Merkle root committed in the proof.
    /// @param newRoot The post-transition Merkle root committed in the proof.
    /// @param amount The amount of tokens to withdraw (uint64 for 8-byte big-endian journal encoding).
    /// @param recipient The address to receive the withdrawn tokens.
    function withdraw(bytes calldata seal, bytes32 oldRoot, bytes32 newRoot, uint64 amount, address recipient)
        external
    {
        if (oldRoot != stateRoot) revert StaleState(stateRoot, oldRoot);
        if (amount == 0) revert InvalidAmount();

        // Journal: oldRoot (32) + newRoot (32) + amount (8) + recipient (20) = 92 bytes
        bytes memory journal = abi.encodePacked(oldRoot, newRoot, amount, recipient);
        verifier.verify(seal, WITHDRAWAL_IMAGE_ID, sha256(journal));

        // CEI: effects before interaction
        stateRoot = newRoot;

        require(token.transfer(recipient, amount), "Withdrawal transfer failed");

        emit Withdrawal(recipient, amount);
    }
}

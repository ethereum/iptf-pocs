// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {IPool} from "./interfaces/IPool.sol";
import {IRegistry} from "./interfaces/IRegistry.sol";

/// @notice Round header signed by the funder out-of-band. `firstPoolLeafIndex`
///         is NOT part of `H_header`; it is set atomically by the factory at
///         publication and registered with the claim contract.
/// @dev    `closeTime` is a unix timestamp in seconds (uint64).
struct RoundHeader {
    uint256 roundId;
    uint64 cohortVersion;
    uint256 cohortRoot;
    uint256 perRecipientAmount;
    uint256 cohortSize;
    address token;
    uint64 closeTime;
    address claimContractAddress;
    uint256 chainId;
}

/// @notice Minimal interface for the claim contract's `registerHeader`.
interface IClaimContract {
    function registerHeader(RoundHeader calldata h, uint64 firstPoolLeafIndex) external;

    function pool() external view returns (address);

    function token() external view returns (address);
}

/// @title RoundFactory
/// @notice Atomic shield-and-publish for a round. All-or-nothing: any
///         deposit revert reverts the entire `publishRound` call.
contract RoundFactory {
    using SafeERC20 for IERC20;

    IRegistry public immutable registry;
    IPool public immutable pool;
    IClaimContract public immutable claimContract;
    IERC20 public immutable token;
    address public immutable funderMultisig;

    /// @notice DOMAIN_HEADER = SHA256("RDR/header/v1") (off-chain pinned).
    bytes32 public constant DOMAIN_HEADER = sha256("RDR/header/v1");

    /// @notice Per-roundId publication marker (reverts collisions).
    mapping(uint256 => bool) public published;

    event RoundPublished(
        uint256 indexed roundId,
        uint64 cohortVersion,
        uint256 cohortRoot,
        uint256 perRecipientAmount,
        uint256 cohortSize,
        address token,
        uint64 closeTime,
        address claimContractAddress,
        uint256 chainId,
        uint64 firstPoolLeafIndex,
        bytes32 hHeader
    );

    error NotFunderMultisig();
    error CohortRootMismatch();
    error CohortSizeMismatch();
    error WrongChainId();
    error WrongClaimContract();
    error WrongCommitmentCount();
    error WrongToken();
    error RoundIdCollision();
    error ZeroAddress();
    error ZeroAmount();

    constructor(address _registry, address _pool, address _claimContract, address _token, address _funderMultisig) {
        if (
            _registry == address(0) || _pool == address(0) || _claimContract == address(0) || _token == address(0)
                || _funderMultisig == address(0)
        ) revert ZeroAddress();

        registry = IRegistry(_registry);
        pool = IPool(_pool);
        claimContract = IClaimContract(_claimContract);
        token = IERC20(_token);
        funderMultisig = _funderMultisig;
    }

    /// @notice Atomically publish a round.
    /// @dev Steps in strict order per SPEC Round Publication:
    ///        1. Authorize msg.sender == funderMultisig.
    ///        2. Read cohortRoot / cohortSize from registry; assert header.
    ///        3. Assert chainId, token, claimContract bindings.
    ///        4. Pull perRecipientAmount * cohortSize tokens from funder.
    ///        5. Approve pool.
    ///        6. Capture firstPoolLeafIndex BEFORE deposit loop.
    ///        7. Deposit each commitment.
    ///        8. Register header (with firstPoolLeafIndex) on claim contract.
    ///        9. Emit RoundPublished.
    /// @param header The round header signed off-band by the funder multisig.
    /// @param commitments Per-recipient commitments in cohort-position order.
    function publishRound(RoundHeader calldata header, uint256[] calldata commitments) external {
        if (msg.sender != funderMultisig) revert NotFunderMultisig();

        // Cohort identity bindings.
        if (registry.cohortRoot(header.cohortVersion) != header.cohortRoot) {
            revert CohortRootMismatch();
        }
        if (registry.cohortSize(header.cohortVersion) != header.cohortSize) {
            revert CohortSizeMismatch();
        }
        if (commitments.length != header.cohortSize) {
            revert WrongCommitmentCount();
        }
        if (header.cohortSize == 0) revert ZeroAmount();
        if (header.perRecipientAmount == 0) revert ZeroAmount();

        // Chain / token / claim contract bindings.
        if (header.chainId != block.chainid) revert WrongChainId();
        if (header.token != address(token)) revert WrongToken();
        if (header.claimContractAddress != address(claimContract)) {
            revert WrongClaimContract();
        }

        // RoundId collision protection (factory side).
        if (published[header.roundId]) revert RoundIdCollision();
        published[header.roundId] = true;

        uint256 totalAmount = header.perRecipientAmount * header.cohortSize;

        // Pull from funder.
        token.safeTransferFrom(msg.sender, address(this), totalAmount);

        // Approve pool to draw exactly totalAmount.
        token.forceApprove(address(pool), totalAmount);

        // Capture firstPoolLeafIndex BEFORE the deposit loop (Design Z prime).
        uint64 firstPoolLeafIndex = uint64(_subTreeSize());

        // Deposit each commitment.
        for (uint256 i = 0; i < commitments.length; i++) {
            pool.deposit(address(claimContract), commitments[i], header.perRecipientAmount, header.roundId);
        }

        // Register header on the claim contract atomically.
        claimContract.registerHeader(header, firstPoolLeafIndex);

        bytes32 hHeader = _computeHHeader(header);

        _emitRoundPublished(header, firstPoolLeafIndex, hHeader);
    }

    function _computeHHeader(RoundHeader calldata header) public pure returns (bytes32) {
        bytes memory body = abi.encodePacked(
            header.roundId,
            header.cohortVersion,
            header.cohortRoot,
            header.perRecipientAmount,
            uint64(header.cohortSize),
            header.token,
            header.closeTime,
            header.claimContractAddress,
            header.chainId
        );
        return sha256(abi.encodePacked(DOMAIN_HEADER, body));
    }

    function _emitRoundPublished(RoundHeader calldata header, uint64 firstPoolLeafIndex, bytes32 hHeader) internal {
        emit RoundPublished(
            header.roundId,
            header.cohortVersion,
            header.cohortRoot,
            header.perRecipientAmount,
            header.cohortSize,
            header.token,
            header.closeTime,
            header.claimContractAddress,
            header.chainId,
            firstPoolLeafIndex,
            hHeader
        );
    }

    /// @dev Read pool sub-tree size via the pool's optional view; falls back
    ///      to the IPool view path if the pool doesn't expose it directly.
    function _subTreeSize() internal view returns (uint256) {
        // The IPool interface doesn't include subTreeSize; use staticcall to
        // a known selector from ShieldedPool. If absent, the call reverts.
        (bool ok, bytes memory ret) =
            address(pool).staticcall(abi.encodeWithSignature("subTreeSize(address)", address(claimContract)));
        require(ok && ret.length == 32, "pool.subTreeSize() missing");
        return abi.decode(ret, (uint256));
    }
}

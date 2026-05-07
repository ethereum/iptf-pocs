// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {IPool} from "./interfaces/IPool.sol";
import {ICompositeVerifier} from "./interfaces/ICompositeVerifier.sol";
import {RoundHeader} from "./RoundFactory.sol";

/// @notice Indexes into the claim circuit's 10 public inputs. Order MUST
///         match `circuits/claim/src/main.nr` `main(...)` parameter order.
library ClaimPublicInputs {
    uint256 internal constant ROUND_ID_HI = 0;
    uint256 internal constant ROUND_ID_LO = 1;
    uint256 internal constant COHORT_ROOT = 2;
    uint256 internal constant CHAIN_ID_HI = 3;
    uint256 internal constant CHAIN_ID_LO = 4;
    uint256 internal constant DESTINATION = 5;
    uint256 internal constant AMOUNT = 6;
    uint256 internal constant NULLIFIER = 7;
    uint256 internal constant CLAIM_CONTRACT_ADDRESS = 8;
    uint256 internal constant RELAY_SUBMITTER = 9;
    uint256 internal constant LENGTH = 10;
}

/// @notice Indexes into the pool-withdraw circuit's 5 public inputs.
library PoolPublicInputs {
    uint256 internal constant POOL_ROOT = 0;
    uint256 internal constant CLAIM_NULLIFIER = 1;
    uint256 internal constant TOKEN = 2;
    uint256 internal constant AMOUNT = 3;
    uint256 internal constant RECIPIENT = 4;
    uint256 internal constant LENGTH = 5;
}

/// @title ClaimContract
/// @notice Verifies relay claim proofs and orchestrates pool unshield with
///         strict cross-proof binding (Design Z prime).
contract ClaimContract {
    /// @notice Per-round registered header.
    mapping(uint256 => RoundHeader) public header;

    /// @notice Per-round firstPoolLeafIndex set by the factory.
    mapping(uint256 => uint64) public firstPoolLeafIndex;

    /// @notice Set true once registerHeader records a roundId.
    mapping(uint256 => bool) public roundRegistered;

    /// @notice Per-claim_nullifier consumed flag.
    mapping(uint256 => bool) public nullifierConsumed;

    /// @notice Per-round count of consumed nullifiers (for residual calc).
    mapping(uint256 => uint256) public nullifiersConsumedCount;

    /// @notice Per-round residual paid flag.
    mapping(uint256 => bool) public residualPaid;

    address public funderMultisig;
    address public factory;
    IPool public pool;
    ICompositeVerifier public verifier;
    IERC20 public token;
    address public funderResidualDestination;
    address public governance;

    /// @notice Residual recovery timelock (seconds). 30 days.
    uint256 public constant RESIDUAL_TIMELOCK_SECONDS = 30 days;

    event Claimed(
        uint256 indexed roundId,
        uint256 indexed claimNullifier,
        address indexed destination,
        uint256 amount,
        address relaySubmitter
    );
    event RoundRegistered(uint256 indexed roundId, uint64 firstPoolLeafIndex);
    event ResidualRecovered(uint256 indexed roundId, uint256 amount, address indexed destination);
    event FactorySet(address indexed factory);
    event PoolSet(address indexed pool);
    event VerifierSet(address indexed verifier);
    event TokenSet(address indexed token);
    event FunderMultisigSet(address indexed multisig);
    event ResidualDestinationSet(address indexed destination);

    error NotFactory();
    error NotMultisig();
    error NotGovernance();
    error RoundClosed();
    error RoundOpen();
    error BadHeaderBinding();
    error BadChainId();
    error BadRelaySubmitter();
    error NullifierConsumed();
    error RoundIdCollision();
    error RoundNotRegistered();
    error BadPoolBinding();
    error InvalidClaimProof();
    error ResidualAlreadyPaid();
    error ZeroAddress();
    error AlreadyConfigured();
    error PublicInputsLengthMismatch();
    error LimbOutOfRange();
    error AmountOverflow();

    constructor(address _governance) {
        if (_governance == address(0)) revert ZeroAddress();
        governance = _governance;
    }

    // Wiring (one-shot, governance-only)

    function setFactory(address _factory) external {
        if (msg.sender != governance) revert NotGovernance();
        if (factory != address(0)) revert AlreadyConfigured();
        if (_factory == address(0)) revert ZeroAddress();
        factory = _factory;
        emit FactorySet(_factory);
    }

    function setPool(address _pool) external {
        if (msg.sender != governance) revert NotGovernance();
        if (address(pool) != address(0)) revert AlreadyConfigured();
        if (_pool == address(0)) revert ZeroAddress();
        pool = IPool(_pool);
        emit PoolSet(_pool);
    }

    function setVerifier(address _verifier) external {
        if (msg.sender != governance) revert NotGovernance();
        if (address(verifier) != address(0)) revert AlreadyConfigured();
        if (_verifier == address(0)) revert ZeroAddress();
        verifier = ICompositeVerifier(_verifier);
        emit VerifierSet(_verifier);
    }

    function setToken(address _token) external {
        if (msg.sender != governance) revert NotGovernance();
        if (address(token) != address(0)) revert AlreadyConfigured();
        if (_token == address(0)) revert ZeroAddress();
        token = IERC20(_token);
        emit TokenSet(_token);
    }

    function setFunderMultisig(address _funderMultisig) external {
        if (msg.sender != governance) revert NotGovernance();
        if (funderMultisig != address(0)) revert AlreadyConfigured();
        if (_funderMultisig == address(0)) revert ZeroAddress();
        funderMultisig = _funderMultisig;
        emit FunderMultisigSet(_funderMultisig);
    }

    function setFunderResidualDestination(address _destination) external {
        if (msg.sender != governance) revert NotGovernance();
        if (funderResidualDestination != address(0)) revert AlreadyConfigured();
        if (_destination == address(0)) revert ZeroAddress();
        funderResidualDestination = _destination;
        emit ResidualDestinationSet(_destination);
    }

    // Factory entry point

    function registerHeader(RoundHeader calldata h, uint64 _firstPoolLeafIndex) external {
        if (msg.sender != factory) revert NotFactory();
        if (roundRegistered[h.roundId]) revert RoundIdCollision();

        roundRegistered[h.roundId] = true;
        header[h.roundId] = h;
        firstPoolLeafIndex[h.roundId] = _firstPoolLeafIndex;

        emit RoundRegistered(h.roundId, _firstPoolLeafIndex);
    }

    // Claim

    /// @notice Submit a claim. Verifies the claim proof, the pool-withdraw
    ///         proof's public inputs (cross-proof binding), and orchestrates
    ///         the pool unshield. Sets nullifierConsumed atomically.
    function claim(
        bytes calldata claimProof,
        uint256[10] calldata claimPublicInputs,
        bytes calldata poolWithdrawProof,
        uint256[5] calldata poolPublicInputs
    ) external {
        uint256 roundId = _decodeRoundId(claimPublicInputs);

        if (!roundRegistered[roundId]) revert RoundNotRegistered();
        RoundHeader memory h = header[roundId];

        if (block.timestamp >= h.closeTime) revert RoundClosed();

        _assertChainId(claimPublicInputs, h.chainId);
        _assertHeaderBindings(claimPublicInputs, h);

        if (claimPublicInputs[ClaimPublicInputs.RELAY_SUBMITTER] != uint256(uint160(msg.sender))) {
            revert BadRelaySubmitter();
        }

        uint256 destInt = claimPublicInputs[ClaimPublicInputs.DESTINATION];
        if (destInt >= (1 << 160)) revert LimbOutOfRange();
        address destination = address(uint160(destInt));
        uint256 nullifier = claimPublicInputs[ClaimPublicInputs.NULLIFIER];

        _assertPoolBindings(poolPublicInputs, nullifier, h.perRecipientAmount, destination);

        // Single-spend at claim contract level.
        if (nullifierConsumed[nullifier]) revert NullifierConsumed();

        if (!verifier.verifyClaim(claimProof, _claimPublicInputsAsBytes32(claimPublicInputs))) {
            revert InvalidClaimProof();
        }

        // Effects before external interaction (CEI).
        nullifierConsumed[nullifier] = true;
        nullifiersConsumedCount[roundId] += 1;

        // Pool unshield. Pool verifies the pool-withdraw proof internally.
        pool.unshield(
            address(this),
            poolWithdrawProof,
            poolPublicInputs[PoolPublicInputs.POOL_ROOT],
            nullifier,
            address(token),
            h.perRecipientAmount,
            destination,
            roundId
        );

        emit Claimed(roundId, nullifier, destination, h.perRecipientAmount, msg.sender);
    }

    function _decodeRoundId(uint256[10] calldata claimPublicInputs) internal pure returns (uint256) {
        uint256 hi = claimPublicInputs[ClaimPublicInputs.ROUND_ID_HI];
        uint256 lo = claimPublicInputs[ClaimPublicInputs.ROUND_ID_LO];
        if (hi >= (1 << 128) || lo >= (1 << 128)) revert LimbOutOfRange();
        return (hi << 128) | lo;
    }

    function _assertChainId(uint256[10] calldata claimPublicInputs, uint256 headerChainId) internal view {
        uint256 hi = claimPublicInputs[ClaimPublicInputs.CHAIN_ID_HI];
        uint256 lo = claimPublicInputs[ClaimPublicInputs.CHAIN_ID_LO];
        if (hi >= (1 << 128) || lo >= (1 << 128)) revert LimbOutOfRange();
        uint256 chainId = (hi << 128) | lo;
        if (chainId != block.chainid || chainId != headerChainId) revert BadChainId();
    }

    function _assertHeaderBindings(uint256[10] calldata claimPublicInputs, RoundHeader memory h) internal view {
        if (claimPublicInputs[ClaimPublicInputs.COHORT_ROOT] != h.cohortRoot) revert BadHeaderBinding();
        if (claimPublicInputs[ClaimPublicInputs.AMOUNT] != h.perRecipientAmount) revert BadHeaderBinding();
        if (claimPublicInputs[ClaimPublicInputs.CLAIM_CONTRACT_ADDRESS] != uint256(uint160(address(this)))) {
            revert BadHeaderBinding();
        }
    }

    function _assertPoolBindings(
        uint256[5] calldata poolPublicInputs,
        uint256 nullifier,
        uint256 amount,
        address destination
    ) internal view {
        if (poolPublicInputs[PoolPublicInputs.CLAIM_NULLIFIER] != nullifier) revert BadPoolBinding();
        if (poolPublicInputs[PoolPublicInputs.AMOUNT] != amount) revert BadPoolBinding();
        if (poolPublicInputs[PoolPublicInputs.TOKEN] != uint256(uint160(address(token)))) revert BadPoolBinding();
        if (poolPublicInputs[PoolPublicInputs.RECIPIENT] != uint256(uint160(destination))) revert BadPoolBinding();
        if (!pool.isKnownRoot(address(this), poolPublicInputs[PoolPublicInputs.POOL_ROOT])) revert BadPoolBinding();
    }

    function _claimPublicInputsAsBytes32(uint256[10] calldata claimPublicInputs)
        internal
        pure
        returns (bytes32[] memory pi)
    {
        pi = new bytes32[](10);
        for (uint256 i = 0; i < 10; i++) {
            pi[i] = bytes32(claimPublicInputs[i]);
        }
    }

    // Funder residual recovery (balance accounting, no ZK)

    function funderUnshieldResidual(uint256 roundId) external {
        if (msg.sender != funderMultisig) revert NotMultisig();
        if (!roundRegistered[roundId]) revert RoundNotRegistered();
        RoundHeader storage h = header[roundId];

        if (block.timestamp < uint256(h.closeTime) + RESIDUAL_TIMELOCK_SECONDS) revert RoundOpen();
        if (residualPaid[roundId]) revert ResidualAlreadyPaid();

        uint256 unclaimed = (h.cohortSize - nullifiersConsumedCount[roundId]) * h.perRecipientAmount;

        residualPaid[roundId] = true;

        if (unclaimed > 0) {
            pool.recoverResidual(roundId, unclaimed, funderResidualDestination);
        }

        emit ResidualRecovered(roundId, unclaimed, funderResidualDestination);
    }
}

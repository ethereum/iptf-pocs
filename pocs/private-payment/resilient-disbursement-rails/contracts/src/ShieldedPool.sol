// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IERC20} from "@openzeppelin-contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin-contracts/token/ERC20/utils/SafeERC20.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";
import {IPool} from "./interfaces/IPool.sol";
import {ICompositeVerifier} from "./interfaces/ICompositeVerifier.sol";

/// @title ShieldedPool
/// @notice Per-claim-contract partitioned shielded ERC-20 pool. Each
///         registered claim contract has its own LeanIMT sub-tree.
///         Single-asset variant for the resilient-disbursement-rails PoC.
contract ShieldedPool is IPool {
    using SafeERC20 for IERC20;
    using LeanIMT for LeanIMTData;

    /// @notice Recent-roots window per claim contract.
    uint256 public constant RECENT_ROOTS_WINDOW = 100;

    /// @notice Timelock for governance-gated config updates.
    uint256 public constant CONFIG_TIMELOCK_BLOCKS = 14400;

    // State

    /// @notice Per-claim-contract LeanIMT sub-tree.
    mapping(address => LeanIMTData) internal _trees;

    /// @notice Per-claim-contract commitment count.
    mapping(address => uint256) public commitmentCount;

    /// @notice Per-claim-contract recent-roots circular buffer.
    mapping(address => uint256[100]) public recentRoots;

    /// @notice Per-claim-contract circular-buffer head index.
    mapping(address => uint256) public rootIndex;

    /// @notice Per-claim-contract recent-roots membership.
    mapping(address => mapping(uint256 => bool)) public knownRoots;

    /// @notice Pool-side spent claim_nullifier set (single-asset, single pool).
    mapping(uint256 => bool) public spentClaimNullifiers;

    /// @notice Tracked balance per claim contract.
    mapping(address => uint256) public balance;

    /// @notice Per-(claim contract, round) deposit total.
    mapping(address => mapping(uint256 => uint256)) public roundDeposit;

    /// @notice Per-(claim contract, round) claimed total.
    mapping(address => mapping(uint256 => uint256)) public roundClaimed;

    /// @notice Per-(claim contract, round) residual paid flag.
    mapping(address => mapping(uint256 => bool)) public roundResidualPaid;

    /// @notice Per-(claim contract, commitment) leaf index + 1 (0 = unknown).
    mapping(address => mapping(uint256 => uint256)) internal _commitmentIndex;

    /// @notice Single asset for the pool.
    IERC20 public immutable token;

    /// @notice Authorized factory for `deposit`.
    address public override authorizedFactory;

    /// @notice Governance address (controls factory and verifier rotation).
    address public governance;

    /// @notice Composite verifier for pool-withdraw proofs.
    ICompositeVerifier public verifier;

    /// @notice Pending factory rotation.
    address public pendingFactory;
    uint256 public pendingFactoryActivation;

    /// @notice Pending verifier rotation.
    address public pendingVerifier;
    uint256 public pendingVerifierActivation;

    // Events

    event Deposited(
        address indexed claimContract, uint256 commitment, uint256 leafIndex, uint256 newRoot, uint256 indexed roundId
    );
    event Unshielded(
        address indexed claimContract,
        uint256 indexed claimNullifier,
        address indexed recipient,
        uint256 amount,
        uint256 roundId
    );
    event ResidualRecovered(
        address indexed claimContract, uint256 indexed roundId, address indexed recipient, uint256 amount
    );
    event AuthorizedFactoryProposed(address indexed newFactory, uint256 activationBlock);
    event AuthorizedFactoryUpdated(address indexed oldFactory, address indexed newFactory);
    event VerifierProposed(address indexed newVerifier, uint256 activationBlock);
    event VerifierUpdated(address indexed oldVerifier, address indexed newVerifier);

    // Errors

    error NotFactory();
    error NotClaimContract();
    error NotGovernance();
    error UnknownRoot();
    error NullifierSpent();
    error InvalidProof();
    error WrongToken();
    error InsufficientBalance();
    error ResidualAlreadyPaid();
    error ZeroAddress();
    error NoPending();
    error TimelockNotExpired();
    error AlreadyPending();
    error CommitmentExists();

    // Constructor

    constructor(address _token, address _verifier, address _governance) {
        if (_token == address(0) || _verifier == address(0) || _governance == address(0)) {
            revert ZeroAddress();
        }
        token = IERC20(_token);
        verifier = ICompositeVerifier(_verifier);
        governance = _governance;
    }

    // Modifiers

    modifier onlyFactory() {
        if (msg.sender != authorizedFactory) revert NotFactory();
        _;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    // IPool

    /// @inheritdoc IPool
    function deposit(address claimContract, uint256 commitment, uint256 amount, uint256 roundId)
        external
        override
        onlyFactory
    {
        if (claimContract == address(0)) revert ZeroAddress();
        if (_commitmentIndex[claimContract][commitment] != 0) revert CommitmentExists();

        // Pull funds from factory.
        token.safeTransferFrom(msg.sender, address(this), amount);

        // Insert into the claim contract's sub-tree.
        uint256 leafIndex = _trees[claimContract].size;
        uint256 newRoot = _trees[claimContract].insert(commitment);

        // Record commitment -> (leafIndex + 1).
        _commitmentIndex[claimContract][commitment] = leafIndex + 1;
        commitmentCount[claimContract] = leafIndex + 1;

        // Update recent-roots circular buffer.
        uint256 idx = rootIndex[claimContract];
        uint256 evicted = recentRoots[claimContract][idx];
        if (evicted != 0) {
            knownRoots[claimContract][evicted] = false;
        }
        recentRoots[claimContract][idx] = newRoot;
        knownRoots[claimContract][newRoot] = true;
        rootIndex[claimContract] = (idx + 1) % RECENT_ROOTS_WINDOW;

        // Accounting.
        balance[claimContract] += amount;
        roundDeposit[claimContract][roundId] += amount;

        emit Deposited(claimContract, commitment, leafIndex, newRoot, roundId);
    }

    /// @inheritdoc IPool
    function unshield(
        address claimContract,
        bytes calldata withdrawProof,
        uint256 subTreeRoot,
        uint256 claimNullifier,
        address tokenAddr,
        uint256 amount,
        address recipient,
        uint256 roundId
    ) external override {
        if (msg.sender != claimContract) revert NotClaimContract();
        if (tokenAddr != address(token)) revert WrongToken();
        if (spentClaimNullifiers[claimNullifier]) revert NullifierSpent();
        if (!knownRoots[claimContract][subTreeRoot]) revert UnknownRoot();
        if (balance[claimContract] < amount) revert InsufficientBalance();

        // publicInputs ordering matches pool-withdraw circuit:
        //   (pool_root, claim_nullifier, token, amount, recipient)
        bytes32[] memory publicInputs = new bytes32[](5);
        publicInputs[0] = bytes32(subTreeRoot);
        publicInputs[1] = bytes32(claimNullifier);
        publicInputs[2] = bytes32(uint256(uint160(tokenAddr)));
        publicInputs[3] = bytes32(amount);
        publicInputs[4] = bytes32(uint256(uint160(recipient)));

        if (!verifier.verifyPoolWithdraw(withdrawProof, publicInputs)) revert InvalidProof();

        // CEI: mark spent + update accounting before transfer.
        spentClaimNullifiers[claimNullifier] = true;
        balance[claimContract] -= amount;
        roundClaimed[claimContract][roundId] += amount;

        token.safeTransfer(recipient, amount);

        emit Unshielded(claimContract, claimNullifier, recipient, amount, roundId);
    }

    /// @inheritdoc IPool
    function recoverResidual(uint256 roundId, uint256 amount, address recipient) external override {
        // msg.sender is the claim contract for which residual is being paid.
        if (recipient == address(0)) revert ZeroAddress();
        if (roundResidualPaid[msg.sender][roundId]) revert ResidualAlreadyPaid();
        if (balance[msg.sender] < amount) revert InsufficientBalance();

        roundResidualPaid[msg.sender][roundId] = true;
        balance[msg.sender] -= amount;

        token.safeTransfer(recipient, amount);

        emit ResidualRecovered(msg.sender, roundId, recipient, amount);
    }

    /// @inheritdoc IPool
    function isKnownRoot(address claimContract, uint256 root) external view override returns (bool) {
        return knownRoots[claimContract][root];
    }

    /// @inheritdoc IPool
    function commitmentIndex(address claimContract, uint256 commitment) external view override returns (uint256) {
        return _commitmentIndex[claimContract][commitment];
    }

    // Sub-tree views

    /// @notice Current root of the claim contract's sub-tree (0 if empty).
    function subTreeRoot(address claimContract) external view returns (uint256) {
        return _trees[claimContract].root();
    }

    /// @notice Current size of the claim contract's sub-tree.
    function subTreeSize(address claimContract) external view returns (uint256) {
        return _trees[claimContract].size;
    }

    // Governance: factory + verifier rotation under timelock

    function proposeAuthorizedFactory(address newFactory) external onlyGovernance {
        if (newFactory == address(0)) revert ZeroAddress();
        if (pendingFactoryActivation != 0) revert AlreadyPending();
        pendingFactory = newFactory;
        pendingFactoryActivation = block.number + CONFIG_TIMELOCK_BLOCKS;
        emit AuthorizedFactoryProposed(newFactory, pendingFactoryActivation);
    }

    function finalizeAuthorizedFactory() external onlyGovernance {
        if (pendingFactoryActivation == 0) revert NoPending();
        if (block.number < pendingFactoryActivation) revert TimelockNotExpired();
        address old = authorizedFactory;
        authorizedFactory = pendingFactory;
        pendingFactory = address(0);
        pendingFactoryActivation = 0;
        emit AuthorizedFactoryUpdated(old, authorizedFactory);
    }

    /// @notice One-shot factory bootstrap. Callable only by governance and
    ///         only while authorizedFactory is unset, to avoid the timelock
    ///         on initial wiring.
    function initAuthorizedFactory(address factory_) external onlyGovernance {
        if (authorizedFactory != address(0)) revert AlreadyPending();
        if (factory_ == address(0)) revert ZeroAddress();
        authorizedFactory = factory_;
        emit AuthorizedFactoryUpdated(address(0), factory_);
    }

    function proposeVerifier(address newVerifier) external onlyGovernance {
        if (newVerifier == address(0)) revert ZeroAddress();
        if (pendingVerifierActivation != 0) revert AlreadyPending();
        pendingVerifier = newVerifier;
        pendingVerifierActivation = block.number + CONFIG_TIMELOCK_BLOCKS;
        emit VerifierProposed(newVerifier, pendingVerifierActivation);
    }

    function finalizeVerifier() external onlyGovernance {
        if (pendingVerifierActivation == 0) revert NoPending();
        if (block.number < pendingVerifierActivation) revert TimelockNotExpired();
        address old = address(verifier);
        verifier = ICompositeVerifier(pendingVerifier);
        pendingVerifier = address(0);
        pendingVerifierActivation = 0;
        emit VerifierUpdated(old, address(verifier));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, stdStorage, StdStorage} from "forge-std/src/Test.sol";
import {ShieldedPoolExt} from "../src/ShieldedPoolExt.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @dev Scope: deposit, epoch rollover, and the 2-in-2-out transfer spend path.
///      With `MockVerifier` the proofs always accept, so these tests cover the
///      contract's public-input marshaling, cross-proof wiring, and state
///      transitions — not the in-circuit/proof-level checks (commitment
///      membership, sorted-low-leaf double-spend, η binding), which are exercised
///      by the circuit tests and the bb-prover integration harness.
contract ShieldedPoolExtTest is Test {
    using stdStorage for StdStorage;

    ShieldedPoolExt public pool;
    MockVerifier public verifier; // deposit
    MockVerifier public transferVerifier; // wallet spend proof
    MockVerifier public insertionVerifier; // relayer insertion proof
    MockERC20 public token;

    address public owner;
    address public user;

    // Small commitment values that fit in the BN254 scalar field.
    bytes32 constant COMMITMENT_0 = bytes32(uint256(1));
    bytes32 constant COMMITMENT_1 = bytes32(uint256(2));
    uint256 constant DEPOSIT_AMOUNT = 1000e6;

    // Stand-in for the off-chain-computed empty indexed-Merkle-tree root. The
    // contract treats it opaquely (stores it, resets to it); its true value is
    // pinned to the Rust mirror in the integration test.
    bytes32 constant EMPTY_IMT_ROOT = bytes32(uint256(0xE3217));

    // Stand-in for the chain-update circuit's VK hash (SPEC `FixedVK`); the
    // contract pins it as the spend proof's `chain_vk_hash` public input.
    bytes32 constant CHAIN_VK_HASH = bytes32(uint256(0xC4A14));

    event Deposit(bytes32 indexed commitment, address indexed token, uint256 amount, bytes encryptedNote);
    event Transfer(
        bytes32 indexed nullifier1,
        bytes32 indexed nullifier2,
        bytes32 commitment1,
        bytes32 commitment2,
        bytes encryptedNotes
    );
    event EpochRollover(uint64 indexed epoch, bytes32 root);

    function setUp() public {
        owner = address(this);
        user = address(0x1);

        verifier = new MockVerifier();
        transferVerifier = new MockVerifier();
        insertionVerifier = new MockVerifier();
        pool = new ShieldedPoolExt(
            address(verifier),
            address(transferVerifier),
            address(insertionVerifier),
            CHAIN_VK_HASH,
            EMPTY_IMT_ROOT
        );

        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));

        token.mint(user, DEPOSIT_AMOUNT * 10);
        vm.prank(user);
        token.approve(address(pool), type(uint256).max);
    }

    // ========== Deposit ==========

    function testDeposit() public {
        bytes memory encryptedNote = "encrypted_data";

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit Deposit(COMMITMENT_0, address(token), DEPOSIT_AMOUNT, encryptedNote);

        // The contract passes currentEpoch as the deposit proof's 4th public
        // input, enforcing epoch_created == currentEpoch in the verified proof.
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, encryptedNote);

        assertEq(pool.getCommitmentCount(), 1);
        assertTrue(pool.commitmentRoot() != bytes32(0));
        assertEq(token.balanceOf(address(pool)), DEPOSIT_AMOUNT);
    }

    function testDepositRevertsUnsupportedToken() public {
        MockERC20 unsupported = new MockERC20("Unsupported", "UNS", 18);
        vm.prank(user);
        vm.expectRevert(ShieldedPoolExt.UnsupportedToken.selector);
        pool.deposit("", COMMITMENT_0, address(unsupported), DEPOSIT_AMOUNT, "");
    }

    function testDepositRevertsZeroAmount() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPoolExt.ZeroAmount.selector);
        pool.deposit("", COMMITMENT_0, address(token), 0, "");
    }

    function testDepositRevertsInvalidProof() public {
        verifier.setResult(false);
        vm.prank(user);
        vm.expectRevert(ShieldedPoolExt.InvalidProof.selector);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, "");
    }

    function testDepositUpdatesRoot() public {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, "");
        bytes32 root1 = pool.commitmentRoot();

        vm.prank(user);
        pool.deposit("", COMMITMENT_1, address(token), DEPOSIT_AMOUNT, "");
        bytes32 root2 = pool.commitmentRoot();

        assertTrue(root1 != root2);
        assertTrue(pool.isKnownRoot(root1)); // historical root retained
    }

    // ========== Epoch rollover ==========

    function testInitialActiveState() public view {
        assertEq(pool.currentEpoch(), 0);
        assertEq(pool.activeLeafCount(), 1, "genesis leaf occupies index 0");
        assertEq(pool.activeNullifierRoot(), EMPTY_IMT_ROOT);
        assertEq(pool.emptyImtRoot(), EMPTY_IMT_ROOT);
    }

    function testRolloverFreezesCurrentRootAndResets() public {
        // Simulate the spend path having advanced the active root.
        bytes32 advancedRoot = bytes32(uint256(0xBEEF));
        stdstore.target(address(pool)).sig("activeNullifierRoot()").checked_write(advancedRoot);
        assertEq(pool.activeNullifierRoot(), advancedRoot);

        vm.expectEmit(true, false, false, true);
        emit EpochRollover(0, advancedRoot);
        pool.rolloverEpoch();

        assertEq(pool.frozenNullifierRoots(0), advancedRoot, "froze the pre-rollover root");
        assertEq(pool.activeNullifierRoot(), EMPTY_IMT_ROOT, "active tree reset");
        assertEq(pool.activeLeafCount(), 1, "leaf count reset to genesis");
        assertEq(pool.currentEpoch(), 1);
    }

    function testRolloverIncrementsEpoch() public {
        pool.rolloverEpoch();
        assertEq(pool.currentEpoch(), 1);
        pool.rolloverEpoch();
        assertEq(pool.currentEpoch(), 2);

        // Each past epoch's root is recorded (empty here, since no spends yet).
        assertEq(pool.frozenNullifierRoots(0), EMPTY_IMT_ROOT);
        assertEq(pool.frozenNullifierRoots(1), EMPTY_IMT_ROOT);
    }

    function testRolloverOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPoolExt.OnlyOwner.selector);
        pool.rolloverEpoch();
    }

    // ========== Transfer (two-proof spend path) ==========

    bytes32 constant NUL_0 = bytes32(uint256(0xA1));
    bytes32 constant NUL_1 = bytes32(uint256(0xA2));
    bytes32 constant OUT_0 = bytes32(uint256(11));
    bytes32 constant OUT_1 = bytes32(uint256(12));
    bytes32 constant POST_ROOT = bytes32(uint256(0xBEEF));

    /// @dev Deposit once so the commitment root is non-zero and `isKnownRoot`.
    function _depositAndGetRoot() internal returns (bytes32) {
        vm.prank(user);
        pool.deposit("", COMMITMENT_0, address(token), DEPOSIT_AMOUNT, "");
        return pool.commitmentRoot();
    }

    function _transfer(bytes32 root, bytes32 postRoot) internal {
        bytes32[2] memory nullifiers = [NUL_0, NUL_1];
        bytes32[2] memory outs = [OUT_0, OUT_1];
        uint64[2] memory epochCreated = [uint64(0), uint64(0)];
        pool.transfer("spend", "insert", nullifiers, outs, root, epochCreated, postRoot, "notes");
    }

    function testTransferAdvancesActiveTreeAndInsertsOutputs() public {
        bytes32 root = _depositAndGetRoot();
        uint64 leafBefore = pool.activeLeafCount();
        uint256 countBefore = pool.getCommitmentCount();

        vm.expectEmit(true, true, false, true);
        emit Transfer(NUL_0, NUL_1, OUT_0, OUT_1, "notes");
        _transfer(root, POST_ROOT);

        assertEq(pool.activeNullifierRoot(), POST_ROOT, "active root advanced to post-root");
        assertEq(pool.activeLeafCount(), leafBefore + 2, "two leaves appended");
        assertEq(pool.getCommitmentCount(), countBefore + 2, "two output commitments inserted");
    }

    function testTransferAcceptsHistoricalRoot() public {
        bytes32 firstRoot = _depositAndGetRoot();
        // A second deposit supersedes `firstRoot`, which stays valid as historical.
        vm.prank(user);
        pool.deposit("", COMMITMENT_1, address(token), DEPOSIT_AMOUNT, "");
        assertTrue(pool.isKnownRoot(firstRoot));

        _transfer(firstRoot, POST_ROOT);
        assertEq(pool.activeNullifierRoot(), POST_ROOT);
    }

    function testTransferRevertsUnknownRoot() public {
        vm.expectRevert(ShieldedPoolExt.InvalidRoot.selector);
        _transfer(bytes32(uint256(0xDEAD)), POST_ROOT);
    }

    function testTransferRevertsInvalidSpendProof() public {
        bytes32 root = _depositAndGetRoot();
        transferVerifier.setResult(false);
        vm.expectRevert(ShieldedPoolExt.InvalidProof.selector);
        _transfer(root, POST_ROOT);
    }

    function testTransferRevertsInvalidInsertionProof() public {
        bytes32 root = _depositAndGetRoot();
        insertionVerifier.setResult(false);
        vm.expectRevert(ShieldedPoolExt.InvalidProof.selector);
        _transfer(root, POST_ROOT);
    }

    // ========== expectedChainAccumulator ==========

    function testExpectedChainAccumulatorZeroWhenCaughtUp() public view {
        // A note created in the current epoch has no frozen epochs to fold.
        assertEq(pool.expectedChainAccumulator(pool.currentEpoch()), bytes32(0));
    }

    function testExpectedChainAccumulatorFoldsFrozenRoots() public {
        pool.rolloverEpoch(); // freezes epoch 0 (EMPTY_IMT_ROOT; no spends)
        pool.rolloverEpoch(); // freezes epoch 1
        assertEq(pool.currentEpoch(), 2);

        // Full range [0, 2): fold both frozen roots, seeded at 0.
        uint256 acc = PoseidonT3.hash([uint256(0), uint256(EMPTY_IMT_ROOT)]);
        acc = PoseidonT3.hash([acc, uint256(EMPTY_IMT_ROOT)]);
        assertEq(pool.expectedChainAccumulator(0), bytes32(acc), "fold over both frozen epochs");

        // Suffix [1, 2): fold only epoch 1.
        uint256 accSuffix = PoseidonT3.hash([uint256(0), uint256(EMPTY_IMT_ROOT)]);
        assertEq(pool.expectedChainAccumulator(1), bytes32(accSuffix), "fold over the suffix only");

        // Empty range [2, 2): nothing to fold.
        assertEq(pool.expectedChainAccumulator(2), bytes32(0), "fresh note folds nothing");
    }

    // ========== Misc ==========

    function testConstructorWiring() public view {
        assertEq(address(pool.depositVerifier()), address(verifier));
        assertEq(address(pool.transferVerifier()), address(transferVerifier));
        assertEq(address(pool.insertionVerifier()), address(insertionVerifier));
        assertEq(pool.chainVkHash(), CHAIN_VK_HASH);
    }

    function testConstructorRevertsZeroDepositVerifier() public {
        vm.expectRevert(ShieldedPoolExt.ZeroAddress.selector);
        new ShieldedPoolExt(address(0), address(transferVerifier), address(insertionVerifier), CHAIN_VK_HASH, EMPTY_IMT_ROOT);
    }

    function testConstructorRevertsZeroTransferVerifier() public {
        vm.expectRevert(ShieldedPoolExt.ZeroAddress.selector);
        new ShieldedPoolExt(address(verifier), address(0), address(insertionVerifier), CHAIN_VK_HASH, EMPTY_IMT_ROOT);
    }

    function testConstructorRevertsZeroInsertionVerifier() public {
        vm.expectRevert(ShieldedPoolExt.ZeroAddress.selector);
        new ShieldedPoolExt(address(verifier), address(transferVerifier), address(0), CHAIN_VK_HASH, EMPTY_IMT_ROOT);
    }

    function testAddSupportedTokenOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPoolExt.OnlyOwner.selector);
        pool.addSupportedToken(address(0x123));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, stdStorage, StdStorage} from "forge-std/src/Test.sol";
import {ShieldedPoolExt} from "../src/ShieldedPoolExt.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev Slice 1.2 scope: deposit + epoch rollover. The two-proof spend path that
///      advances `activeNullifierRoot` arrives in a later slice; here the active
///      root is poked via `stdstore` to test that rollover freezes it.
contract ShieldedPoolExtTest is Test {
    using stdStorage for StdStorage;

    ShieldedPoolExt public pool;
    MockVerifier public verifier;
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

    event Deposit(bytes32 indexed commitment, address indexed token, uint256 amount, bytes encryptedNote);
    event EpochRollover(uint64 indexed epoch, bytes32 root);

    function setUp() public {
        owner = address(this);
        user = address(0x1);

        verifier = new MockVerifier();
        pool = new ShieldedPoolExt(address(verifier), EMPTY_IMT_ROOT);

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

    // ========== Misc ==========

    function testConstructorRevertsZeroVerifier() public {
        vm.expectRevert(ShieldedPoolExt.ZeroAddress.selector);
        new ShieldedPoolExt(address(0), EMPTY_IMT_ROOT);
    }

    function testAddSupportedTokenOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPoolExt.OnlyOwner.selector);
        pool.addSupportedToken(address(0x123));
    }
}

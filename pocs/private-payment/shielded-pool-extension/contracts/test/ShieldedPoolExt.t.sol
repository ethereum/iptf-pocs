// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPoolExt} from "../src/ShieldedPoolExt.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev Slice 1.1 scope: the minimal deposit-only contract. Rollover,
///      frozen-root publication, and the two-proof spend path are tested in
///      later slices.
contract ShieldedPoolExtTest is Test {
    ShieldedPoolExt public pool;
    MockVerifier public verifier;
    MockERC20 public token;

    address public owner;
    address public user;

    // Small commitment values that fit in the BN254 scalar field.
    bytes32 constant COMMITMENT_0 = bytes32(uint256(1));
    bytes32 constant COMMITMENT_1 = bytes32(uint256(2));
    uint256 constant DEPOSIT_AMOUNT = 1000e6;

    event Deposit(bytes32 indexed commitment, address indexed token, uint256 amount, bytes encryptedNote);

    function setUp() public {
        owner = address(this);
        user = address(0x1);

        verifier = new MockVerifier();
        pool = new ShieldedPoolExt(address(verifier));

        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));

        token.mint(user, DEPOSIT_AMOUNT * 10);
        vm.prank(user);
        token.approve(address(pool), type(uint256).max);
    }

    function testCurrentEpochStartsAtZero() public view {
        assertEq(pool.currentEpoch(), 0);
    }

    function testDeposit() public {
        bytes memory encryptedNote = "encrypted_data";

        vm.prank(user);
        vm.expectEmit(true, true, false, true);
        emit Deposit(COMMITMENT_0, address(token), DEPOSIT_AMOUNT, encryptedNote);

        // The contract passes currentEpoch (0) as the deposit proof's 4th public
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

    function testConstructorRevertsZeroVerifier() public {
        vm.expectRevert(ShieldedPoolExt.ZeroAddress.selector);
        new ShieldedPoolExt(address(0));
    }

    function testAddSupportedTokenOnlyOwner() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPoolExt.OnlyOwner.selector);
        pool.addSupportedToken(address(0x123));
    }
}

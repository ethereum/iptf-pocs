// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";

contract ShieldedPoolTest is Test {
    ShieldedPool public pool;
    MockERC20 public token;
    MockCompositeVerifier public verifier;

    address public factory = address(0xFAC7);
    address public claimContract = address(0xC1A1);
    address public claimContract2 = address(0xC1A2);
    address public governance = address(0x6017);
    address public recipient = address(0xBEEF);

    uint256 public constant ROUND_ID = 7;
    uint256 public constant AMOUNT = 1_000;
    uint256 public constant COMMITMENT_BASE = 0xC0FFEE;

    function setUp() public {
        token = new MockERC20("Mock", "MCK", 6);
        verifier = new MockCompositeVerifier();
        pool = new ShieldedPool(address(token), address(verifier), governance);

        vm.prank(governance);
        pool.initAuthorizedFactory(factory);

        // Pre-fund the factory with tokens; factory approves pool.
        token.mint(factory, 1_000_000);
        vm.prank(factory);
        token.approve(address(pool), type(uint256).max);
    }

    function test_deposit_factoryOnly() public {
        vm.expectRevert(ShieldedPool.NotFactory.selector);
        pool.deposit(claimContract, COMMITMENT_BASE, AMOUNT, ROUND_ID);
    }

    function test_deposit_updatesAccountingAndTree() public {
        vm.prank(factory);
        pool.deposit(claimContract, COMMITMENT_BASE, AMOUNT, ROUND_ID);

        assertEq(pool.commitmentCount(claimContract), 1);
        assertEq(pool.balance(claimContract), AMOUNT);
        assertEq(pool.roundDeposit(claimContract, ROUND_ID), AMOUNT);
        assertEq(pool.commitmentIndex(claimContract, COMMITMENT_BASE), 1); // leafIndex+1
        assertTrue(pool.isKnownRoot(claimContract, pool.subTreeRoot(claimContract)));
    }

    function test_deposit_perClaimContractIsolation() public {
        vm.prank(factory);
        pool.deposit(claimContract, COMMITMENT_BASE, AMOUNT, ROUND_ID);
        vm.prank(factory);
        pool.deposit(claimContract2, COMMITMENT_BASE + 1, AMOUNT, ROUND_ID);

        assertEq(pool.commitmentCount(claimContract), 1);
        assertEq(pool.commitmentCount(claimContract2), 1);
        assertEq(pool.balance(claimContract), AMOUNT);
        assertEq(pool.balance(claimContract2), AMOUNT);
        // Roots are distinct - two separate sub-trees with different leaves.
        assertTrue(pool.subTreeRoot(claimContract) != 0);
        assertTrue(pool.subTreeRoot(claimContract2) != 0);
        assertTrue(pool.subTreeRoot(claimContract) != pool.subTreeRoot(claimContract2));
    }

    function _seedDeposit() internal returns (uint256 root) {
        vm.prank(factory);
        pool.deposit(claimContract, COMMITMENT_BASE, AMOUNT, ROUND_ID);
        root = pool.subTreeRoot(claimContract);
    }

    function test_unshield_callerMustBeClaimContract() public {
        uint256 root = _seedDeposit();

        vm.expectRevert(ShieldedPool.NotClaimContract.selector);
        pool.unshield(claimContract, hex"", root, 0x111, address(token), AMOUNT, recipient, ROUND_ID);
    }

    function test_unshield_happyPath() public {
        uint256 root = _seedDeposit();
        uint256 nullifier = 0x111;

        vm.prank(claimContract);
        pool.unshield(claimContract, hex"00", root, nullifier, address(token), AMOUNT, recipient, ROUND_ID);

        assertEq(token.balanceOf(recipient), AMOUNT);
        assertEq(pool.balance(claimContract), 0);
        assertEq(pool.roundClaimed(claimContract, ROUND_ID), AMOUNT);
        assertTrue(pool.spentClaimNullifiers(nullifier));
        assertEq(verifier.poolWithdrawCalls(), 1);

        // publicInputs ordering: (root, nullifier, token, amount, recipient).
        assertEq(verifier.lastPoolWithdrawPublicInputs(0), bytes32(root));
        assertEq(verifier.lastPoolWithdrawPublicInputs(1), bytes32(nullifier));
        assertEq(verifier.lastPoolWithdrawPublicInputs(2), bytes32(uint256(uint160(address(token)))));
        assertEq(verifier.lastPoolWithdrawPublicInputs(3), bytes32(AMOUNT));
        assertEq(verifier.lastPoolWithdrawPublicInputs(4), bytes32(uint256(uint160(recipient))));
    }

    function test_unshield_revertsDoubleSpend() public {
        uint256 root = _seedDeposit();
        // Add another deposit so balance allows two attempts.
        vm.prank(factory);
        pool.deposit(claimContract, COMMITMENT_BASE + 1, AMOUNT, ROUND_ID);

        uint256 root2 = pool.subTreeRoot(claimContract);
        uint256 nullifier = 0xDEAD;

        vm.prank(claimContract);
        pool.unshield(claimContract, hex"00", root2, nullifier, address(token), AMOUNT, recipient, ROUND_ID);

        vm.prank(claimContract);
        vm.expectRevert(ShieldedPool.NullifierSpent.selector);
        pool.unshield(claimContract, hex"00", root2, nullifier, address(token), AMOUNT, recipient, ROUND_ID);
    }

    function test_unshield_revertsUnknownRoot() public {
        _seedDeposit();
        vm.prank(claimContract);
        vm.expectRevert(ShieldedPool.UnknownRoot.selector);
        pool.unshield(claimContract, hex"00", 0xBADBAD, 0x111, address(token), AMOUNT, recipient, ROUND_ID);
    }

    function test_unshield_revertsWrongToken() public {
        uint256 root = _seedDeposit();
        vm.prank(claimContract);
        vm.expectRevert(ShieldedPool.WrongToken.selector);
        pool.unshield(claimContract, hex"00", root, 0x111, address(0xDEADBEEF), AMOUNT, recipient, ROUND_ID);
    }

    function test_unshield_revertsInvalidProof() public {
        uint256 root = _seedDeposit();
        verifier.setPoolWithdrawResult(false);

        vm.prank(claimContract);
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.unshield(claimContract, hex"00", root, 0x111, address(token), AMOUNT, recipient, ROUND_ID);
    }

    function test_recoverResidual_success() public {
        uint256 root = _seedDeposit();
        uint256 nullifier = 0x111;

        // No claim consumed.
        vm.prank(claimContract);
        pool.recoverResidual(ROUND_ID, AMOUNT, recipient);

        assertEq(token.balanceOf(recipient), AMOUNT);
        assertEq(pool.balance(claimContract), 0);
        assertTrue(pool.roundResidualPaid(claimContract, ROUND_ID));

        root; // silence unused-warning
        nullifier;
    }

    function test_recoverResidual_doubleCallReverts() public {
        _seedDeposit();
        vm.prank(claimContract);
        pool.recoverResidual(ROUND_ID, AMOUNT, recipient);

        vm.prank(claimContract);
        vm.expectRevert(ShieldedPool.ResidualAlreadyPaid.selector);
        pool.recoverResidual(ROUND_ID, AMOUNT, recipient);
    }

    function test_recoverResidual_revertsInsufficientBalance() public {
        _seedDeposit();

        vm.prank(claimContract);
        vm.expectRevert(ShieldedPool.InsufficientBalance.selector);
        pool.recoverResidual(ROUND_ID, AMOUNT + 1, recipient);
    }

    function test_initFactory_oneShot() public {
        vm.prank(governance);
        vm.expectRevert(ShieldedPool.AlreadyPending.selector);
        pool.initAuthorizedFactory(address(0xAB));
    }

    function test_proposeFactory_timelockFlow() public {
        vm.prank(governance);
        pool.proposeAuthorizedFactory(address(0xAB));

        vm.prank(governance);
        vm.expectRevert(ShieldedPool.TimelockNotExpired.selector);
        pool.finalizeAuthorizedFactory();

        vm.roll(block.number + pool.CONFIG_TIMELOCK_BLOCKS());
        vm.prank(governance);
        pool.finalizeAuthorizedFactory();

        assertEq(pool.authorizedFactory(), address(0xAB));
    }
}

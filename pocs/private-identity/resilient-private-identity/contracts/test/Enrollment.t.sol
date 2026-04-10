// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {Enrollment, IVerifier, IIdentityTree} from "../src/Enrollment.sol";

contract MockVerifier is IVerifier {
    bool public returnValue;

    constructor(bool _returnValue) {
        returnValue = _returnValue;
    }

    function setReturnValue(bool _v) external {
        returnValue = _v;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return returnValue;
    }
}

contract MockIdentityTree is IIdentityTree {
    uint256 public lastLeaf;
    uint256 public lastNullifier;
    uint256 public removedLeaf;

    function insertLeaf(uint256 leaf, uint256 enrollmentNullifier) external {
        lastLeaf = leaf;
        lastNullifier = enrollmentNullifier;
    }

    function removeLeaf(uint256 leaf, uint256[] calldata) external {
        removedLeaf = leaf;
    }
}

contract EnrollmentTest is Test {
    Enrollment public enrollment;
    MockVerifier public mockVerifier;
    MockIdentityTree public mockTree;

    address public multisigAddr = address(0xAA);
    address public guardianAddr = address(0xBB);

    // BN254 G1 generator point
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    uint256 constant STAKE_AMOUNT = 0.1 ether;

    function setUp() public {
        mockVerifier = new MockVerifier(true);
        mockTree = new MockIdentityTree();
        enrollment = new Enrollment(
            address(mockTree),
            address(mockVerifier),
            G1_X,
            G1_Y,
            multisigAddr,
            guardianAddr,
            STAKE_AMOUNT
        );
    }

    function test_constructor_state() public view {
        (uint256 kx, uint256 ky) = enrollment.mpcPublicKey();
        assertEq(kx, G1_X);
        assertEq(ky, G1_Y);
        assertEq(enrollment.multisig(), multisigAddr);
        assertEq(enrollment.guardian(), guardianAddr);
    }


    function test_enroll_success() public {
        enrollment.enroll{value: STAKE_AMOUNT}(42, 100, 5, 6, hex"1234");
        assertEq(mockTree.lastLeaf(), 42);
        assertEq(mockTree.lastNullifier(), 100);
        assertEq(enrollment.stakers(42), address(this));
    }

    function test_enroll_revertsOnInsufficientStake() public {
        vm.expectRevert(Enrollment.InsufficientStake.selector);
        enrollment.enroll{value: STAKE_AMOUNT - 1}(42, 100, 5, 6, hex"1234");
    }

    function test_enroll_revertsOnInvalidProof() public {
        mockVerifier.setReturnValue(false);
        vm.expectRevert(Enrollment.InvalidProof.selector);
        enrollment.enroll{value: STAKE_AMOUNT}(42, 100, 5, 6, hex"1234");
    }

    function test_enroll_graceKeyFallback() public {
        // Simulate key rotation: set up grace period
        // First propose + finalize a new key
        vm.startPrank(multisigAddr);

        // Propose a new key (use 2*G1 = known BN254 point)
        // 2*G1 on BN254
        uint256 newX = 0x030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd3;
        uint256 newY = 0x15ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4;
        enrollment.proposeMPCPublicKey(newX, newY);

        // Advance past timelock
        vm.roll(block.number + 14401);
        enrollment.finalizeMPCPublicKey();
        vm.stopPrank();

        // Now we're in the grace period. Current key is newKey, previous is G1.
        // Mock verifier returns false for current key, then true for previous
        // We'll use a special mock that alternates
        MockVerifierAlternating altVerifier = new MockVerifierAlternating();
        // Create a new enrollment with the alternating verifier
        Enrollment enrollmentAlt = new Enrollment(
            address(mockTree),
            address(altVerifier),
            newX,
            newY,
            multisigAddr,
            guardianAddr,
            STAKE_AMOUNT
        );

        // Simulate that the previous key was set (we need to do key rotation on enrollmentAlt)
        // Actually, let's just test the existing enrollment contract's grace logic
        // The mock verifier always returns true, so it won't fall through to grace
        // Let's use a verifier that fails first, succeeds second
        MockVerifierAlternating altVer2 = new MockVerifierAlternating();
        Enrollment enrollment2 = new Enrollment(
            address(mockTree),
            address(altVer2),
            G1_X,
            G1_Y,
            multisigAddr,
            guardianAddr,
            STAKE_AMOUNT
        );

        // Rotate key on enrollment2
        vm.startPrank(multisigAddr);
        enrollment2.proposeMPCPublicKey(newX, newY);
        vm.roll(block.number + 14401);
        enrollment2.finalizeMPCPublicKey();
        vm.stopPrank();

        // During grace period, first verify with current key fails, then retry with previous succeeds
        uint256 graceExpiry = enrollment2.keyGraceExpiry();
        assertTrue(block.number < graceExpiry);

        // altVer2: first call returns false, second returns true
        enrollment2.enroll{value: STAKE_AMOUNT}(42, 100, 5, 6, hex"1234");
        assertEq(mockTree.lastLeaf(), 42);
    }


    function test_proposeMPCPublicKey_onlyMultisig() public {
        vm.prank(address(0xdead));
        vm.expectRevert(Enrollment.NotMultisig.selector);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);
    }

    function test_proposeMPCPublicKey_revertsNotOnCurve() public {
        vm.prank(multisigAddr);
        vm.expectRevert(Enrollment.NotOnCurve.selector);
        enrollment.proposeMPCPublicKey(999, 999);
    }

    function test_proposeMPCPublicKey_revertsIfAlreadyPending() public {
        vm.startPrank(multisigAddr);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);
        vm.expectRevert(Enrollment.KeyAlreadyPending.selector);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);
        vm.stopPrank();
    }

    function test_proposeMPCPublicKey_setsState() public {
        vm.prank(multisigAddr);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);

        (uint256 px, uint256 py) = enrollment.pendingKey();
        assertEq(px, G1_X);
        assertEq(py, G1_Y);
        assertEq(enrollment.pendingKeyActivation(), block.number + 14400);
    }


    function test_finalizeMPCPublicKey_onlyMultisig() public {
        vm.prank(multisigAddr);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);

        vm.prank(address(0xdead));
        vm.expectRevert(Enrollment.NotMultisig.selector);
        enrollment.finalizeMPCPublicKey();
    }

    function test_finalizeMPCPublicKey_revertsNoPending() public {
        vm.prank(multisigAddr);
        vm.expectRevert(Enrollment.NoPendingKey.selector);
        enrollment.finalizeMPCPublicKey();
    }

    function test_finalizeMPCPublicKey_revertsTimelockNotExpired() public {
        vm.prank(multisigAddr);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);

        vm.prank(multisigAddr);
        vm.expectRevert(Enrollment.TimelockNotExpired.selector);
        enrollment.finalizeMPCPublicKey();
    }

    function test_finalizeMPCPublicKey_rotatesKeys() public {
        vm.startPrank(multisigAddr);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);

        vm.roll(block.number + 14401);
        enrollment.finalizeMPCPublicKey();
        vm.stopPrank();

        (uint256 kx, uint256 ky) = enrollment.mpcPublicKey();
        assertEq(kx, G1_X);
        assertEq(ky, G1_Y);

        // Previous key should be the old key (also G1 in this case, since constructor set it)
        (uint256 px, uint256 py) = enrollment.previousMPCKey();
        assertEq(px, G1_X);
        assertEq(py, G1_Y);

        // Grace period set
        assertTrue(enrollment.keyGraceExpiry() > 0);

        // Pending cleared
        assertEq(enrollment.pendingKeyActivation(), 0);
    }


    function test_vetoPendingKey_onlyGuardian() public {
        vm.prank(multisigAddr);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);

        vm.prank(address(0xdead));
        vm.expectRevert(Enrollment.NotGuardian.selector);
        enrollment.vetoPendingKey();
    }

    function test_vetoPendingKey_revertsNoPending() public {
        vm.prank(guardianAddr);
        vm.expectRevert(Enrollment.NoPendingKey.selector);
        enrollment.vetoPendingKey();
    }

    function test_vetoPendingKey_clearsPending() public {
        vm.prank(multisigAddr);
        enrollment.proposeMPCPublicKey(G1_X, G1_Y);

        vm.prank(guardianAddr);
        enrollment.vetoPendingKey();

        assertEq(enrollment.pendingKeyActivation(), 0);
        (uint256 px, uint256 py) = enrollment.pendingKey();
        assertEq(px, 0);
        assertEq(py, 0);
    }
    function test_unstake_success() public {
        enrollment.enroll{value: STAKE_AMOUNT}(42, 100, 5, 6, hex"1234");
        uint256 balanceBefore = address(this).balance;

        uint256[] memory siblings = new uint256[](0);
        enrollment.unstake(42, siblings);

        assertEq(address(this).balance, balanceBefore + STAKE_AMOUNT);
        assertEq(enrollment.stakers(42), address(0));
        assertEq(mockTree.removedLeaf(), 42);
    }

    function test_unstake_revertsNotStaker() public {
        enrollment.enroll{value: STAKE_AMOUNT}(42, 100, 5, 6, hex"1234");

        vm.prank(address(0xdead));
        vm.expectRevert(Enrollment.NotStaker.selector);
        uint256[] memory siblings = new uint256[](0);
        enrollment.unstake(42, siblings);
    }

    receive() external payable {}
}

/// @dev Returns false on first call, true on second call
contract MockVerifierAlternating is IVerifier {
    uint256 private callCount;

    function verify(bytes calldata, bytes32[] calldata) external returns (bool) {
        callCount++;
        return callCount > 1;
    }
}

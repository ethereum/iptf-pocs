// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";
import {BalanceVerifier} from "../src/BalanceVerifier.sol";

/// @dev Mock verifier that always succeeds (no-op verify).
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {}
}

contract BalanceVerifierTest is Test {
    BalanceVerifier internal balanceVerifier;
    MockRiscZeroVerifier internal mockVerifier;

    bytes32 internal constant ROOT = keccak256("test-accounts-root");

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        balanceVerifier = new BalanceVerifier(mockVerifier, ROOT);
    }

    // ---------------------------------------------------------------
    // 1. Constructor sets state correctly
    // ---------------------------------------------------------------
    function test_constructor_setsState() public view {
        assertEq(address(balanceVerifier.verifier()), address(mockVerifier));
        assertEq(balanceVerifier.accountsRoot(), ROOT);
    }

    // ---------------------------------------------------------------
    // 2. IMAGE_ID is placeholder zero until guest is compiled
    // ---------------------------------------------------------------
    function test_imageId_isPlaceholderZero() public view {
        // IMAGE_ID should be bytes32(0) until the guest ELF is compiled
        assertEq(balanceVerifier.IMAGE_ID(), bytes32(0));
    }

    // ---------------------------------------------------------------
    // 3. verifyBalance succeeds with correct root and amount
    // ---------------------------------------------------------------
    function test_verifyBalance_succeedsWithCorrectRoot() public {
        uint64 amount = 1000;
        bool result = balanceVerifier.verifyBalance(hex"", ROOT, amount);
        assertTrue(result);
    }

    // ---------------------------------------------------------------
    // 4. verifyBalance reverts with wrong root
    // ---------------------------------------------------------------
    function test_verifyBalance_revertsWithWrongRoot() public {
        bytes32 wrongRoot = keccak256("wrong-root");
        uint64 amount = 1000;
        vm.expectRevert("Root mismatch");
        balanceVerifier.verifyBalance(hex"", wrongRoot, amount);
    }

    // ---------------------------------------------------------------
    // 5. verifyBalance reverts with zero root
    // ---------------------------------------------------------------
    function test_verifyBalance_revertsWithZeroRoot() public {
        uint64 amount = 1000;
        vm.expectRevert("Root mismatch");
        balanceVerifier.verifyBalance(hex"", bytes32(0), amount);
    }

    // ---------------------------------------------------------------
    // 6. verifyBalance can be called multiple times (no state changes)
    // ---------------------------------------------------------------
    function test_verifyBalance_canBeCalledMultipleTimes() public {
        uint64 amount = 500;
        // Balance proofs are read-only attestations; repeated calls should succeed.
        bool result1 = balanceVerifier.verifyBalance(hex"", ROOT, amount);
        bool result2 = balanceVerifier.verifyBalance(hex"", ROOT, amount);
        assertTrue(result1);
        assertTrue(result2);
    }

    // ---------------------------------------------------------------
    // 7. verifyBalance works with different required amounts
    // ---------------------------------------------------------------
    function test_verifyBalance_differentAmounts() public {
        // Same root, different required_amounts should all succeed.
        bool result1 = balanceVerifier.verifyBalance(hex"", ROOT, 100);
        bool result2 = balanceVerifier.verifyBalance(hex"", ROOT, 999_999);
        bool result3 = balanceVerifier.verifyBalance(hex"", ROOT, 0);
        assertTrue(result1);
        assertTrue(result2);
        assertTrue(result3);
    }

    // ---------------------------------------------------------------
    // 8. BalanceProofVerified event is emitted on success
    // ---------------------------------------------------------------
    function test_balanceProofVerified_eventEmitted() public {
        uint64 amount = 1000;
        vm.expectEmit(true, false, false, true);
        emit BalanceVerifier.BalanceProofVerified(ROOT, amount);
        balanceVerifier.verifyBalance(hex"", ROOT, amount);
    }
}

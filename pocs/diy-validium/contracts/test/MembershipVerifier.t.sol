// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";
import {MembershipVerifier} from "../src/MembershipVerifier.sol";

/// @dev Mock verifier that always succeeds (no-op verify).
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {}
}

contract MembershipVerifierTest is Test {
    MembershipVerifier internal membershipVerifier;
    MockRiscZeroVerifier internal mockVerifier;

    bytes32 internal constant ROOT = keccak256("test-allowlist-root");

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        membershipVerifier = new MembershipVerifier(mockVerifier, ROOT);
    }

    function test_constructor_setsState() public view {
        assertEq(address(membershipVerifier.verifier()), address(mockVerifier));
        assertEq(membershipVerifier.allowlistRoot(), ROOT);
    }

    function test_verifyMembership_succeedsWithCorrectRoot() public {
        bool result = membershipVerifier.verifyMembership(hex"", ROOT);
        assertTrue(result);
    }

    function test_verifyMembership_revertsWithWrongRoot() public {
        bytes32 wrongRoot = keccak256("wrong-root");
        vm.expectRevert("Root mismatch");
        membershipVerifier.verifyMembership(hex"", wrongRoot);
    }
}

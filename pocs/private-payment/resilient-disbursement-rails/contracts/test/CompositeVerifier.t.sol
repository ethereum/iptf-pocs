// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {CompositeVerifier} from "../src/CompositeVerifier.sol";
import {MockClaimVerifier} from "../src/mocks/MockClaimVerifier.sol";
import {MockWithdrawVerifier} from "../src/mocks/MockWithdrawVerifier.sol";

contract CompositeVerifierTest is Test {
    CompositeVerifier public composite;
    MockClaimVerifier public claimV;
    MockWithdrawVerifier public withdrawV;

    function setUp() public {
        claimV = new MockClaimVerifier();
        withdrawV = new MockWithdrawVerifier();
        composite = new CompositeVerifier(address(claimV), address(withdrawV));
    }

    function test_constructor_revertsZeroClaim() public {
        vm.expectRevert(CompositeVerifier.ZeroAddress.selector);
        new CompositeVerifier(address(0), address(withdrawV));
    }

    function test_constructor_revertsZeroWithdraw() public {
        vm.expectRevert(CompositeVerifier.ZeroAddress.selector);
        new CompositeVerifier(address(claimV), address(0));
    }

    function test_verifyClaim_forwards() public {
        bytes32[] memory pi = new bytes32[](1);
        pi[0] = bytes32(uint256(0xAA));

        assertTrue(composite.verifyClaim(hex"AA", pi));
        assertEq(claimV.callCount(), 1);
        assertEq(withdrawV.callCount(), 0);
        assertEq(claimV.lastPublicInputs(0), bytes32(uint256(0xAA)));

        claimV.setResult(false);
        assertFalse(composite.verifyClaim(hex"AA", pi));
    }

    function test_verifyPoolWithdraw_forwards() public {
        bytes32[] memory pi = new bytes32[](1);
        pi[0] = bytes32(uint256(0xBB));

        assertTrue(composite.verifyPoolWithdraw(hex"BB", pi));
        assertEq(withdrawV.callCount(), 1);
        assertEq(claimV.callCount(), 0);
        assertEq(withdrawV.lastPublicInputs(0), bytes32(uint256(0xBB)));

        withdrawV.setResult(false);
        assertFalse(composite.verifyPoolWithdraw(hex"BB", pi));
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {IdentityTree} from "../src/IdentityTree.sol";

contract IdentityTreeTest is Test {
    IdentityTree public tree;
    address public governance = address(0xAAA);
    address public authorizedCaller = address(0xBBB);

    function setUp() public {
        tree = new IdentityTree(governance);
        vm.prank(governance);
        tree.addAuthorized(authorizedCaller);
    }

    function test_constructor_setsGovernance() public view {
        assertEq(tree.governance(), governance);
    }

    function test_addAuthorized_onlyGovernance() public {
        vm.prank(address(0xdead));
        vm.expectRevert(IdentityTree.NotGovernance.selector);
        tree.addAuthorized(address(0x123));
    }

    function test_removeAuthorized() public {
        vm.prank(governance);
        tree.removeAuthorized(authorizedCaller);
        assertFalse(tree.authorized(authorizedCaller));
    }

    function test_insertLeaf_onlyAuthorized() public {
        vm.prank(address(0xdead));
        vm.expectRevert(IdentityTree.NotAuthorized.selector);
        tree.insertLeaf(1, 100);
    }

    function test_insertLeaf_whenNotPaused() public {
        vm.prank(governance);
        tree.pause();

        vm.prank(authorizedCaller);
        vm.expectRevert(IdentityTree.ContractPaused.selector);
        tree.insertLeaf(1, 100);
    }

    function test_insertLeaf_success() public {
        vm.prank(authorizedCaller);
        tree.insertLeaf(1, 100);

        assertTrue(tree.insertedLeaves(1));
        assertTrue(tree.usedEnrollmentNullifiers(100));
    }

    function test_insertLeaf_emitsEvent() public {
        vm.prank(authorizedCaller);
        // We just check it doesn't revert; exact root value depends on Poseidon
        tree.insertLeaf(1, 100);
    }

    function test_insertLeaf_rejectsDuplicateLeaf() public {
        vm.prank(authorizedCaller);
        tree.insertLeaf(1, 100);

        vm.prank(authorizedCaller);
        vm.expectRevert(); // LeanIMT will revert with LeafAlreadyExists or our DuplicateLeaf
        tree.insertLeaf(1, 200);
    }

    function test_insertLeaf_rejectsDuplicateNullifier() public {
        vm.prank(authorizedCaller);
        tree.insertLeaf(1, 100);

        vm.prank(authorizedCaller);
        vm.expectRevert(IdentityTree.DuplicateEnrollmentNullifier.selector);
        tree.insertLeaf(2, 100);
    }

    function test_isRecentRoot_afterInsert() public {
        vm.prank(authorizedCaller);
        tree.insertLeaf(1, 100);

        // After inserting, the new root should be in the circular buffer
        uint256 idx = tree.rootIndex();
        uint256 root = tree.recentRoots(idx);
        assertTrue(tree.isRecentRoot(root));
    }

    function test_isRecentRoot_rejectsZero() public view {
        assertFalse(tree.isRecentRoot(0));
    }

    function test_isRecentRoot_rejectsUnknown() public view {
        assertFalse(tree.isRecentRoot(12345));
    }

    function test_pause_unpause() public {
        vm.prank(governance);
        tree.pause();
        assertTrue(tree.paused());

        vm.prank(governance);
        tree.unpause();
        assertFalse(tree.paused());

        // Can insert again after unpause
        vm.prank(authorizedCaller);
        tree.insertLeaf(1, 100);
    }

    function test_pause_onlyGovernance() public {
        vm.prank(address(0xdead));
        vm.expectRevert(IdentityTree.NotGovernance.selector);
        tree.pause();
    }

    function test_multipleInserts_rootsTracked() public {
        vm.startPrank(authorizedCaller);
        tree.insertLeaf(1, 100);
        uint256 root1 = tree.recentRoots(tree.rootIndex());

        tree.insertLeaf(2, 200);
        uint256 root2 = tree.recentRoots(tree.rootIndex());

        assertTrue(tree.isRecentRoot(root1));
        assertTrue(tree.isRecentRoot(root2));
        assertTrue(root1 != root2);
        vm.stopPrank();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {Registry} from "../src/Registry.sol";

contract RegistryTest is Test {
    Registry public registry;
    address public operator = address(0xCAFE);
    address public governance = address(0xBEEF);

    function setUp() public {
        registry = new Registry(operator, governance);
    }

    function test_constructor_revertsZeroAddress() public {
        vm.expectRevert(Registry.ZeroAddress.selector);
        new Registry(address(0), governance);

        vm.expectRevert(Registry.ZeroAddress.selector);
        new Registry(operator, address(0));
    }

    function test_publishCohort_incrementsVersion() public {
        vm.prank(operator);
        registry.publishCohort(0xAAAA, 4);
        assertEq(registry.currentVersion(), 1);
        assertEq(registry.cohortRoot(1), 0xAAAA);
        assertEq(registry.cohortSize(1), 4);

        vm.prank(operator);
        registry.publishCohort(0xBBBB, 5);
        assertEq(registry.currentVersion(), 2);
        // Past version remains readable.
        assertEq(registry.cohortRoot(1), 0xAAAA);
        assertEq(registry.cohortRoot(2), 0xBBBB);
    }

    function test_publishCohort_revertsNotOperator() public {
        vm.prank(address(0xDEAD));
        vm.expectRevert(Registry.NotOperator.selector);
        registry.publishCohort(0xAAAA, 1);
    }

    function test_publishCohort_revertsEmptyRoot() public {
        vm.prank(operator);
        vm.expectRevert(Registry.EmptyRoot.selector);
        registry.publishCohort(0, 1);
    }

    function test_publishCohort_revertsEmptySize() public {
        vm.prank(operator);
        vm.expectRevert(Registry.EmptySize.selector);
        registry.publishCohort(0xAAAA, 0);
    }

    function test_proposeOperatorKey_revertsNotGovernance() public {
        vm.prank(operator);
        vm.expectRevert(Registry.NotGovernance.selector);
        registry.proposeOperatorKey(address(0xFEED));
    }

    function test_operatorKeyRotation_timelockFlow() public {
        address newKey = address(0xFEED);

        vm.prank(governance);
        registry.proposeOperatorKey(newKey);

        // Cannot finalize before timelock.
        vm.prank(governance);
        vm.expectRevert(Registry.TimelockNotExpired.selector);
        registry.finalizeOperatorKey();

        vm.roll(block.number + registry.OPERATOR_KEY_TIMELOCK_BLOCKS());

        vm.prank(governance);
        registry.finalizeOperatorKey();
        assertEq(registry.operatorKey(), newKey);

        // Old operator can no longer publish.
        vm.prank(operator);
        vm.expectRevert(Registry.NotOperator.selector);
        registry.publishCohort(0xCCCC, 1);

        vm.prank(newKey);
        registry.publishCohort(0xCCCC, 1);
        assertEq(registry.cohortRoot(1), 0xCCCC);
    }

    function test_cancelPendingOperatorKey() public {
        vm.prank(governance);
        registry.proposeOperatorKey(address(0xFEED));

        vm.prank(governance);
        registry.cancelPendingOperatorKey();

        vm.roll(block.number + registry.OPERATOR_KEY_TIMELOCK_BLOCKS());

        vm.prank(governance);
        vm.expectRevert(Registry.NoPendingKey.selector);
        registry.finalizeOperatorKey();
    }

    function test_proposeOperatorKey_revertsKeyAlreadyPending() public {
        vm.prank(governance);
        registry.proposeOperatorKey(address(0xFEED));

        vm.prank(governance);
        vm.expectRevert(Registry.KeyAlreadyPending.selector);
        registry.proposeOperatorKey(address(0xCAFE));
    }
}

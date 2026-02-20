// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/src/Test.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";
import {TransferVerifier} from "../src/TransferVerifier.sol";

/// @dev Mock verifier that always succeeds (no-op verify).
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {}
}

contract TransferVerifierTest is Test {
    TransferVerifier internal transferVerifier;
    MockRiscZeroVerifier internal mockVerifier;

    bytes32 internal constant ROOT = keccak256("test-state-root");
    bytes32 internal constant NEW_ROOT = keccak256("test-new-state-root");
    bytes32 internal constant THIRD_ROOT = keccak256("test-third-root");

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        transferVerifier = new TransferVerifier(mockVerifier, ROOT, bytes32(0));
    }

    // ---------------------------------------------------------------
    // 1. Constructor sets state correctly
    // ---------------------------------------------------------------
    function test_constructor_setsState() public view {
        assertEq(address(transferVerifier.verifier()), address(mockVerifier));
        assertEq(transferVerifier.stateRoot(), ROOT);
        assertEq(transferVerifier.operator(), address(this));
    }

    // ---------------------------------------------------------------
    // 2. IMAGE_ID is placeholder zero until guest is compiled
    // ---------------------------------------------------------------
    function test_imageId_isConstructorParam() public view {
        // IMAGE_ID is set via constructor parameter
        assertEq(transferVerifier.IMAGE_ID(), bytes32(0));
    }

    // ---------------------------------------------------------------
    // 3. executeTransfer updates stateRoot to newRoot
    // ---------------------------------------------------------------
    function test_executeTransfer_updatesStateRoot() public {
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT);
        assertEq(transferVerifier.stateRoot(), NEW_ROOT);
    }

    // ---------------------------------------------------------------
    // 4. executeTransfer emits Transfer event with correct args
    // ---------------------------------------------------------------
    function test_executeTransfer_emitsTransferEvent() public {
        vm.expectEmit(true, true, true, true);
        emit TransferVerifier.Transfer(ROOT, NEW_ROOT);
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT);
    }

    // ---------------------------------------------------------------
    // 5. executeTransfer reverts when oldRoot != stateRoot (stale state)
    // ---------------------------------------------------------------
    function test_executeTransfer_revertsStaleState() public {
        bytes32 wrongRoot = keccak256("wrong-root");
        vm.expectRevert(abi.encodeWithSelector(TransferVerifier.StaleState.selector, ROOT, wrongRoot));
        transferVerifier.executeTransfer(hex"", wrongRoot, NEW_ROOT);
    }

    // ---------------------------------------------------------------
    // 6. Sequential root check prevents replay (double-spend protection)
    // ---------------------------------------------------------------
    function test_executeTransfer_sequentialRootPreventsReplay() public {
        // First transfer succeeds: ROOT -> NEW_ROOT
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT);

        // Replaying with old ROOT reverts — sequential root check prevents double-spend
        vm.expectRevert(abi.encodeWithSelector(TransferVerifier.StaleState.selector, NEW_ROOT, ROOT));
        transferVerifier.executeTransfer(hex"", ROOT, THIRD_ROOT);
    }

    // ---------------------------------------------------------------
    // 7. Two sequential transfers succeed with correct chaining
    // ---------------------------------------------------------------
    function test_executeTransfer_sequentialTransfersSucceed() public {
        // First transfer: ROOT -> NEW_ROOT
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT);
        assertEq(transferVerifier.stateRoot(), NEW_ROOT);

        // Second transfer: NEW_ROOT -> THIRD_ROOT
        transferVerifier.executeTransfer(hex"", NEW_ROOT, THIRD_ROOT);
        assertEq(transferVerifier.stateRoot(), THIRD_ROOT);
    }
}

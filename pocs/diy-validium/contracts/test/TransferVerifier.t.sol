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
    bytes32 internal constant NULLIFIER = keccak256("test-nullifier");
    bytes32 internal constant OTHER_NULLIFIER = keccak256("test-nullifier-2");

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        transferVerifier = new TransferVerifier(mockVerifier, ROOT);
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
    function test_imageId_isPlaceholderZero() public view {
        // IMAGE_ID should be bytes32(0) until the guest ELF is compiled
        assertEq(transferVerifier.IMAGE_ID(), bytes32(0));
    }

    // ---------------------------------------------------------------
    // 3. executeTransfer updates stateRoot to newRoot
    // ---------------------------------------------------------------
    function test_executeTransfer_updatesStateRoot() public {
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT, NULLIFIER);
        assertEq(transferVerifier.stateRoot(), NEW_ROOT);
    }

    // ---------------------------------------------------------------
    // 4. executeTransfer marks nullifier as used
    // ---------------------------------------------------------------
    function test_executeTransfer_marksNullifierUsed() public {
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT, NULLIFIER);
        assertTrue(transferVerifier.nullifiers(NULLIFIER));
    }

    // ---------------------------------------------------------------
    // 5. executeTransfer emits Transfer event with correct args
    // ---------------------------------------------------------------
    function test_executeTransfer_emitsTransferEvent() public {
        vm.expectEmit(true, true, true, true);
        emit TransferVerifier.Transfer(ROOT, NEW_ROOT, NULLIFIER);
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT, NULLIFIER);
    }

    // ---------------------------------------------------------------
    // 6. executeTransfer reverts when oldRoot != stateRoot (stale state)
    // ---------------------------------------------------------------
    function test_executeTransfer_revertsStaleState() public {
        bytes32 wrongRoot = keccak256("wrong-root");
        vm.expectRevert(abi.encodeWithSelector(TransferVerifier.StaleState.selector, ROOT, wrongRoot));
        transferVerifier.executeTransfer(hex"", wrongRoot, NEW_ROOT, NULLIFIER);
    }

    // ---------------------------------------------------------------
    // 7. executeTransfer reverts when nullifier already used (double-spend)
    // ---------------------------------------------------------------
    function test_executeTransfer_revertsDoubleSpend() public {
        // First transfer succeeds
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT, NULLIFIER);

        // Second transfer with the same nullifier should revert
        vm.expectRevert(abi.encodeWithSelector(TransferVerifier.NullifierAlreadyUsed.selector, NULLIFIER));
        transferVerifier.executeTransfer(hex"", NEW_ROOT, keccak256("another-root"), NULLIFIER);
    }

    // ---------------------------------------------------------------
    // 8. Second transfer with same nullifier reverts even with different roots
    // ---------------------------------------------------------------
    function test_executeTransfer_revertsWithDifferentNullifier() public {
        // First transfer succeeds
        transferVerifier.executeTransfer(hex"", ROOT, NEW_ROOT, NULLIFIER);

        // Second transfer with same nullifier but different roots reverts
        bytes32 thirdRoot = keccak256("third-root");
        vm.expectRevert(abi.encodeWithSelector(TransferVerifier.NullifierAlreadyUsed.selector, NULLIFIER));
        transferVerifier.executeTransfer(hex"", NEW_ROOT, thirdRoot, NULLIFIER);
    }
}

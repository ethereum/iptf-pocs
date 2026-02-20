// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/src/Test.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";
import {DisclosureVerifier} from "../src/DisclosureVerifier.sol";

/// @dev Mock verifier that always succeeds (no-op verify).
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    bytes public lastSeal;
    bytes32 public lastImageId;
    bytes32 public lastJournalDigest;

    function verify(bytes calldata seal, bytes32 imageId, bytes32 journalDigest) external pure override {}
}

/// @dev Mock verifier that captures arguments for inspection.
/// Note: Does not declare `is IRiscZeroVerifier` because the interface marks
/// verify as `view`, but this mock needs to write state. ABI-compatible at
/// runtime when called via CALL (non-view caller).
contract CapturingRiscZeroVerifier {
    bytes32 public lastJournalDigest;

    function verify(bytes calldata, bytes32, bytes32 journalDigest) external {
        lastJournalDigest = journalDigest;
    }
}

contract DisclosureVerifierTest is Test {
    DisclosureVerifier internal disclosureVerifier;
    MockRiscZeroVerifier internal mockVerifier;

    bytes32 internal constant ROOT = keccak256("test-state-root");
    uint64 internal constant THRESHOLD = 1000;
    bytes32 internal constant DK_HASH = keccak256("test-disclosure-key");

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        disclosureVerifier = new DisclosureVerifier(mockVerifier, ROOT, bytes32(0));
    }

    // ---------------------------------------------------------------
    // 1. Constructor sets state correctly
    // ---------------------------------------------------------------
    function test_constructor_setsState() public view {
        assertEq(address(disclosureVerifier.verifier()), address(mockVerifier));
        assertEq(disclosureVerifier.stateRoot(), ROOT);
    }

    // ---------------------------------------------------------------
    // 2. IMAGE_ID is set via constructor parameter
    // ---------------------------------------------------------------
    function test_imageId_isConstructorParam() public view {
        assertEq(disclosureVerifier.IMAGE_ID(), bytes32(0));
    }

    // ---------------------------------------------------------------
    // 3. verifyDisclosure emits DisclosureVerified with correct args
    // ---------------------------------------------------------------
    function test_verifyDisclosure_emitsEvent() public {
        vm.expectEmit(true, true, true, true);
        emit DisclosureVerifier.DisclosureVerified(ROOT, THRESHOLD, DK_HASH);
        disclosureVerifier.verifyDisclosure(hex"", ROOT, THRESHOLD, DK_HASH);
    }

    // ---------------------------------------------------------------
    // 4. verifyDisclosure reverts when root != stateRoot
    // ---------------------------------------------------------------
    function test_verifyDisclosure_revertsRootMismatch() public {
        bytes32 wrongRoot = keccak256("wrong-root");
        vm.expectRevert("Root mismatch");
        disclosureVerifier.verifyDisclosure(hex"", wrongRoot, THRESHOLD, DK_HASH);
    }

    // ---------------------------------------------------------------
    // 5. verifyDisclosure calls verifier with correct journal encoding
    // ---------------------------------------------------------------
    function test_verifyDisclosure_callsVerifierWithCorrectJournal() public {
        // Deploy a capturing verifier to inspect the journal digest
        CapturingRiscZeroVerifier capturingVerifier = new CapturingRiscZeroVerifier();
        DisclosureVerifier dv = new DisclosureVerifier(IRiscZeroVerifier(address(capturingVerifier)), ROOT, bytes32(0));

        dv.verifyDisclosure(hex"", ROOT, THRESHOLD, DK_HASH);

        // The journal should be abi.encodePacked(root, threshold, disclosureKeyHash)
        bytes memory expectedJournal = abi.encodePacked(ROOT, THRESHOLD, DK_HASH);
        bytes32 expectedDigest = sha256(expectedJournal);
        assertEq(capturingVerifier.lastJournalDigest(), expectedDigest);
    }

    // ---------------------------------------------------------------
    // 6. verifyDisclosure is read-only — stateRoot unchanged after call
    // ---------------------------------------------------------------
    function test_verifyDisclosure_isReadOnly() public {
        bytes32 rootBefore = disclosureVerifier.stateRoot();
        disclosureVerifier.verifyDisclosure(hex"", ROOT, THRESHOLD, DK_HASH);
        bytes32 rootAfter = disclosureVerifier.stateRoot();
        assertEq(rootBefore, rootAfter);
    }
}

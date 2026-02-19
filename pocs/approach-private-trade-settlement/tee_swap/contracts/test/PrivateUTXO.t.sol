// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {PrivateUTXO} from "../src/PrivateUTXO.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";

contract PrivateUTXOTest is Test {
    PrivateUTXO public utxo;
    MockVerifier public verifier;

    // Small values that fit in BN254 scalar field
    bytes32 constant COMMITMENT_0 = bytes32(uint256(1));
    bytes32 constant COMMITMENT_1 = bytes32(uint256(2));
    bytes32 constant COMMITMENT_2 = bytes32(uint256(3));
    bytes32 constant COMMITMENT_3 = bytes32(uint256(4));
    bytes32 constant NULLIFIER_0 = bytes32(uint256(100));
    bytes32 constant NULLIFIER_1 = bytes32(uint256(101));
    bytes32 constant NULLIFIER_2 = bytes32(uint256(102));

    bytes32 constant PK_STEALTH = bytes32(uint256(0xbeef));
    bytes32 constant H_SWAP = bytes32(uint256(0xaaaa));
    bytes32 constant H_R = bytes32(uint256(0xbbbb));
    bytes32 constant H_META = bytes32(uint256(0xcccc));
    bytes32 constant H_ENC = bytes32(uint256(0xdddd));

    uint256 constant TIMEOUT_FUTURE = 2000000000; // ~2033
    uint256 constant TIMEOUT_PAST = 1000000000; // ~2001

    // Events (re-declared for vm.expectEmit)
    event SwapNoteLocked(
        bytes32 indexed commitment,
        uint256 timeout,
        bytes32 pkStealth,
        bytes32 hSwap,
        bytes32 hR,
        bytes32 hMeta,
        bytes32 hEnc
    );
    event NoteCreated(bytes32 indexed commitment);
    event NoteSpent(bytes32 indexed nullifier);

    function setUp() public {
        verifier = new MockVerifier();
        utxo = new PrivateUTXO(address(verifier));

        // Set block.timestamp to a known value
        vm.warp(1700000000); // ~Nov 2023
    }

    // ========== Fund Tests ==========

    function testFund() public {
        vm.expectEmit(true, false, false, false);
        emit NoteCreated(COMMITMENT_0);

        utxo.fund(COMMITMENT_0);

        assertEq(utxo.getCommitmentCount(), 1);
        assertTrue(utxo.commitmentRoot() != bytes32(0));
    }

    function testFundMultiple() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root1 = utxo.commitmentRoot();

        utxo.fund(COMMITMENT_1);
        bytes32 root2 = utxo.commitmentRoot();

        assertEq(utxo.getCommitmentCount(), 2);
        assertTrue(root1 != root2);
        assertTrue(utxo.isKnownRoot(root1)); // Historical root preserved
        assertTrue(utxo.isKnownRoot(root2)); // Current root valid
    }

    function testFundRevertsNonOwner() public {
        vm.prank(address(0xBAD));
        vm.expectRevert(PrivateUTXO.OnlyOwner.selector);
        utxo.fund(COMMITMENT_0);
    }

    function testFundUpdatesRoot() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root1 = utxo.commitmentRoot();

        utxo.fund(COMMITMENT_1);
        bytes32 root2 = utxo.commitmentRoot();

        assertTrue(root1 != root2);
    }

    // ========== Transfer — Standard Mode (timeout=0) ==========

    function testTransferStandard() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        vm.expectEmit(true, false, false, false);
        emit NoteCreated(COMMITMENT_1);
        vm.expectEmit(true, false, false, false);
        emit NoteSpent(NULLIFIER_0);

        utxo.transfer(
            "", NULLIFIER_0, root, COMMITMENT_1, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );

        assertTrue(utxo.nullifiers(NULLIFIER_0));
        assertEq(utxo.getCommitmentCount(), 2);
    }

    function testTransferStandardNoTimeConstraint() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // Should work regardless of timestamp
        vm.warp(1);
        utxo.transfer(
            "", NULLIFIER_0, root, COMMITMENT_1, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );
        assertTrue(utxo.nullifiers(NULLIFIER_0));
    }

    // ========== Transfer — Lock Mode (timeout>0, pkStealth!=0, hSwap!=0) ==========

    function testTransferLock() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        vm.expectEmit(true, false, false, true);
        emit SwapNoteLocked(COMMITMENT_1, TIMEOUT_FUTURE, PK_STEALTH, H_SWAP, H_R, H_META, H_ENC);

        utxo.transfer("", NULLIFIER_0, root, COMMITMENT_1, TIMEOUT_FUTURE, PK_STEALTH, H_SWAP, H_R, H_META, H_ENC);

        assertTrue(utxo.nullifiers(NULLIFIER_0));
        assertEq(utxo.getCommitmentCount(), 2);
    }

    function testTransferLockNoTimeConstraint() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // Lock should work even if current time is past timeout (lock creates the note)
        vm.warp(TIMEOUT_FUTURE + 1);
        utxo.transfer("", NULLIFIER_0, root, COMMITMENT_1, TIMEOUT_FUTURE, PK_STEALTH, H_SWAP, H_R, H_META, H_ENC);

        assertTrue(utxo.nullifiers(NULLIFIER_0));
    }

    function testTransferLockEmitsAllEvents() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        vm.expectEmit(true, false, false, true);
        emit SwapNoteLocked(COMMITMENT_1, TIMEOUT_FUTURE, PK_STEALTH, H_SWAP, H_R, H_META, H_ENC);
        vm.expectEmit(true, false, false, false);
        emit NoteCreated(COMMITMENT_1);
        vm.expectEmit(true, false, false, false);
        emit NoteSpent(NULLIFIER_0);

        utxo.transfer("", NULLIFIER_0, root, COMMITMENT_1, TIMEOUT_FUTURE, PK_STEALTH, H_SWAP, H_R, H_META, H_ENC);
    }

    // ========== Transfer — Claim Mode (timeout>0, pkStealth!=0, hSwap=0) ==========

    function testTransferClaimBeforeTimeout() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // block.timestamp (1700000000) < TIMEOUT_FUTURE (2000000000) → claim succeeds
        utxo.transfer(
            "",
            NULLIFIER_0,
            root,
            COMMITMENT_1,
            TIMEOUT_FUTURE,
            PK_STEALTH,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );

        assertTrue(utxo.nullifiers(NULLIFIER_0));
    }

    function testTransferClaimAtExactTimeout() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // block.timestamp == timeout → claim succeeds (require block.timestamp <= timeout)
        vm.warp(TIMEOUT_FUTURE);
        utxo.transfer(
            "",
            NULLIFIER_0,
            root,
            COMMITMENT_1,
            TIMEOUT_FUTURE,
            PK_STEALTH,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );

        assertTrue(utxo.nullifiers(NULLIFIER_0));
    }

    function testTransferClaimRevertsAfterTimeout() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // block.timestamp > timeout → claim fails
        vm.warp(TIMEOUT_FUTURE + 1);
        vm.expectRevert(PrivateUTXO.ClaimExpired.selector);
        utxo.transfer(
            "",
            NULLIFIER_0,
            root,
            COMMITMENT_1,
            TIMEOUT_FUTURE,
            PK_STEALTH,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
    }

    // ========== Transfer — Refund Mode (timeout>0, pkStealth=0) ==========

    function testTransferRefundAfterTimeout() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // block.timestamp > timeout → refund succeeds
        vm.warp(TIMEOUT_PAST + 1);
        utxo.transfer(
            "",
            NULLIFIER_0,
            root,
            COMMITMENT_1,
            TIMEOUT_PAST,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );

        assertTrue(utxo.nullifiers(NULLIFIER_0));
    }

    function testTransferRefundRevertsBeforeTimeout() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // block.timestamp <= timeout → refund fails
        vm.expectRevert(PrivateUTXO.RefundNotReady.selector);
        utxo.transfer(
            "",
            NULLIFIER_0,
            root,
            COMMITMENT_1,
            TIMEOUT_FUTURE,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
    }

    function testTransferRefundRevertsAtExactTimeout() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // block.timestamp == timeout → refund fails (require block.timestamp > timeout)
        vm.warp(TIMEOUT_FUTURE);
        vm.expectRevert(PrivateUTXO.RefundNotReady.selector);
        utxo.transfer(
            "",
            NULLIFIER_0,
            root,
            COMMITMENT_1,
            TIMEOUT_FUTURE,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
    }

    // ========== Validation Tests ==========

    function testTransferRevertsInvalidProof() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        verifier.setResult(false);

        vm.expectRevert(PrivateUTXO.InvalidProof.selector);
        utxo.transfer(
            "", NULLIFIER_0, root, COMMITMENT_1, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );
    }

    function testTransferRevertsSpentNullifier() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // First transfer succeeds
        utxo.transfer(
            "", NULLIFIER_0, root, COMMITMENT_1, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );

        // Second transfer with same nullifier fails
        bytes32 newRoot = utxo.commitmentRoot();
        vm.expectRevert(PrivateUTXO.NullifierAlreadySpent.selector);
        utxo.transfer(
            "", NULLIFIER_0, newRoot, COMMITMENT_2, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );
    }

    function testTransferRevertsInvalidRoot() public {
        vm.expectRevert(PrivateUTXO.InvalidRoot.selector);
        utxo.transfer(
            "",
            NULLIFIER_0,
            bytes32(uint256(999)),
            COMMITMENT_1,
            0,
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0),
            bytes32(0)
        );
    }

    function testTransferRevertsSpentNullifierAcrossModes() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        // Spend via standard mode
        utxo.transfer(
            "", NULLIFIER_0, root, COMMITMENT_1, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );

        // Try to reuse via lock mode
        bytes32 newRoot = utxo.commitmentRoot();
        vm.expectRevert(PrivateUTXO.NullifierAlreadySpent.selector);
        utxo.transfer("", NULLIFIER_0, newRoot, COMMITMENT_2, TIMEOUT_FUTURE, PK_STEALTH, H_SWAP, H_R, H_META, H_ENC);
    }

    // ========== Historical Roots Tests ==========

    function testIsKnownRootRejectsUnknown() public view {
        assertFalse(utxo.isKnownRoot(bytes32(uint256(999))));
    }

    function testIsKnownRootRejectsZeroRoot() public view {
        // Empty tree has commitmentRoot() == bytes32(0), but isKnownRoot should reject it
        assertFalse(utxo.isKnownRoot(bytes32(0)));
    }

    function testHistoricalRootPreserved() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root1 = utxo.commitmentRoot();

        utxo.fund(COMMITMENT_1);
        bytes32 root2 = utxo.commitmentRoot();

        assertTrue(utxo.isKnownRoot(root1)); // Historical
        assertTrue(utxo.isKnownRoot(root2)); // Current
    }

    function testTransferWithHistoricalRoot() public {
        utxo.fund(COMMITMENT_0);
        bytes32 historicalRoot = utxo.commitmentRoot();

        // Insert another commitment to change the root
        utxo.fund(COMMITMENT_1);

        // Transfer using historical root should succeed
        utxo.transfer(
            "", NULLIFIER_0, historicalRoot, COMMITMENT_2, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );

        assertTrue(utxo.nullifiers(NULLIFIER_0));
    }

    function testValidRootsMapping() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root1 = utxo.commitmentRoot();
        assertFalse(utxo.validRoots(root1)); // Current root not in validRoots

        utxo.fund(COMMITMENT_1);
        assertTrue(utxo.validRoots(root1)); // Now it's historical
    }

    // ========== Commitment Count / Root Tests ==========

    function testInitialState() public view {
        assertEq(utxo.getCommitmentCount(), 0);
        assertEq(utxo.commitmentRoot(), bytes32(0));
    }

    function testCommitmentCountAfterTransfer() public {
        utxo.fund(COMMITMENT_0);
        bytes32 root = utxo.commitmentRoot();

        utxo.transfer(
            "", NULLIFIER_0, root, COMMITMENT_1, 0, bytes32(0), bytes32(0), bytes32(0), bytes32(0), bytes32(0)
        );

        assertEq(utxo.getCommitmentCount(), 2); // 1 fund + 1 transfer output
    }
}

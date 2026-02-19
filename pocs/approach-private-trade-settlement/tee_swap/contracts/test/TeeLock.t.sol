// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {TeeLock} from "../src/TeeLock.sol";

contract TeeLockTest is Test {
    TeeLock public teeLock;

    address public teeAddress;
    address public nonTeeAddress;

    bytes32 constant SWAP_ID = bytes32(uint256(0x1234));
    bytes32 constant SWAP_ID_2 = bytes32(uint256(0x5678));
    bytes32 constant EPH_KEY_A = bytes32(uint256(0xaaaa));
    bytes32 constant EPH_KEY_B = bytes32(uint256(0xbbbb));
    bytes32 constant ENC_SALT_A = bytes32(uint256(0xcccc));
    bytes32 constant ENC_SALT_B = bytes32(uint256(0xdddd));

    event SwapRevealed(bytes32 indexed swapId);

    function setUp() public {
        teeAddress = address(0x7EE);
        nonTeeAddress = address(0xBAD);
        teeLock = new TeeLock(teeAddress);
    }

    // ========== announceSwap Tests ==========

    function testAnnounceSwap() public {
        vm.prank(teeAddress);

        vm.expectEmit(true, false, false, false);
        emit SwapRevealed(SWAP_ID);

        teeLock.announceSwap(SWAP_ID, EPH_KEY_A, EPH_KEY_B, ENC_SALT_A, ENC_SALT_B);

        (bool revealed, bytes32 ephA, bytes32 ephB, bytes32 encA, bytes32 encB, uint256 ts) =
            teeLock.announcements(SWAP_ID);

        assertTrue(revealed);
        assertEq(ephA, EPH_KEY_A);
        assertEq(ephB, EPH_KEY_B);
        assertEq(encA, ENC_SALT_A);
        assertEq(encB, ENC_SALT_B);
        assertEq(ts, block.timestamp);
    }

    function testAnnounceSwapRevertsNonTEE() public {
        vm.prank(nonTeeAddress);
        vm.expectRevert(TeeLock.OnlyTEE.selector);
        teeLock.announceSwap(SWAP_ID, EPH_KEY_A, EPH_KEY_B, ENC_SALT_A, ENC_SALT_B);
    }

    function testAnnounceSwapRevertsDuplicate() public {
        vm.prank(teeAddress);
        teeLock.announceSwap(SWAP_ID, EPH_KEY_A, EPH_KEY_B, ENC_SALT_A, ENC_SALT_B);

        vm.prank(teeAddress);
        vm.expectRevert(TeeLock.SwapAlreadyRevealed.selector);
        teeLock.announceSwap(SWAP_ID, EPH_KEY_A, EPH_KEY_B, ENC_SALT_A, ENC_SALT_B);
    }

    function testAnnounceSwapMultipleDistinctSwaps() public {
        vm.prank(teeAddress);
        teeLock.announceSwap(SWAP_ID, EPH_KEY_A, EPH_KEY_B, ENC_SALT_A, ENC_SALT_B);

        vm.prank(teeAddress);
        teeLock.announceSwap(SWAP_ID_2, EPH_KEY_B, EPH_KEY_A, ENC_SALT_B, ENC_SALT_A);

        (bool revealed1,,,,,) = teeLock.announcements(SWAP_ID);
        (bool revealed2,,,,,) = teeLock.announcements(SWAP_ID_2);

        assertTrue(revealed1);
        assertTrue(revealed2);
    }

    function testAnnouncementNotRevealedByDefault() public view {
        (bool revealed,,,,,) = teeLock.announcements(SWAP_ID);
        assertFalse(revealed);
    }

    function testTeeAddress() public view {
        assertEq(teeLock.tee(), teeAddress);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/src/Test.sol";
import { TeeSwap } from "../src/TeeSwap.sol";

contract TeeSwapTest is Test {
    TeeSwap public teeSwap;

    function setUp() public {
        teeSwap = new TeeSwap();
        teeSwap.setNumber(0);
    }

    function test_Increment() public {
        teeSwap.increment();
        assertEq(teeSwap.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        teeSwap.setNumber(x);
        assertEq(teeSwap.number(), x);
    }
}

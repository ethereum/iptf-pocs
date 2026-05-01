// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/src/Test.sol";
import { ResilientDisbursementRails } from "../src/ResilientDisbursementRails.sol";

contract ResilientDisbursementRailsTest is Test {
    ResilientDisbursementRails public resilientDisbursementRails;

    function setUp() public {
        resilientDisbursementRails = new ResilientDisbursementRails();
        resilientDisbursementRails.setNumber(0);
    }

    function test_Increment() public {
        resilientDisbursementRails.increment();
        assertEq(resilientDisbursementRails.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        resilientDisbursementRails.setNumber(x);
        assertEq(resilientDisbursementRails.number(), x);
    }
}

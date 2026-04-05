// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/src/Test.sol";
import { ResilientPrivateIdentity } from "../src/ResilientPrivateIdentity.sol";

contract ResilientPrivateIdentityTest is Test {
    ResilientPrivateIdentity public resilientPrivateIdentity;

    function setUp() public {
        resilientPrivateIdentity = new ResilientPrivateIdentity();
        resilientPrivateIdentity.setNumber(0);
    }

    function test_Increment() public {
        resilientPrivateIdentity.increment();
        assertEq(resilientPrivateIdentity.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        resilientPrivateIdentity.setNumber(x);
        assertEq(resilientPrivateIdentity.number(), x);
    }
}

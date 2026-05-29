// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import { ShieldedPoolExt } from "../src/ShieldedPoolExt.sol";

contract ShieldedPoolExtTest is Test {
    function test_placeholder() public {
        // TODO: tests for epoch rollover, active-tree pre/post root acceptance,
        // frozen-root publication, replay/double-spend rejection.
        assertTrue(true);
    }
}

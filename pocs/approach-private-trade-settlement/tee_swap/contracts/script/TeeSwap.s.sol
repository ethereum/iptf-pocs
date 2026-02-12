// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/src/Script.sol";
import { TeeSwap } from "../src/TeeSwap.sol";

contract TeeSwapScript is Script {
    TeeSwap public teeSwap;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        teeSwap = new TeeSwap();

        vm.stopBroadcast();
    }
}

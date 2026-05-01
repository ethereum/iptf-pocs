// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/src/Script.sol";
import { ResilientDisbursementRails } from "../src/ResilientDisbursementRails.sol";

contract ResilientDisbursementRailsScript is Script {
    ResilientDisbursementRails public resilientDisbursementRails;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        resilientDisbursementRails = new ResilientDisbursementRails();

        vm.stopBroadcast();
    }
}

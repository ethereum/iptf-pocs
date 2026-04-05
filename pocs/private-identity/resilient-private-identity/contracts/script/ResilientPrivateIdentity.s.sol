// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/src/Script.sol";
import { ResilientPrivateIdentity } from "../src/ResilientPrivateIdentity.sol";

contract ResilientPrivateIdentityScript is Script {
    ResilientPrivateIdentity public resilientPrivateIdentity;

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        resilientPrivateIdentity = new ResilientPrivateIdentity();

        vm.stopBroadcast();
    }
}

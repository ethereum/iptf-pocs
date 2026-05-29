// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/src/Script.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        // TODO: deploy attestation registry, mock token, verifiers, ShieldedPoolExt.
        vm.stopBroadcast();
    }
}

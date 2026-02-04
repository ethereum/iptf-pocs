// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/src/Script.sol";
import {Config} from "forge-std/src/Config.sol";
import {HonkVerifier as DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {HonkVerifier as TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {HonkVerifier as WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

/// @title Deploy
/// @notice Deployment script for shielded pool contracts
contract Deploy is Script, Config {
    function run() public {
        _loadConfig("./deployments.toml", true);

        vm.startBroadcast();

        address depositVerifier = address(new DepositVerifier());
        address transferVerifier = address(new TransferVerifier());
        address withdrawVerifier = address(new WithdrawVerifier());

        vm.stopBroadcast();

        config.set("deposit_verifier_address", depositVerifier);
        config.set("transfer_verifier_address", transferVerifier);
        config.set("withdraw_verifier_address", withdrawVerifier);

        // Log summary
        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("deposit verifier: ", depositVerifier);
        console.log("transfer verifier: ", transferVerifier);
        console.log("withdraw verifier: ", withdrawVerifier);
    }
}

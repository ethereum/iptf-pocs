// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/src/Script.sol";
import {Config} from "forge-std/src/Config.sol";
import {PrivateUTXO} from "../src/PrivateUTXO.sol";
import {TeeLock} from "../src/TeeLock.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";

/// @title Deploy
/// @notice Deployment script for TEE swap contracts
contract Deploy is Script, Config {
    function run() public {
        _loadConfig("./deployments.toml", true);

        bool useMockVerifier = config.get("use_mock_verifier").toBool();

        vm.startBroadcast();

        // Deploy verifier
        address verifierAddress;
        if (useMockVerifier) {
            MockVerifier mockVerifier = new MockVerifier();
            verifierAddress = address(mockVerifier);
            console.log("MockVerifier deployed at:", verifierAddress);
        } else {
            verifierAddress = config.get("verifier_address").toAddress();
            console.log("Using existing verifier at:", verifierAddress);
        }

        // Deploy PrivateUTXO
        PrivateUTXO privateUtxo = new PrivateUTXO(verifierAddress);
        console.log("PrivateUTXO deployed at:", address(privateUtxo));

        // Deploy TeeLock with deployer as TEE address
        TeeLock teeLock = new TeeLock(msg.sender);
        console.log("TeeLock deployed at:", address(teeLock));

        vm.stopBroadcast();

        config.set("verifier_address", verifierAddress);
        config.set("private_utxo_address", address(privateUtxo));
        config.set("tee_lock_address", address(teeLock));

        // Log summary
        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Chain ID:", block.chainid);
        console.log("Verifier:", verifierAddress);
        console.log("PrivateUTXO:", address(privateUtxo));
        console.log("TeeLock:", address(teeLock));
    }
}

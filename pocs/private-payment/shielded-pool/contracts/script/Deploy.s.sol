// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/src/Script.sol";
import {Config} from "forge-std/src/Config.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockVerifier} from "../src/mocks/MockVerifier.sol";
import {CompositeVerifier} from "../src/CompositeVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {HonkVerifier as DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {HonkVerifier as TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {HonkVerifier as WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";

/// @title Deploy
/// @notice Deployment script for shielded pool contracts
contract Deploy is Script, Config {
    function run() public {
        _loadConfig("./deployments.toml", true);

        bool useMockVerifier = config.get("use_mock_verifier").toBool();

        vm.startBroadcast();

        AttestationRegistry registry = new AttestationRegistry();
        address registryAddress = address(registry);
        console.log("AttestationRegistry deployed at:", registryAddress);

        // Deploy or use existing Verifier
        address verifierAddress;
        if (useMockVerifier) {
            // Deploy MockVerifier and use it for all three circuit verifiers
            MockVerifier mockVerifier = new MockVerifier();
            address mockVerifierAddr = address(mockVerifier);
            console.log("MockVerifier deployed at:", mockVerifierAddr);

            CompositeVerifier compositeVerifier = new CompositeVerifier(
                mockVerifierAddr, // deposit verifier
                mockVerifierAddr, // transfer verifier
                mockVerifierAddr // withdraw verifier
            );
            verifierAddress = address(compositeVerifier);
            console.log("CompositeVerifier (mock) deployed at:", verifierAddress);
        } else {
            address depositVerifier = config.get("deposit_verifier_address").toAddress();
            address transferVerifier = config.get("transfer_verifier_address").toAddress();
            address withdrawVerifier = config.get("withdraw_verifier_address").toAddress();

            // Deploy CompositeVerifier with the real circuit verifiers
            CompositeVerifier compositeVerifier =
                new CompositeVerifier(depositVerifier, transferVerifier, withdrawVerifier);
            verifierAddress = address(compositeVerifier);
            console.log("CompositeVerifier (real) deployed at:", verifierAddress);
        }

        // Deploy ShieldedPool
        ShieldedPool pool = new ShieldedPool(verifierAddress, registryAddress);
        console.log("ShieldedPool deployed at:", address(pool));

        // Deploy MockERC20 for testing
        MockERC20 mockToken = new MockERC20("Mock USDC", "mUSDC", 6);
        address mockTokenAddress = address(mockToken);
        console.log("MockERC20 deployed at:", mockTokenAddress);

        vm.stopBroadcast();

        config.set("shielded_pool_address", address(pool));
        config.set("composite_verifier_address", verifierAddress);
        config.set("attestation_registry_address", registryAddress);
        config.set("mock_token_address", mockTokenAddress);

        // Log summary
        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Chain ID:", block.chainid);
        console.log("AttestationRegistry:", registryAddress);
        console.log("CompositeVerifier:", verifierAddress);
        console.log("ShieldedPool:", address(pool));
        console.log("MockERC20:", mockTokenAddress);
    }
}

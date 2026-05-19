// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {Config} from "forge-std/Config.sol";
import {PetitionRegistry} from "../src/PetitionRegistry.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {MockBatchVerifier} from "../src/mocks/MockBatchVerifier.sol";
import {MockResolutionVerifier} from "../src/mocks/MockResolutionVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {HonkVerifier as BatchVerifier} from "../src/verifiers/BatchVerifier.sol";
import {HonkVerifier as ResolutionVerifier} from "../src/verifiers/ResolutionVerifier.sol";

/// @title Deploy
/// @notice With `USE_MOCK_VERIFIER=true` deploys mock SNARK verifiers
///         (accept any bytes); with `false` deploys the Honk verifiers
///         emitted by `scripts/generate-verifiers.sh`.
contract Deploy is Script, Config {
    function run() public {
        _loadConfig("./deployments.toml", true);

        bool useMockVerifier = config.get("use_mock_verifier").toBool();
        address governance = config.get("governance").toAddress();
        bytes32 emptyImtRoot = vm.envBytes32("EMPTY_IMT_ROOT");
        bytes32 pinnedSignerVkHash = vm.envBytes32("PINNED_SIGNER_VK_HASH");

        vm.startBroadcast();

        MockERC20 mockToken = new MockERC20("Mock USDC", "mUSDC", 6);
        console.log("MockERC20:", address(mockToken));

        address batchVerifierAddr;
        address resolutionVerifierAddr;
        if (useMockVerifier) {
            batchVerifierAddr = address(new MockBatchVerifier());
            resolutionVerifierAddr = address(new MockResolutionVerifier());
            console.log("MockBatchVerifier:", batchVerifierAddr);
            console.log("MockResolutionVerifier:", resolutionVerifierAddr);
        } else {
            batchVerifierAddr = address(new BatchVerifier());
            resolutionVerifierAddr = address(new ResolutionVerifier());
            console.log("BatchVerifier:", batchVerifierAddr);
            console.log("ResolutionVerifier:", resolutionVerifierAddr);
        }

        PetitionRegistry registry = new PetitionRegistry(
            PetitionRegistry.InitArgs({
                batchVerifier: IVerifier(batchVerifierAddr),
                resolutionVerifier: IVerifier(resolutionVerifierAddr),
                bountyToken: address(mockToken),
                governance: governance,
                alpha: uint64(1),
                alphaMin: uint64(1),
                alphaMax: uint64(1_000),
                srsHash: bytes32(0),
                attrCount: uint8(4),
                emptyImtRoot: emptyImtRoot,
                pinnedSignerVkHash: pinnedSignerVkHash
            })
        );
        console.log("PetitionRegistry:", address(registry));

        vm.stopBroadcast();

        config.set("bounty_token_address", address(mockToken));
        config.set("petition_registry_address", address(registry));
        config.set("batch_verifier_address", batchVerifierAddr);
        config.set("resolution_verifier_address", resolutionVerifierAddr);

        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Chain ID:", block.chainid);
        console.log("MockERC20:", address(mockToken));
        console.log("PetitionRegistry:", address(registry));
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {TransferVerifier} from "../src/TransferVerifier.sol";
import {ValidiumBridge} from "../src/ValidiumBridge.sol";
import {DisclosureVerifier} from "../src/DisclosureVerifier.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";

/// @notice Mock RISC Zero verifier for local/testnet use. Accepts all proofs.
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {
        // no-op: all proofs pass
    }
}

/// @title Deploy
/// @notice Deployment script for verifier contracts (Transfer, Bridge, Disclosure).
/// @dev Usage: forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract Deploy is Script {
    function run() external {
        // Use existing verifier if VERIFIER_ADDRESS is set, otherwise deploy a mock.
        address verifierAddr = vm.envOr("VERIFIER_ADDRESS", address(0));

        // Merkle roots — default to placeholder (all zeros).
        bytes32 allowlistRoot = vm.envOr("ALLOWLIST_ROOT", bytes32(0));
        bytes32 accountsRoot = vm.envOr("ACCOUNTS_ROOT", bytes32(0));

        // ERC20 token address for the bridge — required for bridge deployment.
        address tokenAddr = vm.envOr("TOKEN_ADDRESS", address(0));

        vm.startBroadcast();

        if (verifierAddr == address(0)) {
            MockRiscZeroVerifier mock = new MockRiscZeroVerifier();
            verifierAddr = address(mock);
            console.log("Deployed MockRiscZeroVerifier at:", verifierAddr);
        } else {
            console.log("Using existing verifier at:", verifierAddr);
        }

        // Transfer verifier
        TransferVerifier transferVerifier = new TransferVerifier(IRiscZeroVerifier(verifierAddr), accountsRoot);
        console.log("Deployed TransferVerifier at:", address(transferVerifier));

        // ValidiumBridge (ERC20 bridge with membership-gated deposit)
        if (tokenAddr != address(0)) {
            ValidiumBridge bridge =
                new ValidiumBridge(IERC20(tokenAddr), IRiscZeroVerifier(verifierAddr), accountsRoot, allowlistRoot);
            console.log("Deployed ValidiumBridge at:", address(bridge));
        } else {
            console.log("Skipping ValidiumBridge (set TOKEN_ADDRESS to deploy)");
        }

        // DisclosureVerifier (compliance disclosure)
        DisclosureVerifier disclosureVerifier = new DisclosureVerifier(IRiscZeroVerifier(verifierAddr), accountsRoot);
        console.log("Deployed DisclosureVerifier at:", address(disclosureVerifier));

        vm.stopBroadcast();
    }
}

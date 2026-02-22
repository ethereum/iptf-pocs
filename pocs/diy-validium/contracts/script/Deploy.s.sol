// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/src/Script.sol";
import {stdToml} from "forge-std/src/StdToml.sol";
import {IERC20} from "forge-std/src/interfaces/IERC20.sol";
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
/// @dev Configuration: all deployment parameters are read from environment variables
///      with sensible defaults using vm.envOr(). For TOML-based config, see
///      forge-std's StdToml / Config pattern used in pocs/private-payment/.
///
///      Environment variables:
///        VERIFIER_ADDRESS — existing RISC Zero verifier (deploys MockRiscZeroVerifier if unset)
///        TOKEN_ADDRESS    — ERC20 token for bridge (skips bridge deployment if unset)
///        ALLOWLIST_ROOT   — Merkle root for bridge allowlist (defaults to bytes32(0))
///        ACCOUNTS_ROOT    — initial account state root (defaults to bytes32(0))
///
///      Usage: forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract Deploy is Script {
    using stdToml for string;

    function run() external {
        // ── Configuration ──────────────────────────────────────────────
        // All params read from env vars; defaults are zero-value placeholders
        // suitable for local/testnet deployments.

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
        TransferVerifier transferVerifier =
            new TransferVerifier(IRiscZeroVerifier(verifierAddr), accountsRoot, bytes32(0));
        console.log("Deployed TransferVerifier at:", address(transferVerifier));

        // ValidiumBridge (ERC20 bridge with membership-gated deposit)
        if (tokenAddr != address(0)) {
            ValidiumBridge bridge = new ValidiumBridge(
                IERC20(tokenAddr), IRiscZeroVerifier(verifierAddr), accountsRoot, allowlistRoot, bytes32(0), bytes32(0)
            );
            console.log("Deployed ValidiumBridge at:", address(bridge));
        } else {
            console.log("Skipping ValidiumBridge (set TOKEN_ADDRESS to deploy)");
        }

        // DisclosureVerifier (compliance disclosure)
        DisclosureVerifier disclosureVerifier =
            new DisclosureVerifier(IRiscZeroVerifier(verifierAddr), accountsRoot, bytes32(0));
        console.log("Deployed DisclosureVerifier at:", address(disclosureVerifier));

        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {MembershipVerifier} from "../src/MembershipVerifier.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";

/// @notice Mock RISC Zero verifier for local/testnet use. Accepts all proofs.
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {
        // no-op: all proofs pass
    }
}

/// @title Deploy
/// @notice Deployment script for MembershipVerifier and (optionally) a mock verifier.
/// @dev Usage: forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract Deploy is Script {
    function run() external {
        // Use existing verifier if VERIFIER_ADDRESS is set, otherwise deploy a mock.
        address verifierAddr = vm.envOr("VERIFIER_ADDRESS", address(0));

        // Default allowlist root is a placeholder (all zeros).
        bytes32 allowlistRoot = vm.envOr("ALLOWLIST_ROOT", bytes32(0));

        vm.startBroadcast();

        if (verifierAddr == address(0)) {
            MockRiscZeroVerifier mock = new MockRiscZeroVerifier();
            verifierAddr = address(mock);
            console.log("Deployed MockRiscZeroVerifier at:", verifierAddr);
        } else {
            console.log("Using existing verifier at:", verifierAddr);
        }

        MembershipVerifier membershipVerifier = new MembershipVerifier(IRiscZeroVerifier(verifierAddr), allowlistRoot);
        console.log("Deployed MembershipVerifier at:", address(membershipVerifier));
        console.log("Allowlist root:", vm.toString(allowlistRoot));

        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {MembershipVerifier} from "../src/MembershipVerifier.sol";
import {BalanceVerifier} from "../src/BalanceVerifier.sol";
import {TransferVerifier} from "../src/TransferVerifier.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";

/// @notice Mock RISC Zero verifier for local/testnet use. Accepts all proofs.
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {
        // no-op: all proofs pass
    }
}

/// @title Deploy
/// @notice Deployment script for Phase 1 + Phase 2 + Phase 3 verifier contracts.
/// @dev Usage: forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
contract Deploy is Script {
    function run() external {
        // Use existing verifier if VERIFIER_ADDRESS is set, otherwise deploy a mock.
        address verifierAddr = vm.envOr("VERIFIER_ADDRESS", address(0));

        // Merkle roots — default to placeholder (all zeros).
        bytes32 allowlistRoot = vm.envOr("ALLOWLIST_ROOT", bytes32(0));
        bytes32 accountsRoot = vm.envOr("ACCOUNTS_ROOT", bytes32(0));

        vm.startBroadcast();

        if (verifierAddr == address(0)) {
            MockRiscZeroVerifier mock = new MockRiscZeroVerifier();
            verifierAddr = address(mock);
            console.log("Deployed MockRiscZeroVerifier at:", verifierAddr);
        } else {
            console.log("Using existing verifier at:", verifierAddr);
        }

        // Phase 1: Membership verifier
        MembershipVerifier membershipVerifier = new MembershipVerifier(IRiscZeroVerifier(verifierAddr), allowlistRoot);
        console.log("Deployed MembershipVerifier at:", address(membershipVerifier));

        // Phase 2: Balance verifier
        BalanceVerifier balanceVerifier = new BalanceVerifier(IRiscZeroVerifier(verifierAddr), accountsRoot);
        console.log("Deployed BalanceVerifier at:", address(balanceVerifier));

        // Phase 3: Transfer verifier (uses accountsRoot as initial state root)
        TransferVerifier transferVerifier = new TransferVerifier(IRiscZeroVerifier(verifierAddr), accountsRoot);
        console.log("Deployed TransferVerifier at:", address(transferVerifier));

        vm.stopBroadcast();
    }
}

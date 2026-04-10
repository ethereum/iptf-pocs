// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console} from "forge-std/Script.sol";
import {Config} from "forge-std/Config.sol";
import {IdentityTree} from "../src/IdentityTree.sol";
import {Enrollment} from "../src/Enrollment.sol";
import {IdentityVerifier} from "../src/IdentityVerifier.sol";
import {HonkVerifier as EnrollmentHonkVerifier} from "../src/verifiers/EnrollmentVerifier.sol";
import {HonkVerifier as MembershipHonkVerifier} from "../src/verifiers/MembershipVerifier.sol";

/// @title Deploy
/// @notice Deployment script for resilient private identity contracts
contract Deploy is Script, Config {
    function run() public {
        _loadConfig("./deployments.toml", true);

        bool useMockVerifier = config.get("use_mock_verifier").toBool();

        address governance = config.get("governance").toAddress();
        address multisigAddr = config.get("multisig").toAddress();
        address guardianAddr = config.get("guardian").toAddress();
        // Read uint256 values directly from env (Config can't handle large uint256)
        uint256 mpcKeyX = vm.envUint("MPC_KEY_X");
        uint256 mpcKeyY = vm.envUint("MPC_KEY_Y");

        vm.startBroadcast();

        // 1. Deploy IdentityTree
        IdentityTree identityTree = new IdentityTree(governance);
        console.log("IdentityTree:", address(identityTree));

        // 2. Resolve verifier addresses
        address enrollmentVerifierAddr;
        address membershipVerifierAddr;
        if (useMockVerifier) {
            // Deploy minimal mock verifiers (always return true)
            MockVerifier enrollmentMock = new MockVerifier();
            MockVerifier membershipMock = new MockVerifier();
            enrollmentVerifierAddr = address(enrollmentMock);
            membershipVerifierAddr = address(membershipMock);
            console.log("MockVerifier (enrollment):", enrollmentVerifierAddr);
            console.log("MockVerifier (membership):", membershipVerifierAddr);
        } else {
            EnrollmentHonkVerifier enrollmentReal = new EnrollmentHonkVerifier();
            MembershipHonkVerifier membershipReal = new MembershipHonkVerifier();
            enrollmentVerifierAddr = address(enrollmentReal);
            membershipVerifierAddr = address(membershipReal);
            console.log("EnrollmentVerifier:", enrollmentVerifierAddr);
            console.log("MembershipVerifier:", membershipVerifierAddr);
        }

        // 3. Deploy Enrollment
        uint256 stakeAmount = 0.1 ether;
        Enrollment enrollment = new Enrollment(
            address(identityTree),
            enrollmentVerifierAddr,
            mpcKeyX,
            mpcKeyY,
            multisigAddr,
            guardianAddr,
            stakeAmount
        );
        console.log("Enrollment:", address(enrollment));

        // 4. Deploy IdentityVerifier
        IdentityVerifier identityVerifierContract = new IdentityVerifier(
            address(identityTree),
            membershipVerifierAddr
        );
        console.log("IdentityVerifier:", address(identityVerifierContract));

        // 5. Authorize Enrollment to insert leaves
        identityTree.addAuthorized(address(enrollment));

        vm.stopBroadcast();

        config.set("identity_tree_address", address(identityTree));
        config.set("enrollment_address", address(enrollment));
        config.set("identity_verifier_address", address(identityVerifierContract));
        config.set("enrollment_verifier_address", enrollmentVerifierAddr);
        config.set("membership_verifier_address", membershipVerifierAddr);

        // Log summary
        console.log("");
        console.log("=== Deployment Summary ===");
        console.log("Chain ID:", block.chainid);
        console.log("IdentityTree:", address(identityTree));
        console.log("Enrollment:", address(enrollment));
        console.log("IdentityVerifier:", address(identityVerifierContract));
    }
}

/// @dev Minimal mock verifier that always returns true
contract MockVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

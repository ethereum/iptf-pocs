// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";

contract AttestationRegistryTest is Test {
    AttestationRegistry public registry;

    address public owner;
    address public attester;
    address public attester2;
    address public nonAttester;

    bytes32 constant SUBJECT_PUBKEY_HASH = keccak256("subject_pubkey_1");
    bytes32 constant SUBJECT_PUBKEY_HASH_2 = keccak256("subject_pubkey_2");

    event AttestationAdded(
        bytes32 indexed leaf,
        bytes32 indexed subjectPubkeyHash,
        address indexed attester,
        uint64 issuedAt,
        uint64 expiresAt
    );
    event AttestationRevoked(bytes32 indexed leaf, address indexed revokedBy);
    event AttesterAdded(address indexed attester);
    event AttesterRemoved(address indexed attester);

    function setUp() public {
        owner = address(this);
        attester = address(0x1);
        attester2 = address(0x2);
        nonAttester = address(0x3);

        registry = new AttestationRegistry();
        registry.addAttester(attester);
    }

    // ========== Attester Management Tests ==========

    function testAddAttester() public {
        vm.expectEmit(true, false, false, false);
        emit AttesterAdded(attester2);

        registry.addAttester(attester2);
        assertTrue(registry.isAuthorizedAttester(attester2));
    }

    function testAddAttesterRevertsIfAlreadyAuthorized() public {
        vm.expectRevert(AttestationRegistry.AttesterAlreadyAuthorized.selector);
        registry.addAttester(attester);
    }

    function testAddAttesterRevertsIfZeroAddress() public {
        vm.expectRevert(AttestationRegistry.ZeroAddress.selector);
        registry.addAttester(address(0));
    }

    function testAddAttesterOnlyOwner() public {
        vm.prank(nonAttester);
        vm.expectRevert(AttestationRegistry.OnlyOwner.selector);
        registry.addAttester(attester2);
    }

    function testRemoveAttester() public {
        vm.expectEmit(true, false, false, false);
        emit AttesterRemoved(attester);

        registry.removeAttester(attester);
        assertFalse(registry.isAuthorizedAttester(attester));
    }

    function testRemoveAttesterRevertsIfNotAuthorized() public {
        vm.expectRevert(AttestationRegistry.AttesterNotAuthorized.selector);
        registry.removeAttester(nonAttester);
    }

    function testRemoveAttesterOnlyOwner() public {
        vm.prank(nonAttester);
        vm.expectRevert(AttestationRegistry.OnlyOwner.selector);
        registry.removeAttester(attester);
    }

    // ========== Add Attestation Tests ==========

    function testAddAttestation() public {
        uint64 expiresAt = uint64(block.timestamp + 365 days);

        vm.prank(attester);
        bytes32 leaf = registry.addAttestation(SUBJECT_PUBKEY_HASH, expiresAt);

        assertTrue(registry.attestationLeaves(leaf));
        assertEq(registry.getAttestationCount(), 1);
        assertTrue(registry.attestationRoot() != bytes32(0));
    }

    function testAddAttestationEmitsEvent() public {
        uint64 expiresAt = uint64(block.timestamp + 365 days);

        vm.prank(attester);
        vm.expectEmit(false, true, true, true);
        emit AttestationAdded(
            bytes32(0), // leaf is computed, can't predict exact value
            SUBJECT_PUBKEY_HASH,
            attester,
            uint64(block.timestamp),
            expiresAt
        );
        registry.addAttestation(SUBJECT_PUBKEY_HASH, expiresAt);
    }

    function testAddAttestationNoExpiry() public {
        vm.prank(attester);
        bytes32 leaf = registry.addAttestation(SUBJECT_PUBKEY_HASH, 0);

        assertTrue(registry.attestationLeaves(leaf));
    }

    function testAddAttestationUpdatesRoot() public {
        // Initial root is the default zero for depth 20
        bytes32 rootBefore = registry.attestationRoot();

        vm.prank(attester);
        registry.addAttestation(SUBJECT_PUBKEY_HASH, 0);

        bytes32 rootAfter = registry.attestationRoot();
        assertTrue(rootAfter != rootBefore);

        // Add another attestation, root should change
        vm.warp(block.timestamp + 1);
        vm.prank(attester);
        registry.addAttestation(SUBJECT_PUBKEY_HASH_2, 0);

        assertTrue(registry.attestationRoot() != rootAfter);
    }

    function testAddAttestationOnlyAuthorizedAttester() public {
        vm.prank(nonAttester);
        vm.expectRevert(AttestationRegistry.OnlyAuthorizedAttester.selector);
        registry.addAttestation(SUBJECT_PUBKEY_HASH, 0);
    }

    function testAddAttestationRevertsIfExists() public {
        vm.prank(attester);
        registry.addAttestation(SUBJECT_PUBKEY_HASH, 0);

        // Same parameters at same timestamp would produce same leaf
        vm.prank(attester);
        vm.expectRevert(AttestationRegistry.AttestationAlreadyExists.selector);
        registry.addAttestation(SUBJECT_PUBKEY_HASH, 0);
    }

    // ========== Ownership Tests ==========

    function testTransferOwnership() public {
        address newOwner = address(0x999);
        registry.transferOwnership(newOwner);
        assertEq(registry.owner(), newOwner);
    }

    function testTransferOwnershipOnlyOwner() public {
        vm.prank(nonAttester);
        vm.expectRevert(AttestationRegistry.OnlyOwner.selector);
        registry.transferOwnership(nonAttester);
    }

    function testTransferOwnershipRevertsZeroAddress() public {
        vm.expectRevert(AttestationRegistry.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }

    // ========== Multiple Attestations ==========

    function testMultipleAttestations() public {
        vm.startPrank(attester);

        bytes32 leaf1 = registry.addAttestation(SUBJECT_PUBKEY_HASH, 0);

        // Different timestamp will produce different leaf
        vm.warp(block.timestamp + 1);
        bytes32 leaf2 = registry.addAttestation(SUBJECT_PUBKEY_HASH_2, 0);

        vm.stopPrank();

        assertTrue(registry.attestationLeaves(leaf1));
        assertTrue(registry.attestationLeaves(leaf2));
        assertEq(registry.getAttestationCount(), 2);
        assertTrue(leaf1 != leaf2);
    }

    // ========== Leaf Index Mapping ==========

    function testLeafAtIndex() public {
        vm.prank(attester);
        bytes32 leaf = registry.addAttestation(SUBJECT_PUBKEY_HASH, 0);

        assertEq(registry.leafAtIndex(0), leaf);
    }
}

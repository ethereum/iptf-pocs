// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {IdentityVerifier} from "../src/IdentityVerifier.sol";

contract MockVerifier {
    bool public returnValue;

    constructor(bool _returnValue) {
        returnValue = _returnValue;
    }

    function setReturnValue(bool _v) external {
        returnValue = _v;
    }

    function verify(bytes calldata, bytes32[] calldata) external view returns (bool) {
        return returnValue;
    }
}

contract MockIdentityTree {
    mapping(uint256 => bool) private _roots;

    function setRoot(uint256 root, bool valid) external {
        _roots[root] = valid;
    }

    function isRecentRoot(uint256 root) external view returns (bool) {
        return _roots[root];
    }
}

contract IdentityVerifierTest is Test {
    IdentityVerifier public iv;
    MockVerifier public mockVerifier;
    MockIdentityTree public mockTree;

    uint256 constant ROOT = 12345;
    uint256 constant NULLIFIER = 67890;
    uint256 constant EXT_NULLIFIER = 11111;
    uint256 constant VERSION = 1;

    function setUp() public {
        mockVerifier = new MockVerifier(true);
        mockTree = new MockIdentityTree();
        iv = new IdentityVerifier(address(mockTree), address(mockVerifier));

        mockTree.setRoot(ROOT, true);
    }

    function test_verifyProof_success() public {
        iv.verifyProof(
            hex"1234",
            ROOT,
            NULLIFIER,
            EXT_NULLIFIER,
            VERSION,
            1, // predicateType
            0, // predicateAttrIndex
            100, // predicateValue
            1 // predicateResult
        );

        assertTrue(iv.usedNullifiers(NULLIFIER));
    }

    function test_verifyProof_emitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit IdentityVerifier.ProofVerified(NULLIFIER, ROOT, EXT_NULLIFIER, VERSION);

        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);
    }

    function test_verifyProof_revertsStaleRoot() public {
        vm.expectRevert(IdentityVerifier.StaleRoot.selector);
        iv.verifyProof(hex"1234", 99999, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);
    }

    function test_verifyProof_revertsNullifierUsed() public {
        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);

        vm.expectRevert(IdentityVerifier.NullifierUsed.selector);
        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);
    }

    function test_verifyProof_revertsInvalidAttrIndex() public {
        vm.expectRevert(IdentityVerifier.InvalidAttrIndex.selector);
        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 2, 100, 1);
    }

    function test_verifyProof_revertsInvalidAttrIndex_large() public {
        vm.expectRevert(IdentityVerifier.InvalidAttrIndex.selector);
        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 999, 100, 1);
    }

    function test_verifyProof_revertsInvalidProof() public {
        mockVerifier.setReturnValue(false);
        vm.expectRevert(IdentityVerifier.InvalidProof.selector);
        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);
    }

    function test_verifyProof_differentNullifiersSameRoot() public {
        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);
        iv.verifyProof(hex"1234", ROOT, NULLIFIER + 1, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);

        assertTrue(iv.usedNullifiers(NULLIFIER));
        assertTrue(iv.usedNullifiers(NULLIFIER + 1));
    }

    function test_verifyProof_attrIndex0and1_valid() public {
        iv.verifyProof(hex"1234", ROOT, NULLIFIER, EXT_NULLIFIER, VERSION, 1, 0, 100, 1);
        iv.verifyProof(hex"1234", ROOT, NULLIFIER + 1, EXT_NULLIFIER, VERSION, 1, 1, 200, 1);
    }
}

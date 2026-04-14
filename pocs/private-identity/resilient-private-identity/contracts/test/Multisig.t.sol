// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {Multisig} from "../src/Multisig.sol";

contract MultisigTarget {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }

    function failing() external pure {
        revert("intentional");
    }
}

contract MultisigTest is Test {
    Multisig public multisig;
    MultisigTarget public target;

    address[7] public owners;

    function setUp() public {
        for (uint256 i = 0; i < 7; i++) {
            owners[i] = address(uint160(0x1000 + i));
        }
        multisig = new Multisig(owners);
        target = new MultisigTarget();
    }

    function test_constructor_setsOwners() public view {
        for (uint256 i = 0; i < 7; i++) {
            assertTrue(multisig.isOwner(owners[i]));
        }
    }

    function test_constructor_nonOwner() public view {
        assertFalse(multisig.isOwner(address(0xdead)));
    }

    function test_constructor_revertsDuplicateOwner() public {
        address[7] memory dupes;
        for (uint256 i = 0; i < 7; i++) {
            dupes[i] = address(uint160(0x2000 + i));
        }
        dupes[3] = dupes[0]; // duplicate
        vm.expectRevert(Multisig.DuplicateOwner.selector);
        new Multisig(dupes);
    }

    function test_constructor_revertsZeroAddress() public {
        address[7] memory bad;
        for (uint256 i = 0; i < 6; i++) {
            bad[i] = address(uint160(0x3000 + i));
        }
        bad[6] = address(0);
        vm.expectRevert(Multisig.ZeroAddress.selector);
        new Multisig(bad);
    }

    function test_propose_onlyOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert(Multisig.NotOwner.selector);
        multisig.propose(address(target), abi.encodeCall(MultisigTarget.setValue, (42)));
    }

    function test_propose_returnsId() public {
        vm.prank(owners[0]);
        uint256 id0 = multisig.propose(address(target), abi.encodeCall(MultisigTarget.setValue, (42)));
        assertEq(id0, 0);

        vm.prank(owners[1]);
        uint256 id1 = multisig.propose(address(target), abi.encodeCall(MultisigTarget.setValue, (99)));
        assertEq(id1, 1);
    }

    function test_confirm_onlyOwner() public {
        vm.prank(owners[0]);
        multisig.propose(address(target), abi.encodeCall(MultisigTarget.setValue, (42)));

        vm.prank(address(0xdead));
        vm.expectRevert(Multisig.NotOwner.selector);
        multisig.confirm(0);
    }

    function test_confirm_revertsDoubleConfirm() public {
        vm.prank(owners[0]);
        multisig.propose(address(target), abi.encodeCall(MultisigTarget.setValue, (42)));

        vm.prank(owners[0]);
        multisig.confirm(0);

        vm.prank(owners[0]);
        vm.expectRevert(Multisig.AlreadyConfirmed.selector);
        multisig.confirm(0);
    }

    function test_confirm_revertsInvalidProposal() public {
        vm.prank(owners[0]);
        vm.expectRevert(Multisig.InvalidProposal.selector);
        multisig.confirm(999);
    }

    function test_execute_onlyOwner() public {
        _createAndConfirm(abi.encodeCall(MultisigTarget.setValue, (42)));

        vm.prank(address(0xdead));
        vm.expectRevert(Multisig.NotOwner.selector);
        multisig.execute(0);
    }

    function test_execute_revertsBelow_threshold() public {
        vm.prank(owners[0]);
        multisig.propose(address(target), abi.encodeCall(MultisigTarget.setValue, (42)));

        // only 3 confirmations
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(owners[i]);
            multisig.confirm(0);
        }

        vm.prank(owners[0]);
        vm.expectRevert(Multisig.BelowThreshold.selector);
        multisig.execute(0);
    }

    function test_execute_success() public {
        _createAndConfirm(abi.encodeCall(MultisigTarget.setValue, (42)));

        vm.prank(owners[0]);
        multisig.execute(0);

        assertEq(target.value(), 42);
    }

    function test_execute_revertsDoubleExecute() public {
        _createAndConfirm(abi.encodeCall(MultisigTarget.setValue, (42)));

        vm.prank(owners[0]);
        multisig.execute(0);

        vm.prank(owners[0]);
        vm.expectRevert(Multisig.AlreadyExecuted.selector);
        multisig.execute(0);
    }

    function test_execute_revertsOnFailedCall() public {
        _createAndConfirm(abi.encodeCall(MultisigTarget.failing, ()));

        vm.prank(owners[0]);
        vm.expectRevert(Multisig.ExecutionFailed.selector);
        multisig.execute(0);
    }

    function test_confirm_revertsOnExecutedProposal() public {
        _createAndConfirm(abi.encodeCall(MultisigTarget.setValue, (42)));

        vm.prank(owners[0]);
        multisig.execute(0);

        vm.prank(owners[4]);
        vm.expectRevert(Multisig.AlreadyExecuted.selector);
        multisig.confirm(0);
    }


    function _createAndConfirm(bytes memory data) internal {
        vm.prank(owners[0]);
        multisig.propose(address(target), data);

        for (uint256 i = 0; i < 4; i++) {
            vm.prank(owners[i]);
            multisig.confirm(0);
        }
    }
}

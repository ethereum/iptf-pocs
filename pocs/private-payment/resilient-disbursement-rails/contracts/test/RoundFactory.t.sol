// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {RoundFactory, RoundHeader} from "../src/RoundFactory.sol";
import {Registry} from "../src/Registry.sol";
import {ClaimContract} from "../src/ClaimContract.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";

contract RoundFactoryTest is Test {
    ShieldedPool public pool;
    RoundFactory public factory;
    Registry public registry;
    ClaimContract public claimContract;
    MockERC20 public token;
    MockCompositeVerifier public verifier;

    address public funderMultisig = address(0xFA17);
    address public operator = address(0x09E2);
    address public governance = address(0x6017);
    address public residualDest;
    uint64 public constant COHORT_VERSION = 1;
    uint256 public constant COHORT_ROOT = 0xC1357;
    uint256 public constant COHORT_SIZE = 4;
    uint256 public constant PER_RECIPIENT_AMOUNT = 1_000;
    uint256 public constant ROUND_ID = 42;

    function setUp() public {
        residualDest = address(0xDE57);

        token = new MockERC20("Mock", "MCK", 6);
        verifier = new MockCompositeVerifier();
        registry = new Registry(operator, governance);
        pool = new ShieldedPool(address(token), address(verifier), governance);
        claimContract = new ClaimContract(governance);

        factory =
            new RoundFactory(address(registry), address(pool), address(claimContract), address(token), funderMultisig);

        // Wire pool: factory authorized.
        vm.prank(governance);
        pool.initAuthorizedFactory(address(factory));

        // Wire claim contract.
        vm.startPrank(governance);
        claimContract.setFactory(address(factory));
        claimContract.setPool(address(pool));
        claimContract.setVerifier(address(verifier));
        claimContract.setToken(address(token));
        claimContract.setFunderMultisig(funderMultisig);
        claimContract.setFunderResidualDestination(residualDest);
        vm.stopPrank();

        // Publish a cohort version.
        vm.prank(operator);
        registry.publishCohort(COHORT_ROOT, COHORT_SIZE);

        // Pre-fund funder multisig.
        token.mint(funderMultisig, 1_000_000);
        vm.prank(funderMultisig);
        token.approve(address(factory), type(uint256).max);
    }

    function _validHeader() internal view returns (RoundHeader memory h) {
        h.roundId = ROUND_ID;
        h.cohortVersion = COHORT_VERSION;
        h.cohortRoot = COHORT_ROOT;
        h.perRecipientAmount = PER_RECIPIENT_AMOUNT;
        h.cohortSize = COHORT_SIZE;
        h.token = address(token);
        h.closeTime = uint64(block.timestamp + 1000);
        h.claimContractAddress = address(claimContract);
        h.chainId = block.chainid;
    }

    function _commitments() internal pure returns (uint256[] memory c) {
        c = new uint256[](COHORT_SIZE);
        for (uint256 i = 0; i < COHORT_SIZE; i++) {
            c[i] = 0xAA00 + i;
        }
    }

    function test_publishRound_happyPath() public {
        RoundHeader memory h = _validHeader();
        uint256[] memory c = _commitments();

        vm.prank(funderMultisig);
        factory.publishRound(h, c);

        // Pool was credited.
        assertEq(pool.balance(address(claimContract)), PER_RECIPIENT_AMOUNT * COHORT_SIZE);
        assertEq(pool.roundDeposit(address(claimContract), ROUND_ID), PER_RECIPIENT_AMOUNT * COHORT_SIZE);
        assertEq(pool.commitmentCount(address(claimContract)), COHORT_SIZE);

        // Claim contract has header registered.
        assertTrue(claimContract.roundRegistered(ROUND_ID));
        // firstPoolLeafIndex was 0 (pre-deposit empty sub-tree).
        assertEq(claimContract.firstPoolLeafIndex(ROUND_ID), 0);

        // Token balance pulled.
        assertEq(token.balanceOf(funderMultisig), 1_000_000 - PER_RECIPIENT_AMOUNT * COHORT_SIZE);
    }

    function test_publishRound_revertsNotMultisig() public {
        RoundHeader memory h = _validHeader();
        uint256[] memory c = _commitments();

        vm.expectRevert(RoundFactory.NotFunderMultisig.selector);
        factory.publishRound(h, c);
    }

    function test_publishRound_revertsCohortRootMismatch() public {
        RoundHeader memory h = _validHeader();
        h.cohortRoot = 0xBADBAD;
        uint256[] memory c = _commitments();

        vm.prank(funderMultisig);
        vm.expectRevert(RoundFactory.CohortRootMismatch.selector);
        factory.publishRound(h, c);
    }

    function test_publishRound_revertsCohortSizeMismatch() public {
        RoundHeader memory h = _validHeader();
        h.cohortSize = COHORT_SIZE + 1;
        uint256[] memory c = new uint256[](COHORT_SIZE + 1);

        vm.prank(funderMultisig);
        vm.expectRevert(RoundFactory.CohortSizeMismatch.selector);
        factory.publishRound(h, c);
    }

    function test_publishRound_revertsWrongCommitmentCount() public {
        RoundHeader memory h = _validHeader();
        uint256[] memory c = new uint256[](COHORT_SIZE - 1);

        vm.prank(funderMultisig);
        vm.expectRevert(RoundFactory.WrongCommitmentCount.selector);
        factory.publishRound(h, c);
    }

    function test_publishRound_revertsWrongChainId() public {
        RoundHeader memory h = _validHeader();
        h.chainId = block.chainid + 1;
        uint256[] memory c = _commitments();

        vm.prank(funderMultisig);
        vm.expectRevert(RoundFactory.WrongChainId.selector);
        factory.publishRound(h, c);
    }

    function test_publishRound_revertsWrongToken() public {
        RoundHeader memory h = _validHeader();
        h.token = address(0xBADBAD);
        uint256[] memory c = _commitments();

        vm.prank(funderMultisig);
        vm.expectRevert(RoundFactory.WrongToken.selector);
        factory.publishRound(h, c);
    }

    function test_publishRound_revertsRoundIdCollision() public {
        RoundHeader memory h = _validHeader();
        uint256[] memory c = _commitments();

        vm.prank(funderMultisig);
        factory.publishRound(h, c);

        vm.prank(funderMultisig);
        vm.expectRevert(RoundFactory.RoundIdCollision.selector);
        factory.publishRound(h, c);
    }

    function test_publishRound_firstPoolLeafIndexCapturesPreLoop() public {
        // Publish a first round that fills 4 leaves.
        RoundHeader memory h1 = _validHeader();
        uint256[] memory c1 = _commitments();
        vm.prank(funderMultisig);
        factory.publishRound(h1, c1);

        // Second round: firstPoolLeafIndex must be 4 (not 8).
        RoundHeader memory h2 = _validHeader();
        h2.roundId = ROUND_ID + 1;
        h2.cohortVersion = COHORT_VERSION;
        uint256[] memory c2 = new uint256[](COHORT_SIZE);
        for (uint256 i = 0; i < COHORT_SIZE; i++) {
            c2[i] = 0xBB00 + i;
        }

        vm.prank(funderMultisig);
        factory.publishRound(h2, c2);

        assertEq(claimContract.firstPoolLeafIndex(h2.roundId), uint64(COHORT_SIZE));
    }

    function test_publishRound_atomicRevertOnDuplicateCommitment() public {
        // Publishing two rounds whose commitments collide on the second's
        // first commitment causes pool.deposit to revert mid-loop. Whole
        // call must roll back.
        RoundHeader memory h1 = _validHeader();
        uint256[] memory c1 = _commitments();
        vm.prank(funderMultisig);
        factory.publishRound(h1, c1);

        // Re-use the same commitments for a second round.
        RoundHeader memory h2 = _validHeader();
        h2.roundId = ROUND_ID + 1;
        uint256[] memory c2 = _commitments();

        uint256 balBefore = token.balanceOf(funderMultisig);
        uint256 poolBalBefore = pool.balance(address(claimContract));
        bool registeredBefore = claimContract.roundRegistered(h2.roundId);

        vm.prank(funderMultisig);
        vm.expectRevert(ShieldedPool.CommitmentExists.selector);
        factory.publishRound(h2, c2);

        // No state changes.
        assertEq(token.balanceOf(funderMultisig), balBefore);
        assertEq(pool.balance(address(claimContract)), poolBalBefore);
        assertEq(claimContract.roundRegistered(h2.roundId), registeredBefore);
    }
}

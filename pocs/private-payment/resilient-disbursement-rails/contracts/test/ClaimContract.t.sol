// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {RoundFactory, RoundHeader} from "../src/RoundFactory.sol";
import {Registry} from "../src/Registry.sol";
import {ClaimContract, ClaimPublicInputs, PoolPublicInputs} from "../src/ClaimContract.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {MockCompositeVerifier} from "../src/mocks/MockCompositeVerifier.sol";

contract ClaimContractTest is Test {
    ShieldedPool public pool;
    RoundFactory public factory;
    Registry public registry;
    ClaimContract public claimContract;
    MockERC20 public token;
    MockCompositeVerifier public verifier;

    address public funderMultisig = address(0xFA17);
    address public operator = address(0x09E2);
    address public governance = address(0x6017);
    address public residualDest = address(0xDE57);
    address public relay = address(0xBEEF);
    address public destinationAddr = address(0xCAFE);

    uint64 public constant COHORT_VERSION = 1;
    uint256 public constant COHORT_ROOT = 0xC1357;
    uint256 public constant COHORT_SIZE = 4;
    uint256 public constant PER_RECIPIENT_AMOUNT = 1_000;
    uint256 public constant ROUND_ID = 42;
    uint64 public CLOSE_TIME;

    function setUp() public {
        token = new MockERC20("Mock", "MCK", 6);
        verifier = new MockCompositeVerifier();
        registry = new Registry(operator, governance);
        pool = new ShieldedPool(address(token), address(verifier), governance);
        claimContract = new ClaimContract(governance);

        factory =
            new RoundFactory(address(registry), address(pool), address(claimContract), address(token), funderMultisig);

        vm.prank(governance);
        pool.initAuthorizedFactory(address(factory));

        vm.startPrank(governance);
        claimContract.setFactory(address(factory));
        claimContract.setPool(address(pool));
        claimContract.setVerifier(address(verifier));
        claimContract.setToken(address(token));
        claimContract.setFunderMultisig(funderMultisig);
        claimContract.setFunderResidualDestination(residualDest);
        vm.stopPrank();

        vm.prank(operator);
        registry.publishCohort(COHORT_ROOT, COHORT_SIZE);

        token.mint(funderMultisig, 1_000_000);
        vm.prank(funderMultisig);
        token.approve(address(factory), type(uint256).max);

        // Publish a round.
        CLOSE_TIME = uint64(block.timestamp + 1000);
        RoundHeader memory h;
        h.roundId = ROUND_ID;
        h.cohortVersion = COHORT_VERSION;
        h.cohortRoot = COHORT_ROOT;
        h.perRecipientAmount = PER_RECIPIENT_AMOUNT;
        h.cohortSize = COHORT_SIZE;
        h.token = address(token);
        h.closeTime = CLOSE_TIME;
        h.claimContractAddress = address(claimContract);
        h.chainId = block.chainid;

        uint256[] memory commitments = new uint256[](COHORT_SIZE);
        for (uint256 i = 0; i < COHORT_SIZE; i++) {
            commitments[i] = 0xAA00 + i;
        }
        vm.prank(funderMultisig);
        factory.publishRound(h, commitments);
    }

    /// @dev Build a valid claim PI array for the given relay.
    function _claimPI(address relaySubmitter) internal view returns (uint256[10] memory pi) {
        pi[ClaimPublicInputs.ROUND_ID_HI] = ROUND_ID >> 128;
        pi[ClaimPublicInputs.ROUND_ID_LO] = ROUND_ID & ((uint256(1) << 128) - 1);
        pi[ClaimPublicInputs.COHORT_ROOT] = COHORT_ROOT;
        pi[ClaimPublicInputs.CHAIN_ID_HI] = block.chainid >> 128;
        pi[ClaimPublicInputs.CHAIN_ID_LO] = block.chainid & ((uint256(1) << 128) - 1);
        pi[ClaimPublicInputs.DESTINATION] = uint256(uint160(destinationAddr));
        pi[ClaimPublicInputs.AMOUNT] = PER_RECIPIENT_AMOUNT;
        pi[ClaimPublicInputs.NULLIFIER] = 0x515151;
        pi[ClaimPublicInputs.CLAIM_CONTRACT_ADDRESS] = uint256(uint160(address(claimContract)));
        pi[ClaimPublicInputs.RELAY_SUBMITTER] = uint256(uint160(relaySubmitter));
    }

    function _expectedDestination(uint256[10] memory pi) internal pure returns (address) {
        return address(uint160(pi[ClaimPublicInputs.DESTINATION]));
    }

    /// @dev Build a pool PI consistent with the given claim PI.
    function _poolPI(uint256[10] memory claimPI) internal view returns (uint256[5] memory pi) {
        address dest = _expectedDestination(claimPI);
        pi[PoolPublicInputs.POOL_ROOT] = pool.subTreeRoot(address(claimContract));
        pi[PoolPublicInputs.CLAIM_NULLIFIER] = claimPI[ClaimPublicInputs.NULLIFIER];
        pi[PoolPublicInputs.TOKEN] = uint256(uint160(address(token)));
        pi[PoolPublicInputs.AMOUNT] = PER_RECIPIENT_AMOUNT;
        pi[PoolPublicInputs.RECIPIENT] = uint256(uint160(dest));
    }

    function test_claim_happyPath() public {
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);
        address dest = _expectedDestination(cpi);

        vm.prank(relay);
        claimContract.claim(hex"01", cpi, hex"02", ppi);

        assertTrue(claimContract.nullifierConsumed(cpi[ClaimPublicInputs.NULLIFIER]));
        assertEq(claimContract.nullifiersConsumedCount(ROUND_ID), 1);
        assertEq(token.balanceOf(dest), PER_RECIPIENT_AMOUNT);
        assertEq(verifier.claimCalls(), 1);
        assertEq(verifier.poolWithdrawCalls(), 1);
    }

    function test_claim_revertsBadCohortRoot() public {
        uint256[10] memory cpi = _claimPI(relay);
        cpi[ClaimPublicInputs.COHORT_ROOT] = 0xBADBAD;
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadHeaderBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsBadAmount() public {
        uint256[10] memory cpi = _claimPI(relay);
        cpi[ClaimPublicInputs.AMOUNT] = PER_RECIPIENT_AMOUNT + 1;
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadHeaderBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsBadClaimContractAddress() public {
        uint256[10] memory cpi = _claimPI(relay);
        cpi[ClaimPublicInputs.CLAIM_CONTRACT_ADDRESS] = uint256(uint160(address(0xBADBAD)));
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadHeaderBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsBadChainId() public {
        uint256[10] memory cpi = _claimPI(relay);
        cpi[ClaimPublicInputs.CHAIN_ID_LO] = (block.chainid & ((uint256(1) << 128) - 1)) + 1;
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadChainId.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsBadRelaySubmitter() public {
        uint256[10] memory cpi = _claimPI(address(0xDEADDEAD));
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadRelaySubmitter.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsCrossProofNullifierMismatch() public {
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);
        ppi[PoolPublicInputs.CLAIM_NULLIFIER] = 0xDEADDEAD; // differ

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadPoolBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsCrossProofAmountMismatch() public {
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);
        ppi[PoolPublicInputs.AMOUNT] = PER_RECIPIENT_AMOUNT + 1;

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadPoolBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsCrossProofTokenMismatch() public {
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);
        ppi[PoolPublicInputs.TOKEN] = uint256(uint160(address(0xBADBAD)));

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadPoolBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsCrossProofRecipientMismatch() public {
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);
        ppi[PoolPublicInputs.RECIPIENT] = uint256(uint160(address(0xBADBAD)));

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadPoolBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsPoolRootUnknown() public {
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);
        ppi[PoolPublicInputs.POOL_ROOT] = 0xDEADBEEF;

        vm.prank(relay);
        vm.expectRevert(ClaimContract.BadPoolBinding.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsDoubleSpend() public {
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        claimContract.claim(hex"", cpi, hex"", ppi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.NullifierConsumed.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsInvalidClaimProof() public {
        verifier.setClaimResult(false);

        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.InvalidClaimProof.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_claim_revertsInvalidPoolProof() public {
        verifier.setPoolWithdrawResult(false);

        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        // Pool reverts with its own InvalidProof; the call propagates.
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);

        // Note: nullifierConsumed flips before pool.unshield call but the
        // whole tx reverts, so it's rolled back.
    }

    function test_claim_revertsClosedRound() public {
        vm.warp(uint256(CLOSE_TIME));
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);

        vm.prank(relay);
        vm.expectRevert(ClaimContract.RoundClosed.selector);
        claimContract.claim(hex"", cpi, hex"", ppi);
    }

    function test_residual_revertsBeforeTimelock() public {
        vm.warp(uint256(CLOSE_TIME)); // round closed
        vm.prank(funderMultisig);
        vm.expectRevert(ClaimContract.RoundOpen.selector);
        claimContract.funderUnshieldResidual(ROUND_ID);
    }

    function test_residual_revertsNotMultisig() public {
        vm.warp(uint256(CLOSE_TIME) + claimContract.RESIDUAL_TIMELOCK_SECONDS());
        vm.expectRevert(ClaimContract.NotMultisig.selector);
        claimContract.funderUnshieldResidual(ROUND_ID);
    }

    function test_residual_succeedsAfterTimelock() public {
        vm.warp(uint256(CLOSE_TIME) + claimContract.RESIDUAL_TIMELOCK_SECONDS());
        uint256 expected = COHORT_SIZE * PER_RECIPIENT_AMOUNT;

        vm.prank(funderMultisig);
        claimContract.funderUnshieldResidual(ROUND_ID);

        assertEq(token.balanceOf(residualDest), expected);
        assertTrue(claimContract.residualPaid(ROUND_ID));
    }

    function test_residual_partialClaimsRecoversCorrectAmount() public {
        // Claim once.
        uint256[10] memory cpi = _claimPI(relay);
        uint256[5] memory ppi = _poolPI(cpi);
        vm.prank(relay);
        claimContract.claim(hex"", cpi, hex"", ppi);

        vm.warp(uint256(CLOSE_TIME) + claimContract.RESIDUAL_TIMELOCK_SECONDS());

        uint256 expected = (COHORT_SIZE - 1) * PER_RECIPIENT_AMOUNT;

        vm.prank(funderMultisig);
        claimContract.funderUnshieldResidual(ROUND_ID);

        assertEq(token.balanceOf(residualDest), expected);
    }

    function test_residual_doubleCallReverts() public {
        vm.warp(uint256(CLOSE_TIME) + claimContract.RESIDUAL_TIMELOCK_SECONDS());

        vm.prank(funderMultisig);
        claimContract.funderUnshieldResidual(ROUND_ID);

        vm.prank(funderMultisig);
        vm.expectRevert(ClaimContract.ResidualAlreadyPaid.selector);
        claimContract.funderUnshieldResidual(ROUND_ID);
    }

    function test_registerHeader_revertsRoundIdCollision() public {
        // Already registered in setUp; factory cannot re-register.
        RoundHeader memory h;
        h.roundId = ROUND_ID;

        vm.prank(address(factory));
        vm.expectRevert(ClaimContract.RoundIdCollision.selector);
        claimContract.registerHeader(h, 0);
    }

    function test_registerHeader_revertsNotFactory() public {
        RoundHeader memory h;
        h.roundId = 999;

        vm.expectRevert(ClaimContract.NotFactory.selector);
        claimContract.registerHeader(h, 0);
    }
}

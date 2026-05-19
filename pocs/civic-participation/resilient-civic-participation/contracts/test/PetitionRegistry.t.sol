// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {PetitionRegistry} from "../src/PetitionRegistry.sol";
import {IPetitionRegistry} from "../src/interfaces/IPetitionRegistry.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {MockBatchVerifier} from "../src/mocks/MockBatchVerifier.sol";
import {MockResolutionVerifier} from "../src/mocks/MockResolutionVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @title PetitionRegistryTest
/// @notice State-machine and validation tests for `PetitionRegistry`,
///         driven by `MockBatchVerifier` and `MockResolutionVerifier`
///         so the suite focuses on the registry's branching logic
///         rather than the ZK verifier internals. The real-everything
///         end-to-end coverage lives in `tests/golden_path.rs`.
contract PetitionRegistryTest is Test {
    PetitionRegistry internal registry;
    MockBatchVerifier internal batchVerifier;
    MockResolutionVerifier internal resolutionVerifier;
    MockERC20 internal token;

    address internal organizer = address(0xc01);
    address internal relayer = address(0xa11);
    address internal resolver_ = address(0xee1);
    address internal governance = address(0x90);

    bytes32 internal constant EMPTY_IMT_ROOT = bytes32(uint256(0xdeadbeef));
    bytes32 internal constant PINNED_SIGNER_VK_HASH = bytes32(uint256(0xabcd));
    uint64 internal constant BATCH_SIZE_MAX = 6;
    uint64 internal constant COOLDOWN_BLOCKS = 600;
    uint64 internal constant RESOLUTION_DEADLINE_BLOCKS = 100_800;
    uint64 internal constant MAX_SIGNING_WINDOW_BLOCKS = 82_800;

    function setUp() public {
        batchVerifier = new MockBatchVerifier();
        resolutionVerifier = new MockResolutionVerifier();
        token = new MockERC20("Mock USDC", "mUSDC", 6);
        registry = new PetitionRegistry(
            PetitionRegistry.InitArgs({
                batchVerifier: IVerifier(address(batchVerifier)),
                resolutionVerifier: IVerifier(address(resolutionVerifier)),
                bountyToken: address(token),
                governance: governance,
                alpha: 1,
                alphaMin: 1,
                alphaMax: 1_000,
                srsHash: bytes32(0),
                attrCount: 4,
                emptyImtRoot: EMPTY_IMT_ROOT,
                pinnedSignerVkHash: PINNED_SIGNER_VK_HASH
            })
        );

        token.mint(organizer, 1_000_000_000);
        vm.prank(organizer);
        token.approve(address(registry), type(uint256).max);

        // KZG point-evaluation precompile (0x0a) is opaque under foundry:
        // `_verifyKzgOpening` treats non-empty return bytes as success.
        // Mock with empty calldata-match so all 24 openings the
        // registry verifies per batch resolve to success.
        bytes memory anyCalldata = "";
        bytes memory kzgOk = abi.encode(uint256(4096), uint256(1));
        vm.mockCall(address(0x0a), anyCalldata, kzgOk);
    }

    function _classSet(uint16 a, uint16 b) internal pure returns (uint16[] memory cs) {
        cs = new uint16[](2);
        cs[0] = a;
        cs[1] = b;
    }

    function _classThresholds(uint64 a, uint64 b) internal pure returns (uint64[] memory ct) {
        ct = new uint64[](2);
        ct[0] = a;
        ct[1] = b;
    }

    /// Valid predicate_def with class-binding tuple at index 0:
    ///   tuples[0] = (claim_index=2, operand=class_tag=826, HASH, EQ),
    ///   ops = [PUSH_TUPLE(0)].
    /// Length = 1 + 1*35 + 1 + 1*2 = 39 bytes.
    function _predicateDef() internal pure returns (bytes memory pd) {
        pd = new bytes(39);
        pd[0] = 0x01; // tuple_count = 1
        pd[1] = 0x02; // tuples[0].claim_index = 2
        // tuples[0].operand[0..32] = 0x00000...033A (826 BE)
        pd[1 + 1 + 30] = 0x03;
        pd[1 + 1 + 31] = 0x3a;
        pd[1 + 33] = 0x02; // tuples[0].type_tag = HASH
        pd[1 + 34] = 0x10; // tuples[0].comparator = EQ
        pd[36] = 0x01; // op_count = 1
        pd[37] = 0x20; // ops[0].code = PUSH_TUPLE
        pd[38] = 0x00; // ops[0].operand = 0
    }

    function _defaultParams() internal view returns (IPetitionRegistry.PetitionParams memory p) {
        p = IPetitionRegistry.PetitionParams({
            rRoot: bytes32(uint256(1)),
            predicateDef: _predicateDef(),
            salt: bytes32(uint256(3)),
            classSet: _classSet(826, 840),
            classThresholds: _classThresholds(3, 3),
            classIndex: 2,
            closeAtBlock: uint64(block.number + 30),
            bounty: 1_000_000
        });
    }

    function _register(IPetitionRegistry.PetitionParams memory p) internal returns (bytes32 petitionId) {
        vm.prank(organizer);
        petitionId = registry.register(p);
    }

    function _registerDefault() internal returns (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) {
        p = _defaultParams();
        petitionId = _register(p);
    }

    /// Build a `BatchPublicInputs` consistent with a freshly-registered petition.
    function _batchPi(
        bytes32 petitionId,
        IPetitionRegistry.PetitionParams memory p,
        bytes32 newRunningRoot,
        bytes32 newIdtagRoot,
        bytes32 versionedHash
    ) internal view returns (IPetitionRegistry.BatchPublicInputs memory pi) {
        bytes32[24] memory blsFields;
        bytes32 predicateHash = registry.getPetition(petitionId).predicateHash;
        uint32 petitionSlot = registry.getPetition(petitionId).slot;
        pi = IPetitionRegistry.BatchPublicInputs({
            petitionId: petitionId,
            rRoot: p.rRoot,
            predicateHash: predicateHash,
            classIndex: p.classIndex,
            slot: petitionSlot,
            batchSize: uint32(BATCH_SIZE_MAX),
            priorRunningRoot: EMPTY_IMT_ROOT,
            newRunningRoot: newRunningRoot,
            priorIdentityTagSetRoot: EMPTY_IMT_ROOT,
            newIdentityTagSetRoot: newIdtagRoot,
            priorLeafCount: 0,
            newLeafCount: BATCH_SIZE_MAX,
            batchVersionedHash: versionedHash,
            blsFields: blsFields,
            signerVkHash: PINNED_SIGNER_VK_HASH
        });
    }

    /// Submit one batch, set `blobhash(0)` via cheatcode, return the
    /// new `runningRoot` and the versioned hash. KZG precompile mock
    /// is installed in `setUp`.
    function _publishBatch(bytes32 petitionId, IPetitionRegistry.PetitionParams memory p)
        internal
        returns (bytes32 newRunningRoot, bytes32 versionedHash)
    {
        newRunningRoot = bytes32(uint256(0xabc1));
        bytes32 newIdtagRoot = bytes32(uint256(0xabc2));
        versionedHash = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);

        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = versionedHash;
        vm.blobhashes(blobHashes);

        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, newRunningRoot, newIdtagRoot, versionedHash);

        vm.prank(relayer);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));
    }

    /// Build resolution PI for a registered+batched petition. After CRIT-1
    /// cleanup the struct only carries outcome bits (b, bPerClass); every
    /// other public input is sourced from PetitionRecord on-chain.
    function _resolutionPi(bool b) internal pure returns (IPetitionRegistry.ResolutionPublicInputs memory pi) {
        bool[] memory bpc = new bool[](2);
        bpc[0] = b;
        bpc[1] = b;
        pi = IPetitionRegistry.ResolutionPublicInputs({b: b, bPerClass: bpc});
    }

    function test_Register_Succeeds() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        uint256 organizerPre = token.balanceOf(organizer);
        bytes32 petitionId = _register(p);

        assertTrue(petitionId != bytes32(0), "petition id zero");
        assertEq(token.balanceOf(organizer), organizerPre - p.bounty, "organizer not debited");
        assertEq(token.balanceOf(address(registry)), p.bounty, "registry not credited");

        PetitionRegistry.PetitionRecord memory rec = registry.getPetition(petitionId);
        assertEq(uint8(rec.state), uint8(IPetitionRegistry.PetitionState.SigningOpen), "state != SigningOpen");
        assertEq(rec.bounty, p.bounty, "bounty mismatch");
        assertEq(rec.runningRoot, EMPTY_IMT_ROOT, "runningRoot != empty");
        assertEq(rec.identityTagSetRoot, EMPTY_IMT_ROOT, "idtagRoot != empty");
        assertEq(rec.organizer, organizer, "organizer mismatch");
    }

    function test_Register_RevertsOnPastCloseAtBlock() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        p.closeAtBlock = uint64(block.number);
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.InvalidPetition.selector);
        registry.register(p);
    }

    function test_Register_RevertsOnSigningWindowTooLong() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        p.closeAtBlock = uint64(block.number + MAX_SIGNING_WINDOW_BLOCKS + 1);
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.SigningWindowTooLong.selector);
        registry.register(p);
    }

    function test_Register_RevertsOnClassIndexOutOfRange() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        p.classIndex = 4; // attrCount = 4 in setUp; valid range is [0, 4)
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.InvalidPetition.selector);
        registry.register(p);
    }

    function test_Register_RevertsOnEmptyClassSet() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        p.classSet = new uint16[](0);
        p.classThresholds = new uint64[](0);
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.ClassSetInvalid.selector);
        registry.register(p);
    }

    function test_Register_RevertsOnUnsortedClassSet() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        p.classSet = _classSet(840, 826); // descending
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.ClassSetInvalid.selector);
        registry.register(p);
    }

    function test_Register_RevertsOnClassSetLengthMismatch() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        p.classThresholds = new uint64[](1);
        p.classThresholds[0] = 3;
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.ClassSetInvalid.selector);
        registry.register(p);
    }

    function test_Register_RevertsOnZeroThreshold() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        p.classThresholds = _classThresholds(0, 3);
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.ClassThresholdsInvalid.selector);
        registry.register(p);
    }

    function test_Register_RevertsOnBountyBelowFloor() public {
        IPetitionRegistry.PetitionParams memory p = _defaultParams();
        // floor = alpha(=1) * 10 * sum(3+3=6) * opCount(=1) = 60
        p.bounty = 59;
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.BountyFloor.selector);
        registry.register(p);
    }

    function test_Register_SlotIncrementsAcrossPetitions() public {
        IPetitionRegistry.PetitionParams memory p1 = _defaultParams();
        bytes32 id1 = _register(p1);
        // Second registration with different close window so the
        // derived petition_id differs.
        IPetitionRegistry.PetitionParams memory p2 = _defaultParams();
        p2.closeAtBlock = uint64(block.number + 31);
        bytes32 id2 = _register(p2);
        assertTrue(id1 != id2, "petition ids collide across slots");
        assertEq(registry.s(), 2, "slot counter not advanced");
    }

    function test_PublishBatch_Succeeds() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        (bytes32 newRoot, bytes32 vh) = _publishBatch(petitionId, p);

        assertEq(registry.getBatchCount(petitionId), 1, "batch count != 1");
        PetitionRegistry.PetitionRecord memory rec = registry.getPetition(petitionId);
        assertEq(rec.runningRoot, newRoot, "runningRoot not advanced");
        assertEq(rec.leafCount, BATCH_SIZE_MAX, "leafCount not advanced");
        PetitionRegistry.BatchRecord memory bat = registry.getBatch(petitionId, 0);
        assertEq(bat.batchVersionedHash, vh, "batch versioned hash mismatch");
        assertEq(bat.relayer, relayer, "relayer not recorded");
    }

    function test_PublishBatch_RevertsOnBatchSizeMismatch() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        pi.batchSize = 5; // != BATCH_SIZE_MAX
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.BatchSizeOutOfRange.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));
    }

    function test_PublishBatch_RevertsOnLeafCountMismatch() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        pi.newLeafCount = pi.priorLeafCount + pi.batchSize + 1;
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.InvalidBatch.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));
    }

    function test_PublishBatch_RevertsOnPriorRunningRootMismatch() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        pi.priorRunningRoot = bytes32(uint256(0xfeed)); // != EMPTY_IMT_ROOT
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.PriorStateMismatch.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));
    }

    function test_PublishBatch_RevertsOnBlobHashMismatch() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        bytes32 vhDeclared = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        bytes32 vhActual = bytes32(uint256(0xbad));
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vhDeclared);
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vhActual;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.BlobHashMismatch.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));
    }

    function test_PublishBatch_RevertsOnProofRejected() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        batchVerifier.setResult(false);

        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.ProofRejected.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));
    }

    function test_PublishBatch_RevertsOnKzgCommitmentWrongLength() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.InvalidBatch.selector);
        registry.publishBatch(pi, hex"00", new bytes(47), new bytes(48 * 24));
    }

    function test_PublishBatch_RevertsOnKzgProofsWrongLength() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.InvalidBatch.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 23));
    }

    function test_PublishBatch_RevertsAfterCooldown() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        vm.roll(p.closeAtBlock); // SigningOpen -> Cooldown
        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.InvalidState.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));
    }

    function test_Resolve_Succeeds() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        _publishBatch(petitionId, p);
        vm.roll(p.closeAtBlock + COOLDOWN_BLOCKS + 1);

        IPetitionRegistry.ResolutionPublicInputs memory pi = _resolutionPi(true);
        uint256 callerPre = token.balanceOf(resolver_);

        vm.expectEmit(true, false, false, true, address(registry));
        emit IPetitionRegistry.PetitionResolved(petitionId, true, pi.bPerClass);
        vm.expectEmit(true, false, false, true, address(registry));
        emit IPetitionRegistry.BountyPaid(petitionId, resolver_, p.bounty);

        vm.prank(resolver_);
        registry.resolve(petitionId, pi, hex"01");

        assertEq(token.balanceOf(resolver_), callerPre + p.bounty, "resolver bounty payout missing");
        PetitionRegistry.PetitionRecord memory rec = registry.getPetition(petitionId);
        assertEq(uint8(rec.state), uint8(IPetitionRegistry.PetitionState.Resolved), "state != Resolved");
        assertTrue(rec.b, "rec.b mismatch");
    }

    function test_Resolve_RevertsBeforeDisputeWindow() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        _publishBatch(petitionId, p);
        // SigningOpen -> Cooldown but NOT into DisputeWindow.
        vm.roll(p.closeAtBlock);
        IPetitionRegistry.ResolutionPublicInputs memory pi = _resolutionPi(true);
        vm.prank(resolver_);
        vm.expectRevert(PetitionRegistry.InvalidState.selector);
        registry.resolve(petitionId, pi, hex"01");
    }

    /// CRIT-1 regression: after the cleanup, runningRoot is sourced from
    /// rec.* and the caller cannot substitute it. Any staleness in the
    /// verifier's view of running_root surfaces from the verifier as
    /// ProofRejected. Covered transitively by test_Resolve_RevertsOnProofRejected;
    /// no separate runningRoot/leafCount mismatch test is needed.

    function test_Resolve_RevertsOnBPerClassLengthMismatch() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        _publishBatch(petitionId, p);
        vm.roll(p.closeAtBlock + COOLDOWN_BLOCKS + 1);
        // Registered class_set has length 2; submit a length-3 outcome vector.
        bool[] memory bpc = new bool[](3);
        bpc[0] = true;
        bpc[1] = true;
        bpc[2] = true;
        IPetitionRegistry.ResolutionPublicInputs memory pi =
            IPetitionRegistry.ResolutionPublicInputs({b: true, bPerClass: bpc});
        vm.prank(resolver_);
        vm.expectRevert(PetitionRegistry.PriorStateMismatch.selector);
        registry.resolve(petitionId, pi, hex"01");
    }

    function test_Resolve_RevertsOnProofRejected() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        _publishBatch(petitionId, p);
        vm.roll(p.closeAtBlock + COOLDOWN_BLOCKS + 1);
        resolutionVerifier.setResult(false);
        IPetitionRegistry.ResolutionPublicInputs memory pi = _resolutionPi(true);
        vm.prank(resolver_);
        vm.expectRevert(PetitionRegistry.ProofRejected.selector);
        registry.resolve(petitionId, pi, hex"01");
    }

    function test_Resolve_RevertsOnSecondResolve() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        _publishBatch(petitionId, p);
        vm.roll(p.closeAtBlock + COOLDOWN_BLOCKS + 1);
        IPetitionRegistry.ResolutionPublicInputs memory pi = _resolutionPi(true);
        vm.prank(resolver_);
        registry.resolve(petitionId, pi, hex"01");
        // Second attempt: state is now `Resolved`, not `DisputeWindow`.
        vm.prank(resolver_);
        vm.expectRevert(PetitionRegistry.InvalidState.selector);
        registry.resolve(petitionId, pi, hex"01");
    }

    function test_MarkUnresolved_Succeeds() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        _publishBatch(petitionId, p);
        vm.roll(p.closeAtBlock + RESOLUTION_DEADLINE_BLOCKS + 1);

        uint256 organizerPre = token.balanceOf(organizer);
        uint256 callerPre = token.balanceOf(resolver_);
        // New formula: rebate = min(GAS_ESTIMATE * tx.gasprice, bounty * 1%).
        // Force tx.gasprice high enough that the cap fires (= bounty * 1%).
        vm.txGasPrice(1_000_000_000); // 1 gwei
        uint256 rebateCap = (p.bounty * 100) / 10_000;
        uint256 estimatedCost = uint256(100_000) * tx.gasprice;
        uint256 rebate = estimatedCost < rebateCap ? estimatedCost : rebateCap;
        uint256 refund = p.bounty - rebate;

        vm.expectEmit(true, false, false, false, address(registry));
        emit IPetitionRegistry.PetitionUnresolved(petitionId);

        vm.prank(resolver_);
        registry.markUnresolved(petitionId);

        assertEq(token.balanceOf(organizer), organizerPre + refund, "organizer refund missing");
        assertEq(token.balanceOf(resolver_), callerPre + rebate, "caller rebate missing");
        PetitionRegistry.PetitionRecord memory rec = registry.getPetition(petitionId);
        assertEq(uint8(rec.state), uint8(IPetitionRegistry.PetitionState.Unresolved), "state != Unresolved");
        assertEq(rec.runningRoot, registry.TOMBSTONE_RUNNING_ROOT(), "runningRoot != tombstone");
    }

    function test_MarkUnresolved_RevertsBeforeDeadline() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        _publishBatch(petitionId, p);
        // In DisputeWindow but before the resolution deadline.
        vm.roll(p.closeAtBlock + COOLDOWN_BLOCKS + 1);
        vm.prank(resolver_);
        vm.expectRevert(PetitionRegistry.TooEarly.selector);
        registry.markUnresolved(petitionId);
    }

    function test_MarkUnresolved_RevertsOutsideDisputeWindow() public {
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        // Still in SigningOpen — never advanced.
        vm.prank(resolver_);
        vm.expectRevert(PetitionRegistry.InvalidState.selector);
        registry.markUnresolved(petitionId);
    }

    function test_UpdateAlpha_Succeeds() public {
        vm.expectEmit(false, false, false, true, address(registry));
        emit IPetitionRegistry.AlphaUpdated(1, 50);
        vm.prank(governance);
        registry.updateAlpha(50);
        assertEq(registry.alpha(), 50, "alpha not updated");
    }

    function test_UpdateAlpha_RevertsForNonGovernance() public {
        vm.prank(organizer);
        vm.expectRevert(PetitionRegistry.NotGovernance.selector);
        registry.updateAlpha(50);
    }

    function test_UpdateAlpha_RevertsBelowMin() public {
        vm.prank(governance);
        vm.expectRevert(PetitionRegistry.AlphaOutOfBounds.selector);
        registry.updateAlpha(0);
    }

    function test_UpdateAlpha_RevertsAboveMax() public {
        vm.prank(governance);
        vm.expectRevert(PetitionRegistry.AlphaOutOfBounds.selector);
        registry.updateAlpha(1_001);
    }

    function test_StateTransitions_AutoAdvance() public {
        // Reverts roll back storage, so the only way to observe a
        // state transition is via a successful call. The publishBatch
        // happy path proves SigningOpen; the resolve happy path
        // proves DisputeWindow. Here we assert the negative
        // transitions: any state-touching call past `closeAtBlock`
        // rejects publishBatch (state moved past SigningOpen), and
        // before `closeAtBlock + COOLDOWN_BLOCKS` rejects resolve
        // (state hasn't reached DisputeWindow yet).
        (bytes32 petitionId, IPetitionRegistry.PetitionParams memory p) = _registerDefault();
        bytes32 vh = bytes32(uint256(0x0142)) | (bytes32(uint256(0x01)) << 248);
        IPetitionRegistry.BatchPublicInputs memory pi =
            _batchPi(petitionId, p, bytes32(uint256(0xabc1)), bytes32(uint256(0xabc2)), vh);
        bytes32[] memory blobHashes = new bytes32[](1);
        blobHashes[0] = vh;
        vm.blobhashes(blobHashes);

        // At closeAtBlock: state advances to Cooldown -> InvalidState.
        vm.roll(p.closeAtBlock);
        vm.prank(relayer);
        vm.expectRevert(PetitionRegistry.InvalidState.selector);
        registry.publishBatch(pi, hex"00", new bytes(48), new bytes(48 * 24));

        // Between Cooldown and DisputeWindow: resolve also rejects.
        IPetitionRegistry.ResolutionPublicInputs memory rpi = _resolutionPi(true);
        vm.prank(resolver_);
        vm.expectRevert(PetitionRegistry.InvalidState.selector);
        registry.resolve(petitionId, rpi, hex"01");
    }
}

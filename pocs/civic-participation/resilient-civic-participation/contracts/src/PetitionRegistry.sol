// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "./interfaces/IVerifier.sol";
import {IPetitionRegistry} from "./interfaces/IPetitionRegistry.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";

/// @title PetitionRegistry
/// @notice On-chain state machine for the Resilient Civic Participation
///         protocol. Holds petition records, batch records, IMT roots,
///         and resolution outputs. The batch SNARK recursively verifies
///         all per-signer SNARKs in-circuit (SPEC Batch SNARK
///         constraint 2), so the registry only verifies one outer proof
///         per batch and one resolution proof per outcome. Records live
///         in the EIP-4844 blob attached to the publishBatch
///         transaction; the contract binds `blobhash(0)` into the batch
///         public inputs and never reads record contents from calldata.
///         Disputes verify KZG point-evaluation openings via the
///         precompile at address 0x0a.
contract PetitionRegistry is IPetitionRegistry {
    // ---------- Storage ----------

    struct PetitionRecord {
        bytes32 rRoot;
        bytes32 predicateHash;
        bytes32 predicateHashPreId;
        bytes32 salt;
        uint16[] classSet;
        uint64[] classThresholds;
        uint8 classIndex;
        uint64 closeAtBlock;
        uint64 registrationBlock;
        uint32 slot;
        uint256 bounty;
        uint64 alphaAtRegistration;
        address organizer;
        bytes32 runningRoot;
        bytes32 identityTagSetRoot;
        uint64 leafCount;
        uint32 nextBatchIndex;
        bool b;
        bool[] bPerClass;
        PetitionState state;
    }

    struct BatchRecord {
        bytes32 batchVersionedHash;
        bytes32 priorRunningRoot;
        bytes32 newRunningRoot;
        bytes32 priorIdentityTagSetRoot;
        bytes32 newIdentityTagSetRoot;
        uint64 priorLeafCount;
        uint64 newLeafCount;
        address relayer;
        uint64 submittedAtBlock;
        BatchState state;
    }

    mapping(bytes32 => PetitionRecord) internal petitions;
    mapping(bytes32 => BatchRecord[]) internal batches;

    IVerifier public immutable batchVerifier;
    IVerifier public immutable resolutionVerifier;
    address public immutable bountyToken;
    address public governance;

    uint64 public alpha;
    uint64 public alphaMin;
    uint64 public alphaMax;
    bytes32 public srsHash;
    uint8 public attrCount;
    uint32 public s;

    /// 12-second block assumption (post-Merge Ethereum mainnet). 2 hours.
    /// Deployments on chains with different block cadence MUST recompute.
    uint64 public constant COOLDOWN_BLOCKS = 600;
    /// 12-second block assumption. 14 days.
    uint64 public constant RESOLUTION_DEADLINE_BLOCKS = 100_800;
    /// 12-second block assumption. 11.5 days.
    uint64 public constant MAX_SIGNING_WINDOW_BLOCKS = 82_800;
    uint32 public constant BATCH_SIZE_MAX = 6;
    bytes32 public constant DOMAIN_PETITION_ID = keccak256("RCP/petition_id/v1");
    bytes32 public constant TOMBSTONE_RUNNING_ROOT = bytes32(uint256(1));
    uint16 public constant GAS_REBATE_BPS = 100;
    /// Gas estimate for `markUnresolved` reimbursement (per call).
    /// Used by the gas-based rebate cap; conservative upper bound.
    uint256 public constant MARK_UNRESOLVED_GAS_ESTIMATE = 100_000;
    /// Poseidon1 domain separator constants (mirrors
    /// circuits/lib/src/domain.nr and src/poseidon.rs).
    uint256 internal constant DOMAIN_NULLIFIER = 1;
    uint256 internal constant DOMAIN_IDTAG = 2;
    uint256 internal constant DOMAIN_LEAF = 3;
    uint256 internal constant DOMAIN_FSRT_PRG = 4;
    uint256 internal constant DOMAIN_PRED = 5;
    uint256 internal constant DOMAIN_ATTR = 6;
    uint256 internal constant DOMAIN_BATCH_SNARK = 7;
    uint256 internal constant DOMAIN_PETITION = 8;
    uint256 internal constant DOMAIN_RESOLUTION_SNARK = 9;

    // ---------- Errors ----------
    error NotGovernance();
    error InvalidPetition();
    error InvalidState();
    error InvalidBatch();
    error InvalidDispute();
    error BountyFloor();
    error ClassThresholdsInvalid();
    error ClassSetInvalid();
    error SigningWindowTooLong();
    error BatchSizeOutOfRange();
    error PriorStateMismatch();
    error ProofRejected();
    error BlobHashMismatch();
    error AlreadyResolved();
    error TooEarly();
    error AlphaOutOfBounds();
    error PaymentFailed();
    error ViolationFalse();
    error PredicateHashMismatch();
    error PredicateMalformed();
    error ClassBindingMissing();
    error VerifierAddressInvalid();
    error SignerVkHashMismatch();
    error SlotOverflow();

    // ---------- Constructor ----------

    struct InitArgs {
        IVerifier batchVerifier;
        IVerifier resolutionVerifier;
        address bountyToken;
        address governance;
        uint64 alpha;
        uint64 alphaMin;
        uint64 alphaMax;
        bytes32 srsHash;
        uint8 attrCount;
        bytes32 emptyImtRoot;
        /// Deploy-pinned hash of the signer SNARK's verification key.
        /// Every batch proof must commit to this value as a public input.
        bytes32 pinnedSignerVkHash;
    }

    /// Poseidon1 hash of the empty depth-24 indexed Merkle tree (with
    /// the implicit (0, 0, 0) leaf at index 0). Off-chain code computes
    /// this with `IndexedMerkleTree::new().root_fr()`; the deployer
    /// passes it in so a fresh `PetitionRecord` matches the empty-IMT
    /// state the relayer's running and identity-tag IMTs maintain.
    bytes32 public immutable emptyImtRoot;

    /// Deploy-pinned signer VK hash.
    bytes32 public immutable pinnedSignerVkHash;

    constructor(InitArgs memory args) {
        // Reject zero-address and EOA verifiers/token.
        if (address(args.batchVerifier) == address(0)) revert VerifierAddressInvalid();
        if (address(args.resolutionVerifier) == address(0)) revert VerifierAddressInvalid();
        if (args.bountyToken == address(0)) revert VerifierAddressInvalid();
        if (address(args.batchVerifier).code.length == 0) revert VerifierAddressInvalid();
        if (address(args.resolutionVerifier).code.length == 0) revert VerifierAddressInvalid();
        if (args.bountyToken.code.length == 0) revert VerifierAddressInvalid();

        batchVerifier = args.batchVerifier;
        resolutionVerifier = args.resolutionVerifier;
        bountyToken = args.bountyToken;
        governance = args.governance;
        alpha = args.alpha;
        alphaMin = args.alphaMin;
        alphaMax = args.alphaMax;
        srsHash = args.srsHash;
        attrCount = args.attrCount;
        emptyImtRoot = args.emptyImtRoot;
        pinnedSignerVkHash = args.pinnedSignerVkHash;
    }

    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    // ---------- Register ----------

    /// register does not accept caller-supplied predicateHash /
    /// predicateHashPreId. Both are recomputed on-chain from
    /// `params.predicateDef` via Poseidon1 (PoseidonT3 library).
    function register(PetitionParams calldata params) external returns (bytes32 petitionId) {
        _validateParams(params);
        _validateClassBinding(params.predicateDef, params.classIndex, params.classSet);

        uint32 sAtReg = s;
        // SPEC sec FSRT Chain: `S` is bounded by `N - 1 = 2^24 - 1`.
        if (sAtReg >= (1 << 24)) revert SlotOverflow();
        bytes32 predicateHash;
        bytes32 predicateHashPreId;
        (petitionId, predicateHash, predicateHashPreId) = _deriveIds(params, sAtReg);

        _writePetition(petitionId, params, predicateHash, predicateHashPreId, sAtReg);
        s = sAtReg + 1;
        _safeTransferFrom(bountyToken, msg.sender, address(this), params.bounty);
        _emitRegistered(petitionId, sAtReg, params, predicateHash);
    }

    function _deriveIds(PetitionParams calldata params, uint32 sAtReg)
        internal
        view
        returns (bytes32 petitionId, bytes32 predicateHash, bytes32 predicateHashPreId)
    {
        bytes32[34] memory canonical = _canonicalScalars(params.predicateDef);
        predicateHashPreId = _recomputePredicateHash(canonical, bytes32(0), params.salt);
        petitionId = _derivePetitionId(params, predicateHashPreId, sAtReg);
        predicateHash = _recomputePredicateHash(canonical, petitionId, params.salt);
    }

    function _emitRegistered(bytes32 petitionId, uint32 sAtReg, PetitionParams calldata params, bytes32 predicateHash)
        internal
    {
        emit PetitionRegistered(
            petitionId,
            sAtReg,
            params.rRoot,
            predicateHash,
            params.classSet,
            params.classThresholds,
            params.classIndex,
            params.closeAtBlock,
            params.bounty
        );
    }

    function _validateParams(PetitionParams calldata params) internal view {
        if (params.closeAtBlock <= block.number) revert InvalidPetition();
        if (params.closeAtBlock - block.number > MAX_SIGNING_WINDOW_BLOCKS) revert SigningWindowTooLong();
        if (params.classIndex >= attrCount) revert InvalidPetition();

        uint256 n = params.classSet.length;
        if (n == 0 || n != params.classThresholds.length) revert ClassSetInvalid();
        // Bound class_set size at the resolution circuit's CLASS_MAX.
        if (n > 16) revert ClassSetInvalid();
        for (uint256 i = 1; i < n; i++) {
            if (params.classSet[i] <= params.classSet[i - 1]) revert ClassSetInvalid();
        }
        uint256 sumThresholds = 0;
        for (uint256 i = 0; i < n; i++) {
            if (params.classThresholds[i] < 1) revert ClassThresholdsInvalid();
            sumThresholds += params.classThresholds[i];
        }

        // Bound predicateDef length per SPEC.
        if (params.predicateDef.length > 1024) revert PredicateMalformed();
        if (params.predicateDef.length < 2) revert PredicateMalformed();
        uint8 tupleCount = uint8(params.predicateDef[0]);
        if (tupleCount < 1 || tupleCount > 20) revert PredicateMalformed();
        uint256 opOff = 1 + uint256(tupleCount) * 35;
        if (opOff >= params.predicateDef.length) revert PredicateMalformed();
        uint8 opCount = uint8(params.predicateDef[opOff]);
        if (opCount < 1 || opCount > 20) revert PredicateMalformed();
        // Total serialized length check.
        if (params.predicateDef.length != opOff + 1 + uint256(opCount) * 2) {
            revert PredicateMalformed();
        }
        uint256 floor_ = uint256(alpha) * 10 * sumThresholds * uint256(opCount);
        if (params.bounty < floor_) revert BountyFloor();
    }

    // ---------- Poseidon helpers ----------

    function _poseidon2(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256[2] memory inp = [a, b];
        return PoseidonT3.hash(inp);
    }

    function _poseidon3(uint256 a, uint256 b, uint256 c) internal pure returns (uint256) {
        uint256[3] memory inp = [a, b, c];
        return PoseidonT4.hash(inp);
    }

    /// Mirrors `src/predicate.rs::canonical_scalars` and
    /// `circuits/lib/src/predicate.nr::encode_canonical_def` scalar pack.
    function _canonicalScalars(bytes calldata predicateDef) internal pure returns (bytes32[34] memory out) {
        uint256 len = predicateDef.length;
        // Segment 0: 0x00 (top) | length_hi | length_lo | def[0..29]
        bytes memory seg0 = new bytes(32);
        seg0[1] = bytes1(uint8(len >> 8));
        seg0[2] = bytes1(uint8(len & 0xff));
        uint256 n0 = len > 29 ? 29 : len;
        for (uint256 k = 0; k < n0; k++) {
            seg0[3 + k] = predicateDef[k];
        }
        out[0] = _bytes32From(seg0);
        // Segments 1..33: 0x00 (top) | def[29 + 31*(i-1) .. 29 + 31*i]
        for (uint256 i = 1; i < 34; i++) {
            bytes memory seg = new bytes(32);
            uint256 srcOff = 29 + 31 * (i - 1);
            for (uint256 k = 0; k < 31 && srcOff + k < len; k++) {
                seg[1 + k] = predicateDef[srcOff + k];
            }
            out[i] = _bytes32From(seg);
        }
    }

    function _bytes32From(bytes memory b) internal pure returns (bytes32 r) {
        require(b.length == 32, "bytes32From: bad length");
        assembly {
            r := mload(add(b, 32))
        }
    }

    /// Mirrors `src/poseidon.rs::hash_predicate` and Noir
    /// `circuits/lib/src/hasher.nr::hash_predicate`: iterated Poseidon2
    /// chain starting from DOMAIN_PRED, folding canonical[0..34], then
    /// petition_id, then salt.
    function _recomputePredicateHash(bytes32[34] memory canonical, bytes32 petitionId, bytes32 salt)
        internal
        pure
        returns (bytes32)
    {
        uint256 acc = DOMAIN_PRED;
        for (uint256 i = 0; i < 34; i++) {
            acc = _poseidon2(acc, uint256(canonical[i]));
        }
        acc = _poseidon2(acc, uint256(petitionId));
        acc = _poseidon2(acc, uint256(salt));
        return bytes32(acc);
    }

    /// Structural class-binding validation. Mirrors
    /// `src/predicate.rs::validate_class_binding` but TIGHTENS to require
    /// the class-binding tuple to be `tuples[0]` (matching the Noir
    /// signer SNARK constraint that ties tuples[0] to (class_index,
    /// class_tag, EQ)).
    function _validateClassBinding(bytes calldata predicateDef, uint8 classIndex, uint16[] calldata classSet)
        internal
        pure
    {
        uint8 tupleCount = uint8(predicateDef[0]);
        uint256 opOff = 1 + uint256(tupleCount) * 35;
        uint8 opCount = uint8(predicateDef[opOff]);

        // Identify class-binding tuples: claim_index == classIndex,
        // operand < 2^16 with value in classSet, comparator == EQ.
        // Any PUSH of such a tuple is "Bound"; non-binding pushes are
        // "Free". The OR rule then requires BOTH branches to be Bound
        // for the result to remain Bound, so the multi-class predicate
        // (e.g. "attr == A OR attr == B" with A, B in classSet) is
        // accepted while OR(Bound, Free) is tainted.
        bool[20] memory isBindingTuple;
        for (uint256 t = 0; t < tupleCount; t++) {
            uint256 tOff = 1 + t * 35;
            if (uint8(predicateDef[tOff]) != classIndex) continue;
            uint8 typeTag = uint8(predicateDef[tOff + 33]);
            if (typeTag != 0x01 && typeTag != 0x02 && typeTag != 0x03) {
                revert PredicateMalformed();
            }
            if (uint8(predicateDef[tOff + 34]) != 0x10) continue; // not EQ
            bool highZero = true;
            for (uint256 b = 0; b < 30; b++) {
                if (uint8(predicateDef[tOff + 1 + b]) != 0) {
                    highZero = false;
                    break;
                }
            }
            if (!highZero) continue;
            uint16 ct = (uint16(uint8(predicateDef[tOff + 1 + 30])) << 8) | uint16(uint8(predicateDef[tOff + 1 + 31]));
            if (_classInSetMemory(ct, classSet)) {
                isBindingTuple[t] = true;
            }
        }
        // At least one tuple must be class-binding.
        bool anyBinding;
        for (uint256 t = 0; t < tupleCount; t++) {
            if (isBindingTuple[t]) {
                anyBinding = true;
                break;
            }
        }
        if (!anyBinding) revert ClassBindingMissing();

        uint8[20] memory taint;
        uint256 sp = 0;
        for (uint256 i = 0; i < opCount; i++) {
            uint8 code = uint8(predicateDef[opOff + 1 + i * 2]);
            uint8 operand = uint8(predicateDef[opOff + 1 + i * 2 + 1]);
            if (code == 0x20) {
                // PUSH_TUPLE
                if (sp >= 20) revert PredicateMalformed();
                if (operand >= tupleCount) revert PredicateMalformed();
                taint[sp] = isBindingTuple[operand] ? 1 : 0;
                sp++;
            } else if (code == 0x21) {
                // AND
                if (operand != 0) revert PredicateMalformed();
                if (sp < 2) revert PredicateMalformed();
                uint8 a = taint[sp - 1];
                uint8 b = taint[sp - 2];
                uint8 combined = (a == 1 || b == 1) ? 1 : ((a == 2 || b == 2) ? 2 : 0);
                taint[sp - 2] = combined;
                sp--;
            } else if (code == 0x22) {
                // OR: both branches must commit to the class binding
                // for the result to remain Bound. If only one side is
                // Bound, the other side could let an off-class signer
                // through, so we taint. Both Bound -> Bound covers the
                // canonical multi-class predicate (e.g. "attr == A OR
                // attr == B" when A, B both in class_set).
                if (operand != 0) revert PredicateMalformed();
                if (sp < 2) revert PredicateMalformed();
                uint8 a = taint[sp - 1];
                uint8 b = taint[sp - 2];
                uint8 combined;
                if (a == 1 && b == 1) {
                    combined = 1;
                } else if (a == 1 || b == 1 || a == 2 || b == 2) {
                    combined = 2;
                } else {
                    combined = 0;
                }
                taint[sp - 2] = combined;
                sp--;
            } else if (code == 0x23) {
                // NOT (taints Bound)
                if (operand != 0) revert PredicateMalformed();
                if (sp < 1) revert PredicateMalformed();
                uint8 a = taint[sp - 1];
                taint[sp - 1] = a == 1 ? 2 : a;
            } else if (code == 0xff) {
                // NOP
                if (operand != 0) revert PredicateMalformed();
            } else {
                revert PredicateMalformed();
            }
        }
        if (sp != 1) revert PredicateMalformed();
        if (taint[0] != 1) revert ClassBindingMissing();
    }

    function _classInSetMemory(uint16 c, uint16[] calldata set) internal pure returns (bool) {
        uint256 lo = 0;
        uint256 hi = set.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            uint16 v = set[mid];
            if (v == c) return true;
            if (v < c) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }

    function _derivePetitionId(PetitionParams calldata params, bytes32 predicateHashPreId, uint32 sAtReg)
        internal
        view
        returns (bytes32)
    {
        bytes32 h = keccak256(
            abi.encodePacked(
                DOMAIN_PETITION_ID,
                uint64(block.chainid),
                address(this),
                msg.sender,
                sAtReg,
                predicateHashPreId,
                params.closeAtBlock
            )
        );
        // Mask the top byte so the resulting bytes32 is always less
        // than the BN254 scalar field modulus. This keeps the on-chain
        // bytes32 identifier and the signer SNARK's `petition_id` Fr
        // public input bit-identical (no silent modular reduction).
        return h & bytes32(uint256(0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff));
    }

    function _writePetition(
        bytes32 petitionId,
        PetitionParams calldata params,
        bytes32 predicateHash,
        bytes32 predicateHashPreId,
        uint32 sAtReg
    ) internal {
        PetitionRecord storage rec = petitions[petitionId];
        if (rec.state != PetitionState.Unset) revert InvalidPetition();
        _writeScalars(rec, params, predicateHash, predicateHashPreId, sAtReg);
        rec.classSet = params.classSet;
        rec.classThresholds = params.classThresholds;
        // SPEC: Registered -> SigningOpen is atomic with the registration
        // call. The Registered enum value documents the lifecycle but
        // is never externally observed because the promotion happens
        // synchronously here.
        rec.state = PetitionState.SigningOpen;
    }

    function _writeScalars(
        PetitionRecord storage rec,
        PetitionParams calldata params,
        bytes32 predicateHash,
        bytes32 predicateHashPreId,
        uint32 sAtReg
    ) internal {
        rec.rRoot = params.rRoot;
        rec.predicateHash = predicateHash;
        rec.predicateHashPreId = predicateHashPreId;
        rec.salt = params.salt;
        rec.classIndex = params.classIndex;
        rec.closeAtBlock = params.closeAtBlock;
        rec.registrationBlock = uint64(block.number);
        rec.slot = sAtReg;
        rec.bounty = params.bounty;
        rec.alphaAtRegistration = alpha;
        rec.organizer = msg.sender;
        rec.runningRoot = emptyImtRoot;
        rec.identityTagSetRoot = emptyImtRoot;
    }

    // ---------- Publish batch ----------

    /// @notice Publish a batch. The transaction MUST be an EIP-4844 blob
    ///         transaction; the registry reads `blobhash(0)` and binds
    ///         it into `pi.batchVersionedHash`. The batch SNARK
    ///         encapsulates verification of all signer SNARKs (SPEC
    ///         constraint 2) and the IMT advance; the cross-field
    ///         binding to the blob (constraint 8) is closed by per-
    ///         position KZG point-evaluation against `batchVersionedHash`.
    /// @param pi             Batch SNARK public inputs (including blsFields).
    /// @param batchProof     bb-emitted UltraHonk proof bytes.
    /// @param kzgCommitment  48-byte KZG commitment to the published blob.
    /// @param kzgProofs      Concatenated 48-byte KZG proofs, one per
    ///                       canonical evaluation point `omega^k` for
    ///                       k in [0, 24). Length MUST equal `24 * 48`.
    function publishBatch(
        BatchPublicInputs calldata pi,
        bytes calldata batchProof,
        bytes calldata kzgCommitment,
        bytes calldata kzgProofs
    ) external {
        _preflightBatch(pi);
        if (!batchVerifier.verify(batchProof, _batchPublicInputs(pi))) revert ProofRejected();
        _verifyConstraint8Openings(pi, kzgCommitment, kzgProofs);
        _commitBatch(pi);
    }

    // EIP-4844 stores blobs in bit-reversal-permuted evaluation form,
    // so the canonical eval point at index `k` is `omega^{br(k, 12)}`
    // where `omega` is the primitive 4096th root of unity in BLS12-381
    function _kzgEvalPoint(uint256 k) internal pure returns (bytes32) {
        if (k == 0) return bytes32(uint256(0x0000000000000000000000000000000000000000000000000000000000000001));
        if (k == 1) return bytes32(uint256(0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000000));
        if (k == 2) return bytes32(uint256(0x00000000000000008d51ccce760304d0ec030002760300000001000000000000));
        if (k == 3) return bytes32(uint256(0x73eda753299d7d47a5e80b39939ed33467baa40089fb5bfefffeffff00000001));
        if (k == 4) return bytes32(uint256(0x345766f603fa66e78c0625cd70d77ce2b38b21c28713b7007228fd3397743f7a));
        if (k == 5) return bytes32(uint256(0x3f96405d25a31660a733b23a98ca5b22a032824078eaa4fe8dd702cb688bc087));
        if (k == 6) return bytes32(uint256(0x1333b22e5ce11044babc5affca86bf658e74903694b04fd86037fe81ae99502e));
        if (k == 7) return bytes32(uint256(0x60b9f524ccbc6d03787d7d083f1b189fc54913cc6b4e0c269fc8017d5166afd3));
        if (k == 8) return bytes32(uint256(0x20b1ce9140267af9dd1c0af834cec32c17beb312f20b6f7653ea61d87742bcce));
        if (k == 9) return bytes32(uint256(0x533bd8c1e977024e561dcd0fd4d314d93bfef0f00df2ec88ac159e2688bd4333));
        if (k == 10) return bytes32(uint256(0x4f2c596e753e4fcc6e92a9c460afca4a1ef4e672ebc1e1bb95df4b360411fe73));
        if (k == 11) return bytes32(uint256(0x24c14de4b45f2d7bc4a72e43a8f20dbb34c8bd90143c7a436a20b4c8fbee018e));
        if (k == 12) return bytes32(uint256(0x1edc919ec91f38ac5ccd4631f16edba4967a6b6cfb0faca4807b811a823f728d));
        if (k == 13) return bytes32(uint256(0x551115b4607e449bd66c91d61832fc60bd43389604eeaf5a7f847ee47dc08d74));
        if (k == 14) return bytes32(uint256(0x38c7f2dd7e0c63fccabf643eda8951f257bc96af334c36bca1abb31fb37786b9));
        if (k == 15) return bytes32(uint256(0x3b25b475ab91194b687a73c92f188612fc010d53ccb225425e544cdf4c887948));
        if (k == 16) return bytes32(uint256(0x50e0903a157988bab4bcd40e22f55448bf6e88fb4c38fb8a360c60997369df4e));
        if (k == 17) return bytes32(uint256(0x230d17191423f48d7e7d03f9e6ac83bc944f1b07b3c56074c9f39f658c9620b3));
        if (k == 18) return bytes32(uint256(0x65f6c5837cb5fca206050b5832d1099726bc7f62d13a6e1c3ec50c9031a36ca3));
        if (k == 19) return bytes32(uint256(0x0df6e1cface780a62d34ccafd6d0ce6e2d0124a02ec3ede2c13af36ece5c935e));
        if (k == 20) return bytes32(uint256(0x2c7e0457c83a7d9c5aea51f540eb0c04963dc46688b5e11768cc0c58459f155b));
        if (k == 21) return bytes32(uint256(0x476fa2fb6162ffabd84f8612c8b6cc00bd7fdf9c77487ae79733f3a6ba60eaa6));
        if (k == 22) return bytes32(uint256(0x5303da18a9d30564a8f0cfd2438f018c01e943612401899720d4ed194fccfeb9));
        return bytes32(uint256(0x20e9cd3a7fca77e38a490835c612d67951d460a1dbfcd267df2b12e5b0330148));
    }

    function _verifyConstraint8Openings(
        BatchPublicInputs calldata pi,
        bytes calldata kzgCommitment,
        bytes calldata kzgProofs
    ) internal view {
        if (kzgCommitment.length != 48) revert InvalidBatch();
        if (kzgProofs.length != 48 * 24) revert InvalidBatch();
        for (uint256 k = 0; k < 24; k++) {
            _verifyKzgOpening(
                pi.batchVersionedHash, _kzgEvalPoint(k), pi.blsFields[k], kzgCommitment, kzgProofs[k * 48:(k + 1) * 48]
            );
        }
    }

    function _preflightBatch(BatchPublicInputs calldata pi) internal {
        PetitionRecord storage rec = petitions[pi.petitionId];
        _advanceStateOnRead(rec);
        if (rec.state != PetitionState.SigningOpen) revert InvalidState();
        // SPEC sec Batch Publication step 4: `[1, BATCH_SIZE_MAX]`. The PoC
        // batch circuit additionally enforces `batch_size == BATCH_SIZE_MAX`
        // (see circuits/batch/src/main.nr); production removes the circuit-side
        // equality and accepts the full SPEC range here.
        if (pi.batchSize == 0 || pi.batchSize > BATCH_SIZE_MAX) revert BatchSizeOutOfRange();
        if (pi.newLeafCount != pi.priorLeafCount + pi.batchSize) revert InvalidBatch();
        if (pi.signerVkHash != pinnedSignerVkHash) revert SignerVkHashMismatch();
        _checkPriorState(rec, pi);
        if (blobhash(0) != pi.batchVersionedHash) revert BlobHashMismatch();
    }

    function _checkPriorState(PetitionRecord storage rec, BatchPublicInputs calldata pi) internal view {
        if (rec.runningRoot != pi.priorRunningRoot) revert PriorStateMismatch();
        if (rec.identityTagSetRoot != pi.priorIdentityTagSetRoot) revert PriorStateMismatch();
        if (rec.leafCount != pi.priorLeafCount) revert PriorStateMismatch();
        if (rec.rRoot != pi.rRoot) revert PriorStateMismatch();
        if (rec.predicateHash != pi.predicateHash) revert PriorStateMismatch();
        if (rec.classIndex != pi.classIndex) revert PriorStateMismatch();
        if (pi.slot != rec.slot) revert PriorStateMismatch();
    }

    function _commitBatch(BatchPublicInputs calldata pi) internal {
        PetitionRecord storage rec = petitions[pi.petitionId];
        uint32 batchIndex = rec.nextBatchIndex;
        batches[pi.petitionId].push(
            BatchRecord({
                batchVersionedHash: pi.batchVersionedHash,
                priorRunningRoot: pi.priorRunningRoot,
                newRunningRoot: pi.newRunningRoot,
                priorIdentityTagSetRoot: pi.priorIdentityTagSetRoot,
                newIdentityTagSetRoot: pi.newIdentityTagSetRoot,
                priorLeafCount: pi.priorLeafCount,
                newLeafCount: pi.newLeafCount,
                relayer: msg.sender,
                submittedAtBlock: uint64(block.number),
                state: BatchState.Active
            })
        );
        rec.runningRoot = pi.newRunningRoot;
        rec.identityTagSetRoot = pi.newIdentityTagSetRoot;
        rec.leafCount = pi.newLeafCount;
        rec.nextBatchIndex = batchIndex + 1;
        emit BatchPublished(
            pi.petitionId,
            batchIndex,
            pi.batchVersionedHash,
            pi.newRunningRoot,
            pi.newIdentityTagSetRoot,
            pi.newLeafCount
        );
    }

    // ---------- Resolve ----------

    function resolve(bytes32 petitionId, ResolutionPublicInputs calldata pi, bytes calldata resolutionProof) external {
        PetitionRecord storage rec = petitions[petitionId];
        _advanceStateOnRead(rec);
        if (rec.state != PetitionState.DisputeWindow) revert InvalidState();
        if (rec.bPerClass.length != 0) revert AlreadyResolved();

        if (!resolutionVerifier.verify(resolutionProof, _resolutionPublicInputs(rec, pi))) revert ProofRejected();

        rec.b = pi.b;
        rec.bPerClass = pi.bPerClass;
        rec.state = PetitionState.Resolved;
        emit PetitionResolved(petitionId, pi.b, pi.bPerClass);

        _safeTransfer(bountyToken, msg.sender, rec.bounty);
        emit BountyPaid(petitionId, msg.sender, rec.bounty);
    }

    // ---------- Mark Unresolved ----------

    /// Rebate to caller is `min(MARK_UNRESOLVED_GAS_ESTIMATE * tx.gasprice,
    /// bounty * GAS_REBATE_BPS / 10_000)`. The cap is the 1% bound from
    /// SPEC line 123 ("capped at 1%"). The gas-based bound prevents a
    /// griefer from claiming 1% of a large bounty for negligible work
    /// when bountyToken is denominated near 1:1 with ETH (e.g., WETH).
    /// For tokens with different decimals the wei-vs-token-unit
    /// comparison treats wei numerically; the cap still bounds payout.
    function markUnresolved(bytes32 petitionId) external {
        PetitionRecord storage rec = petitions[petitionId];
        _advanceStateOnRead(rec);
        if (rec.state != PetitionState.DisputeWindow) revert InvalidState();
        if (block.number < uint256(rec.closeAtBlock) + RESOLUTION_DEADLINE_BLOCKS) revert TooEarly();

        uint256 rebateCap = (rec.bounty * uint256(GAS_REBATE_BPS)) / 10_000;
        uint256 estimatedGasCost = MARK_UNRESOLVED_GAS_ESTIMATE * tx.gasprice;
        uint256 rebate = estimatedGasCost < rebateCap ? estimatedGasCost : rebateCap;
        uint256 refund = rec.bounty - rebate;
        rec.runningRoot = TOMBSTONE_RUNNING_ROOT;
        rec.state = PetitionState.Unresolved;
        _safeTransfer(bountyToken, rec.organizer, refund);
        if (rebate > 0) _safeTransfer(bountyToken, msg.sender, rebate);
        emit PetitionUnresolved(petitionId);
        emit BountyRefunded(petitionId, rec.organizer, refund);
    }

    // ---------- Dispute ----------

    struct DisputeParams {
        bytes32 petitionId;
        uint32 batchIndex;
        uint32 positionI;
        uint32 positionJ;
        uint8 violationType;
    }

    /// Dispute a published batch using KZG openings against
    /// `batchVersionedHash`. Positions identify which record(s) inside
    /// the batch the dispute targets; the contract derives canonical
    /// evaluation points internally, eliminating the previous attack
    /// surface where a caller could supply arbitrary `z` values.
    /// `openingsBlob` carries y-values only (32 bytes each); `proofsBlob`
    /// carries 48-byte KZG proofs.
    function dispute(
        bytes32 petitionId,
        uint32 batchIndex,
        uint32 positionI,
        uint32 positionJ,
        uint8 violationType,
        bytes calldata kzgCommitment,
        bytes calldata openingsBlob,
        bytes calldata proofsBlob
    ) external {
        DisputeParams memory dp = DisputeParams(petitionId, batchIndex, positionI, positionJ, violationType);
        _preflightDispute(dp, kzgCommitment);
        _verifyOpenings(dp, kzgCommitment, openingsBlob, proofsBlob);
        if (!_applyViolationPredicate(dp, openingsBlob)) revert ViolationFalse();
        _cascadeRepudiation(dp);
    }

    function _preflightDispute(DisputeParams memory dp, bytes calldata kzgCommitment) internal {
        PetitionRecord storage rec = petitions[dp.petitionId];
        _advanceStateOnRead(rec);
        // SPEC line 107: dispute only during DisputeWindow.
        if (rec.state != PetitionState.DisputeWindow) revert InvalidState();
        if (dp.batchIndex >= batches[dp.petitionId].length) revert InvalidBatch();
        BatchRecord storage bat = batches[dp.petitionId][dp.batchIndex];
        if (bat.state != BatchState.Active) revert InvalidBatch();
        if (kzgCommitment.length != 48) revert InvalidBatch();

        // Position bound: must lie in [0, BATCH_SIZE_MAX).
        if (dp.positionI >= BATCH_SIZE_MAX) revert InvalidDispute();
        if (dp.violationType != 0x01) {
            if (dp.positionJ >= BATCH_SIZE_MAX) revert InvalidDispute();
            if (dp.positionI == dp.positionJ) revert InvalidDispute();
        }
        if (dp.violationType == 0x03) {
            // SPEC: ordering violation compares records i and i+1.
            if (dp.positionJ != dp.positionI + 1) revert InvalidDispute();
        }

        bytes32 sha = sha256(kzgCommitment);
        bytes32 reconstructedVh = (sha & ~bytes32(uint256(0xff) << 248)) | bytes32(uint256(0x01) << 248);
        if (reconstructedVh != bat.batchVersionedHash) revert BlobHashMismatch();
    }

    /// y-only openings; z is derived from positions inside the contract.
    /// Layout: `openingsBlob[k*32 .. k*32+32]` for opening index k.
    /// For violation 0x01: 4 openings (one record's 4 field elements).
    /// For violation 0x02, 0x03: 8 openings (two records' 8 field elements).
    function _verifyOpenings(
        DisputeParams memory dp,
        bytes calldata kzgCommitment,
        bytes calldata openingsBlob,
        bytes calldata proofsBlob
    ) internal view {
        uint256 needed = dp.violationType == 0x01 ? 4 : 8;
        if (openingsBlob.length != needed * 32) revert InvalidBatch();
        if (proofsBlob.length != needed * 48) revert InvalidBatch();
        bytes32 vh = batches[dp.petitionId][dp.batchIndex].batchVersionedHash;

        for (uint256 k = 0; k < needed; k++) {
            uint32 pos = k < 4 ? dp.positionI : dp.positionJ;
            uint256 evalIdx = uint256(pos) * 4 + (k % 4);
            _verifyKzgOpening(
                vh,
                _kzgEvalPoint(evalIdx),
                _read32(openingsBlob, k * 32),
                kzgCommitment,
                proofsBlob[k * 48:(k + 1) * 48]
            );
        }
    }

    function _applyViolationPredicate(DisputeParams memory dp, bytes calldata openingsBlob)
        internal
        view
        returns (bool)
    {
        if (dp.violationType == 0x01) {
            return !_classInSet(_decodeRecordClassTag(openingsBlob, 0), petitions[dp.petitionId].classSet);
        } else if (dp.violationType == 0x02) {
            bytes32 idTagI = _reconstructIdentityTag(openingsBlob, 0);
            bytes32 idTagJ = _reconstructIdentityTag(openingsBlob, 4 * 32);
            return idTagI == idTagJ;
        } else if (dp.violationType == 0x03) {
            // SPEC: leaf_k = Poseidon1(DOMAIN_LEAF, nullifier_k, class_tag_k)
            bytes32 nullI = _reconstructNullifier(openingsBlob, 0);
            bytes32 nullJ = _reconstructNullifier(openingsBlob, 4 * 32);
            uint16 ctI = _decodeRecordClassTag(openingsBlob, 0);
            uint16 ctJ = _decodeRecordClassTag(openingsBlob, 4 * 32);
            uint256 leafI = _poseidon3(DOMAIN_LEAF, uint256(nullI), uint256(ctI));
            uint256 leafJ = _poseidon3(DOMAIN_LEAF, uint256(nullJ), uint256(ctJ));
            return leafI >= leafJ;
        }
        revert InvalidBatch();
    }

    function _cascadeRepudiation(DisputeParams memory dp) internal {
        PetitionRecord storage rec = petitions[dp.petitionId];
        uint256 cnt = batches[dp.petitionId].length;
        bytes32 newRunning;
        bytes32 newIdtag;
        uint64 newLeafCount;
        if (dp.batchIndex > 0) {
            BatchRecord storage prev = batches[dp.petitionId][dp.batchIndex - 1];
            newRunning = prev.newRunningRoot;
            newIdtag = prev.newIdentityTagSetRoot;
            newLeafCount = prev.newLeafCount;
        } else {
            // SPEC line 107: rollback to initial empty-IMT state if no
            // active predecessor exists. zero would brick the petition.
            newRunning = emptyImtRoot;
            newIdtag = emptyImtRoot;
            newLeafCount = 0;
        }
        for (uint256 b = dp.batchIndex; b < cnt; b++) {
            if (batches[dp.petitionId][b].state == BatchState.Active) {
                batches[dp.petitionId][b].state = BatchState.Repudiated;
            }
        }
        rec.runningRoot = newRunning;
        rec.identityTagSetRoot = newIdtag;
        rec.leafCount = newLeafCount;
        rec.nextBatchIndex = dp.batchIndex;
        emit BatchRepudiated(dp.petitionId, dp.batchIndex, newRunning, newIdtag, newLeafCount);
    }

    // ---------- Governance ----------

    function updateAlpha(uint64 newAlpha) external onlyGovernance {
        if (newAlpha < alphaMin || newAlpha > alphaMax) revert AlphaOutOfBounds();
        emit AlphaUpdated(alpha, newAlpha);
        alpha = newAlpha;
    }

    // ---------- View ----------

    function getPetition(bytes32 petitionId) external view returns (PetitionRecord memory) {
        return petitions[petitionId];
    }

    function getBatch(bytes32 petitionId, uint32 idx) external view returns (BatchRecord memory) {
        return batches[petitionId][idx];
    }

    function getBatchCount(bytes32 petitionId) external view returns (uint256) {
        return batches[petitionId].length;
    }

    // ---------- Internal ----------

    function _advanceStateOnRead(PetitionRecord storage rec) internal {
        if (rec.state == PetitionState.Unset) revert InvalidPetition();
        // Registered -> SigningOpen atomic with first read after registration.
        if (rec.state == PetitionState.Registered) {
            rec.state = PetitionState.SigningOpen;
        }
        if (rec.state == PetitionState.SigningOpen && block.number >= rec.closeAtBlock) {
            rec.state = PetitionState.SigningClosed;
        }
        // SigningClosed -> Cooldown atomic with SigningClosed entry.
        if (rec.state == PetitionState.SigningClosed) {
            rec.state = PetitionState.Cooldown;
        }
        if (rec.state == PetitionState.Cooldown && block.number >= rec.closeAtBlock + COOLDOWN_BLOCKS) {
            rec.state = PetitionState.DisputeWindow;
        }
    }

    function _classInSet(uint16 c, uint16[] storage set) internal view returns (bool) {
        uint256 lo = 0;
        uint256 hi = set.length;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            uint16 v = set[mid];
            if (v == c) return true;
            if (v < c) lo = mid + 1;
            else hi = mid;
        }
        return false;
    }

    function _batchPublicInputs(BatchPublicInputs calldata pi) internal pure returns (bytes32[] memory out) {
        // 13 named PIs + 24 blsFields + 1 signerVkHash = 38 total. PI ordering
        // matches SPEC sec Batch SNARK "Public inputs (ordered)" exactly.
        out = new bytes32[](13 + 24 + 1);
        out[0] = pi.petitionId;
        out[1] = pi.rRoot;
        out[2] = pi.predicateHash;
        out[3] = bytes32(uint256(pi.classIndex));
        out[4] = bytes32(uint256(pi.slot));
        out[5] = bytes32(uint256(pi.batchSize));
        out[6] = pi.priorRunningRoot;
        out[7] = pi.newRunningRoot;
        out[8] = pi.priorIdentityTagSetRoot;
        out[9] = pi.newIdentityTagSetRoot;
        out[10] = bytes32(uint256(pi.priorLeafCount));
        out[11] = bytes32(uint256(pi.newLeafCount));
        out[12] = pi.batchVersionedHash;
        for (uint256 k = 0; k < 24; k++) {
            out[13 + k] = pi.blsFields[k];
        }
        out[37] = pi.signerVkHash;
    }

    // Resolution circuit (circuits/resolution/src/main.nr) public input
    // layout, declaration-order:
    //   predicate_hash, r_root, running_root, leaf_count,
    //   class_set[CLASS_MAX], class_set_len,
    //   class_thresholds[CLASS_MAX], b, b_per_class[CLASS_MAX].
    // Total: 4 + 16 + 1 + 16 + 1 + 16 = 54. Unused slots in the
    // fixed-size arrays are padded with 0.
    uint256 internal constant RESOLUTION_CLASS_MAX = 16;

    function _resolutionPublicInputs(PetitionRecord storage rec, ResolutionPublicInputs calldata pi)
        internal
        view
        returns (bytes32[] memory out)
    {
        uint256 csLen = rec.classSet.length;
        if (pi.bPerClass.length != csLen) revert PriorStateMismatch();
        // 4 named + 16 class_set + 1 class_set_len + 16 thresholds + 1 b + 16 bPerClass + 1 classIndex = 55
        out = new bytes32[](4 + RESOLUTION_CLASS_MAX + 1 + RESOLUTION_CLASS_MAX + 1 + RESOLUTION_CLASS_MAX + 1);
        uint256 j = 0;
        out[j++] = rec.predicateHash;
        out[j++] = rec.rRoot;
        out[j++] = rec.runningRoot;
        out[j++] = bytes32(uint256(rec.leafCount));
        for (uint256 i = 0; i < RESOLUTION_CLASS_MAX; i++) {
            out[j++] = i < csLen ? bytes32(uint256(rec.classSet[i])) : bytes32(0);
        }
        out[j++] = bytes32(csLen);
        for (uint256 i = 0; i < RESOLUTION_CLASS_MAX; i++) {
            out[j++] = i < csLen ? bytes32(uint256(rec.classThresholds[i])) : bytes32(0);
        }
        out[j++] = bytes32(uint256(pi.b ? 1 : 0));
        for (uint256 i = 0; i < RESOLUTION_CLASS_MAX; i++) {
            out[j++] = i < csLen ? bytes32(uint256(pi.bPerClass[i] ? 1 : 0)) : bytes32(0);
        }
        out[j++] = bytes32(uint256(rec.classIndex));
    }

    function _verifyKzgOpening(
        bytes32 versionedHash,
        bytes32 z,
        bytes32 y,
        bytes calldata commitment,
        bytes calldata proof_
    ) internal view {
        bytes memory input = bytes.concat(versionedHash, z, y, commitment, proof_);
        (bool ok, bytes memory ret) = address(0x0a).staticcall(input);
        if (!ok || ret.length == 0) revert ProofRejected();
    }

    function _read32(bytes calldata data, uint256 off) internal pure returns (bytes32 v) {
        assembly {
            v := calldataload(add(data.offset, off))
        }
    }

    /// Decode `class_tag` (uint16 BE) from the y-value at `base + 2*32`
    /// (FE2 of a record at the given base offset). `base = 0` is the
    /// first record; `base = 4*32` is the second record.
    function _decodeRecordClassTag(bytes calldata openingsBlob, uint256 base) internal pure returns (uint16 classTag) {
        bytes32 fe2y = _read32(openingsBlob, base + 2 * 32);
        uint256 contentRaw = uint256(fe2y) & ((uint256(1) << 248) - 1);
        // class_tag occupies content bytes [2..4] of FE2.
        uint256 hi4 = contentRaw >> (27 * 8);
        classTag = uint16(hi4 & 0xffff);
    }

    function _reconstructNullifier(bytes calldata openingsBlob, uint256 base) internal pure returns (bytes32) {
        bytes32 fe0y = _read32(openingsBlob, base);
        bytes32 fe1y = _read32(openingsBlob, base + 32);
        uint256 fe0 = uint256(fe0y) & ((uint256(1) << 248) - 1);
        uint256 fe1 = uint256(fe1y) & ((uint256(1) << 248) - 1);
        uint256 fe1Byte0 = (fe1 >> (30 * 8)) & 0xff;
        uint256 nul = (fe0 << 8) | fe1Byte0;
        return bytes32(nul);
    }

    function _reconstructIdentityTag(bytes calldata openingsBlob, uint256 base) internal pure returns (bytes32) {
        bytes32 fe1y = _read32(openingsBlob, base + 32);
        bytes32 fe2y = _read32(openingsBlob, base + 2 * 32);
        uint256 fe1 = uint256(fe1y) & ((uint256(1) << 248) - 1);
        uint256 fe2 = uint256(fe2y) & ((uint256(1) << 248) - 1);
        uint256 fe1Body = fe1 & ((uint256(1) << (30 * 8)) - 1);
        uint256 fe2Hi = (fe2 >> (29 * 8)) & 0xffff;
        uint256 idt = (fe1Body << 16) | fe2Hi;
        return bytes32(idt);
    }

    function _safeTransfer(address token, address to, uint256 amount) internal {
        (bool ok, bytes memory ret) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert PaymentFailed();
    }

    function _safeTransferFrom(address token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory ret) =
            token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount));
        if (!ok || (ret.length != 0 && !abi.decode(ret, (bool)))) revert PaymentFailed();
    }
}

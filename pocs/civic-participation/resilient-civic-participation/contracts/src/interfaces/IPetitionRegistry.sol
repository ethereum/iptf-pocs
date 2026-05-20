// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title IPetitionRegistry
/// @notice Public entry points of the on-chain petition registry.
interface IPetitionRegistry {
    enum PetitionState {
        Unset,
        Registered,
        SigningOpen,
        SigningClosed,
        Cooldown,
        DisputeWindow,
        Resolved,
        Unresolved
    }

    enum BatchState {
        Unset,
        Active,
        Repudiated
    }

    struct PetitionParams {
        bytes32 rRoot;
        bytes predicateDef;
        bytes32 salt;
        uint16[] classSet;
        uint64[] classThresholds;
        uint8 classIndex;
        uint64 closeAtBlock;
        uint256 bounty;
    }

    struct BatchPublicInputs {
        bytes32 petitionId;
        bytes32 rRoot;
        bytes32 predicateHash;
        uint8 classIndex;
        uint32 slot;
        uint32 batchSize;
        bytes32 priorRunningRoot;
        bytes32 newRunningRoot;
        bytes32 priorIdentityTagSetRoot;
        bytes32 newIdentityTagSetRoot;
        uint64 priorLeafCount;
        uint64 newLeafCount;
        // Bound to `blobhash(0)` of the publishing transaction.
        bytes32 batchVersionedHash;
        // Per-position BLS12-381 field-element decompositions of the
        // batch records (SPEC constraint 8). Length is
        // `BATCH_SIZE_MAX * FE_PER_RECORD = 24`; the contract verifies
        // each value via a KZG point-evaluation at `omega^k` against
        // `batchVersionedHash`.
        bytes32[24] blsFields;
        // Signer VK hash pinned by the deploy-time constant
        // `pinnedSignerVkHash`. Without this, a malicious relayer could
        // supply their own signer VK and prove anything.
        bytes32 signerVkHash;
    }

    // Resolver supplies only the outcome bits; the contract reads every
    // other public input (predicateHash, rRoot, runningRoot, leafCount,
    // classSet, classThresholds, classIndex) from PetitionRecord at
    // resolve-time. This removes the substitution attack surface for
    // classSet / classThresholds (CRIT-1 in AUDIT.md).
    struct ResolutionPublicInputs {
        bool b;
        bool[] bPerClass;
    }

    event PetitionRegistered(
        bytes32 indexed petitionId,
        uint32 slot,
        bytes32 rRoot,
        bytes32 predicateHash,
        uint16[] classSet,
        uint64[] classThresholds,
        uint8 classIndex,
        uint64 closeAtBlock,
        uint256 bounty
    );

    event BatchPublished(
        bytes32 indexed petitionId,
        uint32 indexed batchIndex,
        bytes32 batchVersionedHash,
        bytes32 newRunningRoot,
        bytes32 newIdentityTagSetRoot,
        uint64 newLeafCount
    );

    event BatchRepudiated(
        bytes32 indexed petitionId,
        uint32 indexed batchIndex,
        bytes32 newRunningRoot,
        bytes32 newIdentityTagSetRoot,
        uint64 newLeafCount
    );

    event PetitionResolved(bytes32 indexed petitionId, bool b, bool[] bPerClass);
    event PetitionUnresolved(bytes32 indexed petitionId);
    event BountyPaid(bytes32 indexed petitionId, address recipient, uint256 amount);
    event BountyRefunded(bytes32 indexed petitionId, address recipient, uint256 amount);
    event AlphaUpdated(uint64 oldAlpha, uint64 newAlpha);
}

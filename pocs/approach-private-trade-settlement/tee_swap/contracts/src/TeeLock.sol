// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title TeeLock
/// @notice Swap announcement contract — TEE reveals ephemeral keys here
/// @dev Deployed on one chain only. The TEE calls announceSwap to atomically reveal both parties' ephemeral keys.
contract TeeLock {
    struct SwapAnnouncement {
        bool revealed;
        bytes32 ephemeralKeyA;
        bytes32 ephemeralKeyB;
        bytes32 encryptedSaltA;
        bytes32 encryptedSaltB;
        uint256 timestamp;
    }

    /// @notice TEE address (PoC: simple EOA, production: EIP-4337 smart account)
    address public tee;

    /// @notice Swap announcements indexed by swapId
    mapping(bytes32 => SwapAnnouncement) public announcements;

    event SwapRevealed(bytes32 indexed swapId);

    error OnlyTEE();
    error SwapAlreadyRevealed();

    modifier onlyTEE() {
        _onlyTEE();
        _;
    }

    function _onlyTEE() internal view {
        if (msg.sender != tee) revert OnlyTEE();
    }

    constructor(address _tee) {
        tee = _tee;
    }

    /// @notice Announce a swap by revealing both parties' ephemeral keys and encrypted salts
    /// @param swapId The unique swap identifier
    /// @param ephemeralKeyA Party A's ephemeral public key (Grumpkin x-coordinate)
    /// @param ephemeralKeyB Party B's ephemeral public key (Grumpkin x-coordinate)
    /// @param encryptedSaltA Party A's encrypted salt
    /// @param encryptedSaltB Party B's encrypted salt
    function announceSwap(
        bytes32 swapId,
        bytes32 ephemeralKeyA,
        bytes32 ephemeralKeyB,
        bytes32 encryptedSaltA,
        bytes32 encryptedSaltB
    ) external onlyTEE {
        if (announcements[swapId].revealed) revert SwapAlreadyRevealed();

        announcements[swapId] = SwapAnnouncement({
            revealed: true,
            ephemeralKeyA: ephemeralKeyA,
            ephemeralKeyB: ephemeralKeyB,
            encryptedSaltA: encryptedSaltA,
            encryptedSaltB: encryptedSaltB,
            timestamp: block.timestamp
        });

        emit SwapRevealed(swapId);
    }
}

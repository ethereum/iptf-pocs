// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IIdentityTree {
    function insertLeaf(uint256 leaf, uint256 enrollmentNullifier) external;
}

interface IVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

contract Enrollment {
    IIdentityTree public identityTree;
    IVerifier public verifier;

    struct ECPoint {
        uint256 x;
        uint256 y;
    }

    ECPoint public mpcPublicKey;
    ECPoint public previousMPCKey;
    uint256 public keyGraceExpiry;

    ECPoint public pendingKey;
    uint256 public pendingKeyActivation;

    address public multisig;
    address public guardian;

    uint256 public constant TIMELOCK_BLOCKS = 14400;
    uint256 public constant GRACE_BLOCKS = 14400;
    uint256 public constant BN254_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    event Enrolled(uint256 indexed leaf, uint256 enrollmentNullifier);
    event MPCKeyProposed(uint256 x, uint256 y, uint256 activationBlock);
    event MPCKeyFinalized(uint256 x, uint256 y);
    event PendingKeyVetoed();

    error NotMultisig();
    error NotGuardian();
    error InvalidProof();
    error NotOnCurve();
    error NoPendingKey();
    error TimelockNotExpired();
    error KeyAlreadyPending();

    modifier onlyMultisig() {
        if (msg.sender != multisig) revert NotMultisig();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert NotGuardian();
        _;
    }

    constructor(
        address _identityTree,
        address _verifier,
        uint256 _mpcPubKeyX,
        uint256 _mpcPubKeyY,
        address _multisig,
        address _guardian
    ) {
        identityTree = IIdentityTree(_identityTree);
        verifier = IVerifier(_verifier);
        mpcPublicKey = ECPoint(_mpcPubKeyX, _mpcPubKeyY);
        multisig = _multisig;
        guardian = _guardian;
    }

    function enroll(
        uint256 leaf,
        uint256 enrollmentNullifier,
        uint256 gIdX,
        uint256 gIdY,
        bytes calldata proof
    ) external {
        bytes32[] memory publicInputs = new bytes32[](6);
        publicInputs[0] = bytes32(leaf);
        publicInputs[1] = bytes32(enrollmentNullifier);
        publicInputs[2] = bytes32(mpcPublicKey.x);
        publicInputs[3] = bytes32(mpcPublicKey.y);
        publicInputs[4] = bytes32(gIdX);
        publicInputs[5] = bytes32(gIdY);

        bool valid = verifier.verify(proof, publicInputs);

        if (!valid && block.number < keyGraceExpiry) {
            // Retry with previous key
            publicInputs[2] = bytes32(previousMPCKey.x);
            publicInputs[3] = bytes32(previousMPCKey.y);
            valid = verifier.verify(proof, publicInputs);
        }

        if (!valid) revert InvalidProof();

        identityTree.insertLeaf(leaf, enrollmentNullifier);
        emit Enrolled(leaf, enrollmentNullifier);
    }

    function proposeMPCPublicKey(uint256 x, uint256 y) external onlyMultisig {
        if (pendingKeyActivation != 0) revert KeyAlreadyPending();
        _requireOnCurve(x, y);

        pendingKey = ECPoint(x, y);
        pendingKeyActivation = block.number + TIMELOCK_BLOCKS;

        emit MPCKeyProposed(x, y, pendingKeyActivation);
    }

    function finalizeMPCPublicKey() external onlyMultisig {
        if (pendingKeyActivation == 0) revert NoPendingKey();
        if (block.number < pendingKeyActivation) revert TimelockNotExpired();

        previousMPCKey = mpcPublicKey;
        mpcPublicKey = pendingKey;
        keyGraceExpiry = block.number + GRACE_BLOCKS;

        delete pendingKey;
        pendingKeyActivation = 0;

        emit MPCKeyFinalized(mpcPublicKey.x, mpcPublicKey.y);
    }

    function vetoPendingKey() external onlyGuardian {
        if (pendingKeyActivation == 0) revert NoPendingKey();

        delete pendingKey;
        pendingKeyActivation = 0;

        emit PendingKeyVetoed();
    }

    function _requireOnCurve(uint256 x, uint256 y) internal pure {
        // BN254 G1 curve: y^2 = x^3 + 3 (mod p)
        uint256 lhs = mulmod(y, y, BN254_P);
        uint256 x2 = mulmod(x, x, BN254_P);
        uint256 x3 = mulmod(x2, x, BN254_P);
        uint256 rhs = addmod(x3, 3, BN254_P);
        if (lhs != rhs) revert NotOnCurve();
    }
}

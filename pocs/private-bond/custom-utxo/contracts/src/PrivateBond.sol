// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

import "@openzeppelin/contracts/access/Ownable.sol";
import "./Verifier.sol";
import "./PoseidonT3.sol";

contract PrivateBond is Ownable {
    HonkVerifier public verifier;
    
    bytes32[] public commitments;

    mapping(bytes32 => bool) public knownRoots;
    mapping(bytes32 => bool) public nullifiers;

    constructor(address _verifier, address initialOwner) Ownable(initialOwner) {
        verifier = HonkVerifier(_verifier);
    }

    // Transfer a bond ownership
    function transfer(
        bytes calldata proof,
        bytes32 root,
        bytes32[2] calldata nullifiersIn,
        bytes32[2] calldata commitmentsOut
    ) external {
        require(knownRoots[root], "Invalid Merkle Root");
        require(!nullifiers[nullifiersIn[0]], "Note 0 already spent");
        require(!nullifiers[nullifiersIn[1]], "Note 1 already spent");
        require(nullifiersIn[0] != nullifiersIn[1], "Identical nullifiers");

        bytes32[] memory publicInputs = new bytes32[](5);
        publicInputs[0] = root;
        publicInputs[1] = nullifiersIn[0];
        publicInputs[2] = nullifiersIn[1];
        publicInputs[3] = commitmentsOut[0];
        publicInputs[4] = commitmentsOut[1];

        require(verifier.verify(proof, publicInputs), "Invalid Transfer Proof");

        nullifiers[nullifiersIn[0]] = true;
        nullifiers[nullifiersIn[1]] = true;

        commitments.push(commitmentsOut[0]);
        commitments.push(commitmentsOut[1]);

        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Minting a new bond
    function mint(bytes32 _commitment) external onlyOwner {
        commitments.push(_commitment);
        
        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Enables minting all the bonds at once
    function mintBatch(bytes32[] memory _commitments) external onlyOwner {
        for (uint32 i = 0; i < _commitments.length; i++) {
            commitments.push(_commitments[i]);
        }
        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Build the merkle root to update contract state
    function buildMerkleRoot() public view returns (bytes32) {
        require(commitments.length > 0, "No commitments provided");
        
        bytes32[] memory currentLevel = commitments;
        
        while (currentLevel.length > 1) {
            bytes32[] memory nextLevel = new bytes32[]((currentLevel.length + 1) / 2);
            
            for (uint32 i = 0; i < currentLevel.length; i += 2) {
                bytes32 left = currentLevel[i];
                bytes32 right = (i + 1 < currentLevel.length) ? currentLevel[i + 1] : left;
                
                nextLevel[i / 2] = poseidonHash(left, right);
            }
            
            currentLevel = nextLevel;
        }
        
        return currentLevel[0];
    }

    function poseidonHash(bytes32 _left, bytes32 _right) internal pure returns (bytes32) {
        uint hash = PoseidonT3.hash([uint256(_left), uint256(_right)]);
        return bytes32(hash);
    }

    // Action of burning notes to redeem cash off-chain from the issuer
    // Uses same JoinSplit proof structure as transfer, but with output values = 0
    function burn(
        bytes calldata proof,
        bytes32 root,
        bytes32[2] calldata nullifiersIn,
        bytes32[2] calldata commitmentsOut,
        bytes32 inputMaturityDate,
        bytes32 isRedeem
    ) external {
        require(knownRoots[root], "Invalid Merkle Root");
        require(!nullifiers[nullifiersIn[0]], "Note 0 already spent");
        require(!nullifiers[nullifiersIn[1]], "Note 1 already spent");
        require(nullifiersIn[0] != nullifiersIn[1], "Identical nullifiers");
        require(block.timestamp >= uint256(inputMaturityDate), "Bond not at maturity yet");
        
        // Circuit returns true (1) when output values sum to 0 (redemption)
        uint256 isRedeemUint = uint256(isRedeem);
        require(isRedeemUint == 1, "Output notes must have 0 value for redemption");

        bytes32[] memory publicInputs = new bytes32[](5);
        publicInputs[0] = root;
        publicInputs[1] = nullifiersIn[0];
        publicInputs[2] = nullifiersIn[1];
        publicInputs[3] = commitmentsOut[0];
        publicInputs[4] = commitmentsOut[1];

        require(verifier.verify(proof, publicInputs), "Invalid Burn Proof");

        nullifiers[nullifiersIn[0]] = true;
        nullifiers[nullifiersIn[1]] = true;

        // For burn, we still add commitments (value=0 notes) to maintain tree structure
        commitments.push(commitmentsOut[0]);
        commitments.push(commitmentsOut[1]);

        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }

    // Don't need to check KYC for now as trusted relayer will be the caller 
    function atomicSwap(
        bytes calldata proofA,
        bytes32[] calldata publicInputsA,

        bytes calldata proofB,
        bytes32[] calldata publicInputsB
    ) external onlyOwner {
        require(block.timestamp < uint256(publicInputsA[3]), "Bond A already matured");
        require(block.timestamp < uint256(publicInputsB[3]), "Bond B already matured");

        require(verifier.verify(proofA, publicInputsA), "Invalid Transfer Proof A");
        require(verifier.verify(proofB, publicInputsB), "Invalid Transfer Proof B");

        // Need to double check 0 position of Root
        require(knownRoots[publicInputsA[0]], "Invalid Merkle Root A");
        require(knownRoots[publicInputsB[0]], "Invalid Merkle Root B");

        bytes32 nullifierA = publicInputsA[1];
        bytes32 nullifierB = publicInputsB[1];
        require(!nullifiers[nullifierA], "Note A already spent");
        require(!nullifiers[nullifierB], "Note B already spent");
        require(nullifierA != nullifierB, "Identical nullifiers");

        nullifiers[nullifierA] = true;
        nullifiers[nullifierB] = true;

        commitments.push(publicInputsA[2]);
        commitments.push(publicInputsB[2]);

        // Update root
        bytes32 newRoot = buildMerkleRoot();
        knownRoots[newRoot] = true;
    }
}
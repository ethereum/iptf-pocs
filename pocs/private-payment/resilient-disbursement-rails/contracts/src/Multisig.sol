// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract Multisig {
    uint256 public constant THRESHOLD = 4;
    uint256 public constant NUM_OWNERS = 7;

    mapping(address => bool) private _owners;
    uint256 public proposalCount;

    struct Proposal {
        address target;
        bytes data;
        uint256 confirmations;
        bool executed;
        mapping(address => bool) confirmed;
    }

    mapping(uint256 => Proposal) public proposals;

    event ProposalCreated(uint256 indexed proposalId, address indexed proposer, address target);
    event ProposalConfirmed(uint256 indexed proposalId, address indexed confirmer);
    event ProposalExecuted(uint256 indexed proposalId);

    error NotOwner();
    error AlreadyConfirmed();
    error AlreadyExecuted();
    error BelowThreshold();
    error ExecutionFailed();
    error InvalidProposal();
    error DuplicateOwner();
    error ZeroAddress();

    modifier onlyOwner() {
        if (!_owners[msg.sender]) revert NotOwner();
        _;
    }

    constructor(address[7] memory owners) {
        for (uint256 i = 0; i < NUM_OWNERS; i++) {
            if (owners[i] == address(0)) revert ZeroAddress();
            if (_owners[owners[i]]) revert DuplicateOwner();
            _owners[owners[i]] = true;
        }
    }

    function propose(address target, bytes calldata data) external onlyOwner returns (uint256) {
        uint256 id = proposalCount++;
        Proposal storage p = proposals[id];
        p.target = target;
        p.data = data;
        emit ProposalCreated(id, msg.sender, target);
        return id;
    }

    function confirm(uint256 proposalId) external onlyOwner {
        if (proposalId >= proposalCount) revert InvalidProposal();
        Proposal storage p = proposals[proposalId];
        if (p.executed) revert AlreadyExecuted();
        if (p.confirmed[msg.sender]) revert AlreadyConfirmed();

        p.confirmed[msg.sender] = true;
        p.confirmations++;
        emit ProposalConfirmed(proposalId, msg.sender);
    }

    function execute(uint256 proposalId) external onlyOwner {
        if (proposalId >= proposalCount) revert InvalidProposal();
        Proposal storage p = proposals[proposalId];
        if (p.executed) revert AlreadyExecuted();
        if (p.confirmations < THRESHOLD) revert BelowThreshold();

        p.executed = true;

        (bool success,) = p.target.call(p.data);
        if (!success) revert ExecutionFailed();

        emit ProposalExecuted(proposalId);
    }

    function isOwner(address addr) public view returns (bool) {
        return _owners[addr];
    }

    function isConfirmed(uint256 proposalId, address addr) public view returns (bool) {
        return proposals[proposalId].confirmed[addr];
    }
}

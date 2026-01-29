// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {FHE, euint64, externalEuint64, ebool} from "@fhevm/solidity/lib/FHE.sol";
import {ZamaEthereumConfig} from "@fhevm/solidity/config/ZamaConfig.sol";

/**
 * @title ConfidentialBond
 * @notice A confidential zero-coupon bond using Zama fhEVM
 * @dev Implements ERC20-like interface with encrypted balances and amounts
 *
 * Privacy model:
 * - Participant addresses are public (whitelist is visible)
 * - Balances and transfer amounts are encrypted (euint64)
 * - Only authorized addresses can decrypt via ACL
 *
 * Trust assumptions:
 * - Threshold network for decryption (2/3 of 13 nodes)
 * - Issuer manages whitelist honestly
 */
contract ConfidentialBond is ZamaEthereumConfig {
    // ============ Public State ============

    /// @notice Bond issuer address with admin privileges
    address public owner;

    /// @notice KYC-approved addresses that can hold/transfer bonds
    mapping(address => bool) public whitelist;

    /// @notice Total bonds issued (public for institutional transparency)
    uint64 public totalSupply;

    /// @notice Unix timestamp when bonds can be redeemed
    uint64 public maturityDate;

    // ============ Encrypted State ============

    /// @dev Encrypted balances - only owner and authorized auditors can decrypt
    mapping(address => euint64) internal _balances;

    /// @dev Encrypted allowances for approve/transferFrom pattern
    mapping(address => mapping(address => euint64)) internal _allowances;

    // ============ Events ============

    /// @notice Emitted on transfer (amount omitted for confidentiality)
    event Transfer(address indexed from, address indexed to);

    /// @notice Emitted on approval (amount omitted for confidentiality)
    event Approval(address indexed owner, address indexed spender);

    /// @notice Emitted on redemption (amount omitted for confidentiality)
    event Redemption(address indexed holder);

    /// @notice Emitted when whitelist status changes
    event WhitelistUpdated(address indexed account, bool status);

    /// @notice Emitted when ownership transfers
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when audit access is granted
    event AuditAccessGranted(address indexed account, address indexed auditor);

    // ============ Errors ============

    error NotOwner();
    error NotWhitelisted(address account);
    error BondNotMature();
    error ZeroAddress();

    // ============ Modifiers ============

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier onlyWhitelisted(address account) {
        if (!whitelist[account]) revert NotWhitelisted(account);
        _;
    }

    modifier afterMaturity() {
        if (block.timestamp < maturityDate) revert BondNotMature();
        _;
    }

    // ============ Constructor ============

    /**
     * @notice Deploy a new confidential bond
     * @param _totalSupply Total bonds to issue (assigned to deployer)
     * @param _maturityDate Unix timestamp for redemption eligibility
     */
    constructor(uint64 _totalSupply, uint64 _maturityDate) {
        owner = msg.sender;
        totalSupply = _totalSupply;
        maturityDate = _maturityDate;

        // Auto-whitelist issuer
        whitelist[msg.sender] = true;
        emit WhitelistUpdated(msg.sender, true);

        // Issuer starts with full encrypted supply
        _balances[msg.sender] = FHE.asEuint64(_totalSupply);
        FHE.allow(_balances[msg.sender], msg.sender);
        FHE.allowThis(_balances[msg.sender]);
    }

    // ============ View Functions ============

    /**
     * @notice Get encrypted balance of an account
     * @dev Caller must have ACL permission to decrypt the returned ciphertext
     * @param account Address to query
     * @return Encrypted balance (euint64)
     */
    function balanceOf(address account) external view returns (euint64) {
        return _balances[account];
    }

    /**
     * @notice Get encrypted allowance
     * @param _owner Token owner
     * @param spender Approved spender
     * @return Encrypted allowance (euint64)
     */
    function allowance(address _owner, address spender) external view returns (euint64) {
        return _allowances[_owner][spender];
    }

    // ============ Admin Functions ============

    /**
     * @notice Add address to whitelist (KYC approved)
     * @param account Address to whitelist
     */
    function addToWhitelist(address account) external onlyOwner {
        if (account == address(0)) revert ZeroAddress();
        whitelist[account] = true;
        emit WhitelistUpdated(account, true);
    }

    /**
     * @notice Remove address from whitelist
     * @param account Address to remove
     */
    function removeFromWhitelist(address account) external onlyOwner {
        whitelist[account] = false;
        emit WhitelistUpdated(account, false);
    }

    /**
     * @notice Transfer ownership to a new address
     * @param newOwner New owner address
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @notice Grant auditor permission to decrypt an account's balance
     * @dev Used for regulatory compliance - grants read access via ACL
     * @param account Account whose balance to expose
     * @param auditor Address that can decrypt the balance
     */
    function grantAuditAccess(address account, address auditor) external onlyOwner {
        FHE.allow(_balances[account], auditor);
        emit AuditAccessGranted(account, auditor);
    }

    /**
     * @notice Grant auditor access to multiple accounts
     * @param accounts Accounts to expose
     * @param auditor Auditor address
     */
    function grantBulkAuditAccess(address[] calldata accounts, address auditor) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            FHE.allow(_balances[accounts[i]], auditor);
            emit AuditAccessGranted(accounts[i], auditor);
        }
    }

    // ============ Transfer Functions ============

    /**
     * @notice Transfer bonds to another whitelisted address
     * @dev Amount is encrypted - uses FHE.select to avoid balance leak on failure
     * @param to Recipient address (must be whitelisted)
     * @param encryptedAmount Encrypted transfer amount
     * @param inputProof ZK proof validating the encrypted input
     * @return success Always returns true (failures are silent for privacy)
     */
    function transfer(
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external onlyWhitelisted(msg.sender) onlyWhitelisted(to) returns (bool) {
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
        _transfer(msg.sender, to, amount);
        return true;
    }

    /**
     * @notice Approve spender to transfer bonds on your behalf
     * @param spender Address to approve
     * @param encryptedAmount Encrypted allowance amount
     * @param inputProof ZK proof validating the encrypted input
     * @return success Always returns true
     */
    function approve(
        address spender,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external returns (bool) {
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
        _approve(msg.sender, spender, amount);
        return true;
    }

    /**
     * @notice Transfer bonds from one address to another (requires allowance)
     * @dev Used for atomic DvP - spender executes transfer on behalf of owner
     * @param from Source address
     * @param to Destination address
     * @param encryptedAmount Encrypted transfer amount
     * @param inputProof ZK proof validating the encrypted input
     * @return success Always returns true (failures are silent for privacy)
     */
    function transferFrom(
        address from,
        address to,
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external onlyWhitelisted(from) onlyWhitelisted(to) returns (bool) {
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, amount);
        return true;
    }

    // ============ Redemption ============

    /**
     * @notice Redeem (burn) bonds after maturity
     * @dev Burns caller's bonds - settlement happens off-chain or via separate stablecoin tx
     * @param encryptedAmount Amount to redeem
     * @param inputProof ZK proof validating the encrypted input
     */
    function redeem(
        externalEuint64 encryptedAmount,
        bytes calldata inputProof
    ) external onlyWhitelisted(msg.sender) afterMaturity {
        euint64 amount = FHE.fromExternal(encryptedAmount, inputProof);

        // Check sufficient balance (encrypted comparison)
        ebool hasEnough = FHE.le(amount, _balances[msg.sender]);

        // Conditional burn: only executes if hasEnough is true
        // If false, redeem amount becomes 0 (preserves privacy - no revert)
        euint64 redeemAmount = FHE.select(hasEnough, amount, FHE.asEuint64(0));

        // Burn tokens
        _balances[msg.sender] = FHE.sub(_balances[msg.sender], redeemAmount);

        // Update ACL for new balance
        FHE.allow(_balances[msg.sender], msg.sender);
        FHE.allowThis(_balances[msg.sender]);

        emit Redemption(msg.sender);
    }

    // ============ Internal Functions ============

    /**
     * @dev Execute encrypted transfer with balance check
     * Uses FHE.select pattern to avoid revealing insufficient balance via revert
     */
    function _transfer(address from, address to, euint64 amount) internal {
        // Check sufficient balance (encrypted comparison)
        ebool hasEnough = FHE.le(amount, _balances[from]);

        // Conditional transfer: if insufficient, amount becomes 0
        // This preserves privacy - observers can't tell if transfer "failed"
        euint64 transferAmount = FHE.select(hasEnough, amount, FHE.asEuint64(0));

        // Update balances (encrypted arithmetic)
        _balances[from] = FHE.sub(_balances[from], transferAmount);
        _balances[to] = FHE.add(_balances[to], transferAmount);

        // Grant decryption rights
        FHE.allow(_balances[from], from);
        FHE.allow(_balances[to], to);
        FHE.allowThis(_balances[from]);
        FHE.allowThis(_balances[to]);

        emit Transfer(from, to);
    }

    /**
     * @dev Set encrypted allowance
     */
    function _approve(address _owner, address spender, euint64 amount) internal {
        _allowances[_owner][spender] = amount;

        // Grant decryption rights to both parties
        FHE.allow(_allowances[_owner][spender], _owner);
        FHE.allow(_allowances[_owner][spender], spender);
        FHE.allowThis(_allowances[_owner][spender]);

        emit Approval(_owner, spender);
    }

    /**
     * @dev Spend allowance with encrypted comparison
     * Uses same FHE.select pattern for privacy
     */
    function _spendAllowance(address _owner, address spender, euint64 amount) internal {
        euint64 currentAllowance = _allowances[_owner][spender];

        // Check sufficient allowance
        ebool hasEnough = FHE.le(amount, currentAllowance);

        // If insufficient allowance, effective spend becomes 0
        euint64 spendAmount = FHE.select(hasEnough, amount, FHE.asEuint64(0));

        // Decrease allowance
        _allowances[_owner][spender] = FHE.sub(currentAllowance, spendAmount);

        // Update ACL
        FHE.allow(_allowances[_owner][spender], _owner);
        FHE.allow(_allowances[_owner][spender], spender);
        FHE.allowThis(_allowances[_owner][spender]);
    }
}

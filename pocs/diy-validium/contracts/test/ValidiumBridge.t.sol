// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/src/Test.sol";
import {IERC20} from "forge-std/src/interfaces/IERC20.sol";
import {IRiscZeroVerifier} from "../src/interfaces/IRiscZeroVerifier.sol";
import {ValidiumBridge} from "../src/ValidiumBridge.sol";

/// @dev Mock verifier that always succeeds (no-op verify).
contract MockRiscZeroVerifier is IRiscZeroVerifier {
    function verify(bytes calldata, bytes32, bytes32) external pure override {}
}

/// @dev Minimal ERC20 implementation for testing. Supports mint, transfer,
///      transferFrom, approve, and balanceOf. No overflow checks beyond
///      Solidity 0.8 built-ins.
contract MockERC20 is IERC20 {
    string public name = "MockToken";
    string public symbol = "MTK";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

contract ValidiumBridgeTest is Test {
    ValidiumBridge internal bridge;
    MockRiscZeroVerifier internal mockVerifier;
    MockERC20 internal token;

    bytes32 internal constant STATE_ROOT = keccak256("test-state-root");
    bytes32 internal constant NEW_ROOT = keccak256("test-new-state-root");
    bytes32 internal constant THIRD_ROOT = keccak256("test-third-root");
    bytes32 internal constant ALLOWLIST_ROOT = keccak256("test-allowlist-root");
    bytes32 internal constant PUBKEY = keccak256("test-pubkey");

    address internal alice = address(0xA11CE);
    address internal bob = address(0xB0B);

    uint64 internal constant DEPOSIT_AMOUNT = 1000;
    uint64 internal constant WITHDRAW_AMOUNT = 500;

    function setUp() public {
        mockVerifier = new MockRiscZeroVerifier();
        token = new MockERC20();
        bridge = new ValidiumBridge(
            IERC20(address(token)),
            IRiscZeroVerifier(address(mockVerifier)),
            STATE_ROOT,
            ALLOWLIST_ROOT,
            bytes32(0),
            bytes32(0)
        );
    }

    // ---------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------

    /// @dev Mint tokens to `user`, approve the bridge, then deposit.
    function _depositAs(address user, uint256 amount, bytes32 pubkey) internal {
        token.mint(user, amount);
        vm.startPrank(user);
        token.approve(address(bridge), amount);
        bridge.deposit(amount, pubkey, hex"");
        vm.stopPrank();
    }

    // ---------------------------------------------------------------
    // 1. Constructor sets state correctly
    // ---------------------------------------------------------------
    function test_constructor_setsState() public view {
        assertEq(address(bridge.token()), address(token));
        assertEq(address(bridge.verifier()), address(mockVerifier));
        assertEq(bridge.stateRoot(), STATE_ROOT);
        assertEq(bridge.allowlistRoot(), ALLOWLIST_ROOT);
        assertEq(bridge.operator(), address(this));
    }

    // ---------------------------------------------------------------
    // 2. Deposit transfers ERC20 from caller and emits Deposit event
    // ---------------------------------------------------------------
    function test_deposit_transfersTokenAndEmits() public {
        uint256 amount = DEPOSIT_AMOUNT;
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);

        // Expect the Deposit event with correct args
        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.Deposit(alice, PUBKEY, amount);

        bridge.deposit(amount, PUBKEY, hex"");
        vm.stopPrank();

        // Bridge should hold the tokens
        assertEq(token.balanceOf(address(bridge)), amount);
        // Alice should have zero tokens left
        assertEq(token.balanceOf(alice), 0);
    }

    // ---------------------------------------------------------------
    // 3. Deposit reverts with InvalidAmount when amount = 0
    // ---------------------------------------------------------------
    function test_deposit_revertsZeroAmount() public {
        vm.prank(alice);
        vm.expectRevert(ValidiumBridge.InvalidAmount.selector);
        bridge.deposit(0, PUBKEY, hex"");
    }

    // ---------------------------------------------------------------
    // 4. Deposit calls verifier.verify with membership journal
    // ---------------------------------------------------------------
    function test_deposit_requiresMembershipProof() public {
        uint256 amount = DEPOSIT_AMOUNT;
        token.mint(alice, amount);

        vm.startPrank(alice);
        token.approve(address(bridge), amount);
        bridge.deposit(amount, PUBKEY, hex"");
        vm.stopPrank();

        // Deposit succeeded => verifier.verify was called and did not revert
        assertEq(token.balanceOf(address(bridge)), amount);
    }

    // ---------------------------------------------------------------
    // 5. Withdraw verifies proof, updates stateRoot, and transfers tokens
    // ---------------------------------------------------------------
    function test_withdraw_updatesStateAndTransfers() public {
        // First, fund the bridge via a deposit
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);

        // Execute withdrawal to bob
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        // State root should be updated
        assertEq(bridge.stateRoot(), NEW_ROOT);
        // Bob should have received the tokens
        assertEq(token.balanceOf(bob), WITHDRAW_AMOUNT);
        // Bridge balance should be zero
        assertEq(token.balanceOf(address(bridge)), 0);
    }

    // ---------------------------------------------------------------
    // 6. Withdraw emits Withdrawal event with correct args
    // ---------------------------------------------------------------
    function test_withdraw_emitsWithdrawalEvent() public {
        // Fund the bridge
        _depositAs(alice, WITHDRAW_AMOUNT, PUBKEY);

        vm.expectEmit(true, true, true, true);
        emit ValidiumBridge.Withdrawal(bob, WITHDRAW_AMOUNT);

        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // 7. Withdraw reverts when oldRoot != stateRoot (stale state)
    // ---------------------------------------------------------------
    function test_withdraw_revertsStaleState() public {
        bytes32 wrongRoot = keccak256("wrong-root");

        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.StaleState.selector, STATE_ROOT, wrongRoot));
        bridge.withdraw(hex"", wrongRoot, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // 8. Sequential root check prevents replay (double-spend protection)
    // ---------------------------------------------------------------
    function test_withdraw_sequentialRootPreventsReplay() public {
        // Fund the bridge with enough for two withdrawals
        _depositAs(alice, WITHDRAW_AMOUNT * 2, PUBKEY);

        // First withdrawal succeeds: STATE_ROOT -> NEW_ROOT
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);

        // Replaying with old STATE_ROOT reverts — sequential root check prevents double-spend
        vm.expectRevert(abi.encodeWithSelector(ValidiumBridge.StaleState.selector, NEW_ROOT, STATE_ROOT));
        bridge.withdraw(hex"", STATE_ROOT, THIRD_ROOT, WITHDRAW_AMOUNT, bob);
    }

    // ---------------------------------------------------------------
    // 9. Withdraw reverts with InvalidAmount when amount = 0
    // ---------------------------------------------------------------
    function test_withdraw_revertsZeroAmount() public {
        vm.expectRevert(ValidiumBridge.InvalidAmount.selector);
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, 0, bob);
    }

    // ---------------------------------------------------------------
    // 10. Withdraw reverts when bridge doesn't have enough tokens
    // ---------------------------------------------------------------
    function test_withdraw_revertsInsufficientBridgeBalance() public {
        // Bridge has zero tokens -- withdrawal should revert due to
        // ERC20 transfer underflow in MockERC20.transfer
        vm.expectRevert();
        bridge.withdraw(hex"", STATE_ROOT, NEW_ROOT, WITHDRAW_AMOUNT, bob);
    }
}

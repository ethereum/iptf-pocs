// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/src/Script.sol";
import {ShieldedPoolExt} from "../src/ShieldedPoolExt.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";
import {HonkVerifier as DepositVerifier} from "../src/verifiers/DepositVerifier.sol";
import {HonkVerifier as TransferVerifier} from "../src/verifiers/TransferVerifier.sol";
import {HonkVerifier as WithdrawVerifier} from "../src/verifiers/WithdrawVerifier.sol";
import {HonkVerifier as InsertionVerifier} from "../src/verifiers/InsertionVerifier.sol";

/// @notice E2e deployment: real bb verifiers + mock token + `ShieldedPoolExt`.
/// @dev `CHAIN_VK_HASH` (the chain-update circuit's VK hash) and `EMPTY_IMT_ROOT`
///      (the empty indexed-Merkle-tree root) are computed off-chain by the
///      integration test (via `bb` and the Rust IMT) and passed as env vars.
///      Forge auto-deploys + links the contract libraries (ZKTranscriptLib in the
///      verifiers; PoseidonT3 + LeanIMT in the pool). Writes `deployments.toml`
///      for the test to read.
contract Deploy is Script {
    function run() external {
        bytes32 chainVkHash = vm.envBytes32("CHAIN_VK_HASH");
        bytes32 emptyImtRoot = vm.envBytes32("EMPTY_IMT_ROOT");

        vm.startBroadcast();
        address depositV = address(new DepositVerifier());
        address transferV = address(new TransferVerifier());
        address withdrawV = address(new WithdrawVerifier());
        address insertionV = address(new InsertionVerifier());
        MockERC20 token = new MockERC20("USD Coin", "USDC", 6);
        // withdrawInsertionVerifier (k=1) has no circuit yet; reuse the k=2
        // insertion verifier as a placeholder (the e2e is transfer-scoped).
        ShieldedPoolExt pool =
            new ShieldedPoolExt(depositV, transferV, insertionV, withdrawV, insertionV, chainVkHash, emptyImtRoot);
        vm.stopBroadcast();

        string memory out = string.concat(
            "shielded_pool = \"", vm.toString(address(pool)), "\"\n", "mock_token = \"", vm.toString(address(token)), "\"\n"
        );
        vm.writeFile("deployments.toml", out);
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {RoundFactory, RoundHeader} from "../src/RoundFactory.sol";

contract HHeaderParityTest is Test {
    string constant FIXTURE_PATH = "contracts/test/fixtures/h_header_parity.toml";

    RoundFactory factory;

    function setUp() public {
        factory = new RoundFactory(address(1), address(2), address(3), address(4), address(5));
    }

    function test_h_header_matches_fixture() public view {
        string memory toml = vm.readFile(FIXTURE_PATH);

        RoundHeader memory header = RoundHeader({
            roundId: uint256(vm.parseTomlBytes32(toml, "$.header.round_id")),
            cohortVersion: uint64(vm.parseTomlUint(toml, "$.header.cohort_version")),
            cohortRoot: uint256(vm.parseTomlBytes32(toml, "$.header.cohort_root")),
            perRecipientAmount: uint256(vm.parseTomlBytes32(toml, "$.header.per_recipient_amount")),
            cohortSize: vm.parseTomlUint(toml, "$.header.cohort_size"),
            token: vm.parseTomlAddress(toml, "$.header.token"),
            closeTime: uint64(vm.parseTomlUint(toml, "$.header.close_time")),
            claimContractAddress: vm.parseTomlAddress(toml, "$.header.claim_contract_address"),
            chainId: uint256(vm.parseTomlBytes32(toml, "$.header.chain_id"))
        });

        bytes32 expected = vm.parseTomlBytes32(toml, "$.expected_h_header");
        bytes32 actual = factory._computeHHeader(header);

        assertEq(actual, expected, "h_header mismatch with fixture");
    }
}

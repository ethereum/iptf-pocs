use std::{
    fs,
    path::PathBuf,
};

use resilient_disbursement_rails::{
    funder::Funder,
    types::{
        Bytes32,
        RoundHeader,
        U256Be,
    },
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    header: HeaderToml,
    expected_h_header: String,
}

#[derive(Deserialize)]
struct HeaderToml {
    round_id: String,
    cohort_version: u64,
    cohort_root: String,
    per_recipient_amount: String,
    cohort_size: u64,
    token: String,
    close_time: u64,
    claim_contract_address: String,
    chain_id: String,
}

fn parse_hex(s: &str) -> Vec<u8> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).expect("valid hex")
}

fn parse_bytes32(s: &str) -> Bytes32 {
    let bytes = parse_hex(s);
    assert_eq!(bytes.len(), 32, "expected 32 bytes, got {}", bytes.len());
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn parse_address(s: &str) -> [u8; 20] {
    let bytes = parse_hex(s);
    assert_eq!(bytes.len(), 20, "expected 20 bytes, got {}", bytes.len());
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

fn fixture_path() -> PathBuf {
    let manifest = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest).join("contracts/test/fixtures/h_header_parity.toml")
}

#[test]
fn h_header_parity() {
    let raw = fs::read_to_string(fixture_path()).expect("read fixture");
    let fix: Fixture = toml::from_str(&raw).expect("parse toml");

    let header = RoundHeader {
        round_id: parse_bytes32(&fix.header.round_id),
        cohort_version: fix.header.cohort_version,
        cohort_root: parse_bytes32(&fix.header.cohort_root),
        per_recipient_amount: U256Be(parse_bytes32(&fix.header.per_recipient_amount)),
        cohort_size: fix.header.cohort_size,
        token: parse_address(&fix.header.token),
        close_time: fix.header.close_time,
        claim_contract_address: parse_address(&fix.header.claim_contract_address),
        chain_id: U256Be(parse_bytes32(&fix.header.chain_id)),
    };

    let actual = Funder::h_header(&header);
    let expected = parse_bytes32(&fix.expected_h_header);

    assert_eq!(
        actual,
        expected,
        "h_header mismatch.\n  actual:   0x{}\n  expected: 0x{}",
        hex::encode(actual),
        hex::encode(expected),
    );
}

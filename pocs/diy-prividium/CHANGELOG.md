# Changelog

All notable changes to the DIY Prividium PoC will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Initial project structure and documentation
- PLAN.md with phased implementation roadmap (Phases 1-4)
- REQUIREMENTS.md with formal functional, privacy, and security requirements
- SPEC.md with detailed protocol specification
- README.md with project overview and build instructions

### Technical Decisions
- Selected SHA-256 as hash function (RISC Zero hardware acceleration)
- Validium architecture: SQLite off-chain, proofs on-chain
- Account commitment scheme: `SHA256(pubkey || balance || salt)`
- Nullifier scheme: `SHA256(secret_key || "nullifier_domain")`

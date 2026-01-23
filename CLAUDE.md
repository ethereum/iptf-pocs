# CLAUDE.md

Project context and guidelines for working in this repository.

## Project Overview

This repository contains proofs of concept for IPTF privacy primitives. The mission is to accelerate institutional Ethereum adoption by demonstrating how financial institutions can use Ethereum privately.

## Target Audience

Specs and documentation should be accessible to:

- **Executives / C-levels**: Need high-level understanding of what privacy guarantees are achieved and business implications
- **Financial institution engineers**: Need technical depth to evaluate and implement
- **Legal / Ops / Business**: Need to understand compliance implications, trust assumptions, and operational requirements

Write specs with layered depth: executive summary up front, technical details below. Avoid unexplained jargon—define terms or link to terminology section.

## Philosophy

The goal is **not** production-ready or fully-secure implementations. The primary deliverable is a detailed `SPEC.md` that thoroughly documents the protocol. Implementation shortcuts are acceptable as long as they are explicitly documented in the spec or README.

Prioritize:
1. Clear, complete specifications
2. Working demonstrations of the core concept
3. Documented limitations and shortcuts

## Security Disclaimer

**These implementations are proofs of concept for research and evaluation purposes only.**

- Do NOT use in production without thorough security audits
- Implementations may contain bugs, incomplete features, or cryptographic weaknesses
- No guarantees of correctness, security, or fitness for any purpose

## PoC Structure

Each PoC lives in `/pocs/[project-name]`. See `/pocs/_template/` for the standard structure.

Required files:

- `SPEC.md` - Detailed protocol specification (the main deliverable)
- `README.md` with:
  - What privacy primitive this demonstrates
  - Cryptographic assumptions and threat model
  - Build and run instructions
  - Known limitations and shortcuts taken
- `CHANGELOG.md` for tracking changes
- CI workflow in `.github/workflows/[project-name].yml`

## PoC Requirements

Every PoC must document:

- The corresponding [iptf-map use case](https://github.com/ethereum/iptf-map/use-cases) it solves
- Map to the corresponding [approach](https://github.com/ethereum/iptf-map/approaches)

## PoC Independence

Each PoC should be self-contained:

- Own build system and dependencies
- Own CI pipeline (path-filtered)
- No cross-PoC imports or shared code (unless explicitly extracted to a shared library)
- Language/tooling choices independent of other PoCs

This ensures:

- Easy extraction if a PoC graduates to its own repo
- No cascading breakage across unrelated projects
- Clear ownership and maintenance boundaries

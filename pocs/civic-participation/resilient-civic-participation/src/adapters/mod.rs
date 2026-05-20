pub mod bb_prover;
pub mod blob_4844;
pub mod chain_registry;
pub mod in_memory_blob;
pub mod in_memory_ri;

// Test-only adapters. NOT for production deployment.
//
// `MockProofBackend` accepts any proof bytes whose prefix matches the
// SHA-256 of the public inputs; production binaries MUST NOT ship it.
// `direct_relay_submission` is an in-process channel that bypasses the
// anonymous-transport boundary the SPEC threat model assumes; useful
// for tests, fatal for production.
//
// Both modules are gated behind `cfg(test)` AND a `test-mocks` Cargo
// feature so they are reachable from integration tests (which build the
// lib as an external crate without `cfg(test)`) without being included
// in default release builds.
#[cfg(any(test, feature = "test-mocks"))]
pub mod direct_relay_submission;
#[cfg(any(test, feature = "test-mocks"))]
pub mod mock_proof;

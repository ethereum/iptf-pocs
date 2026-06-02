//! SimplePIR primitive: an oblivious fetch of a single `u64` record (each record
//! `< 2^MOD_POWER`). The commitment-path read (Slice 2) is built on this — the
//! server's only input to `answer` is the encrypted query, so it never learns the
//! index. Server (`answer`) and client (`query`/`recover`) run in one process for
//! the PoC; that does not weaken the index-privacy property (the server's input is
//! identical either way).
//!
//! Shortcut vs SPEC: SimplePIR is NOT silent-preprocessing (the SPEC's InsPIRe).
//! The client keeps `client_hint` from the offline `setup`, and the offline phase
//! is per-database. InsPIRe (server-side silent preprocessing, no client hint) has
//! no portable Rust library (Google's impl is an Ubuntu/AVX-512 benchmark CLI), so
//! it stays the documented production target. See README "Implementation shortcuts".

use simplepir::{
    answer,
    query,
    recover,
    setup,
    CompressedDatabase,
    Database,
    Matrix,
};

/// LWE secret-key dimension (SimplePIR's recommended value for security).
pub const SECRET_DIMENSION: usize = 2048;
/// Plaintext-modulus exponent: each record MUST be `< 2^MOD_POWER`.
pub const MOD_POWER: u8 = 17;

/// Plaintext modulus `2^MOD_POWER` (one past the largest representable record).
pub fn plaintext_mod() -> u64 {
    1u64 << MOD_POWER
}

/// An in-process SimplePIR database over `u64` records. Bundles the server side
/// (compressed data + `server_hint` seed) and the client side (`client_hint`); a
/// real deployment splits these across the wire, but index-privacy is identical —
/// the server only ever sees the encrypted `query_cipher`.
pub struct PirDatabase {
    db: Database,
    compressed: CompressedDatabase,
    /// Seed for the public A-matrix (server-side, public).
    server_hint: u64,
    client_hint: Matrix,
    side_len: usize,
}

impl PirDatabase {
    /// Build from row-major `records` (each MUST be `< 2^MOD_POWER`), padded to a
    /// square matrix, running the (expensive, offline) `setup`.
    pub fn from_records(records: Vec<u64>) -> Self {
        let db = Database::from_vector(records, MOD_POWER);
        let side_len = db.side_len();
        let (server_hint, client_hint) = setup(&db, SECRET_DIMENSION);
        let compressed = db.compress().expect("compress database");
        Self { db, compressed, server_hint, client_hint, side_len }
    }

    /// The square-matrix side length (capacity is `side_len^2`).
    pub fn side_len(&self) -> usize {
        self.side_len
    }

    /// The plaintext record stored at `index` (server-side view; used to verify
    /// an oblivious `fetch` returned the right value).
    pub fn get(&self, index: usize) -> Option<u64> {
        self.db.get(index)
    }

    /// Obliviously fetch the record at `index` via the full PIR roundtrip: client
    /// `query` -> server `answer` -> client `recover`. The server's only input is
    /// the encrypted query, so it learns nothing about `index`.
    pub fn fetch(&self, index: usize) -> u64 {
        let (client_state, query_cipher) =
            query(index, self.side_len, SECRET_DIMENSION, self.server_hint, plaintext_mod());
        let answer_cipher = answer(&self.compressed, &query_cipher);
        recover(&client_state, &self.client_hint, &answer_cipher, &query_cipher, plaintext_mod())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The oblivious `fetch` recovers the stored record at every index — i.e. the
    /// SimplePIR query -> answer -> recover roundtrip is correct for our params.
    #[test]
    fn fetch_recovers_each_stored_record() {
        let records: Vec<u64> = (0..16).map(|i| 1000 + i as u64).collect();
        let pir = PirDatabase::from_records(records);
        for index in 0..16 {
            let expected = pir.get(index).expect("record present");
            assert_eq!(pir.fetch(index), expected, "PIR fetch must recover the stored record at {index}");
        }
    }

    /// The server's only input is `query_cipher`; it must not reveal the index.
    /// (a) The cipher size is identical for any index (no length side-channel).
    /// (b) Two queries for the SAME index differ (probabilistic encryption — the
    /// server cannot even tell two reads hit the same leaf). The residual
    /// guarantee — that the ciphertexts are computationally indistinguishable —
    /// rests on LWE semantic security and is not asserted here.
    #[test]
    fn query_does_not_leak_the_index() {
        let pir = PirDatabase::from_records((0..16).map(|i| i as u64).collect());
        let mk = |index| query(index, pir.side_len, SECRET_DIMENSION, pir.server_hint, plaintext_mod()).1;

        assert_eq!(mk(0).len(), mk(7).len(), "query size must not depend on the index");
        assert_ne!(mk(3), mk(3), "repeated queries for one index must differ (semantic security)");
    }
}

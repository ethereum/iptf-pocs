//! NIST KAT (.rsp) parser for MAYO-2.
//!
//! Each KAT entry is a stanza of `key = HEXVALUE` lines separated by
//! blank lines. Header lines starting with `#` are comments and are
//! ignored. The fields we care about are:
//!
//! * `count`: entry index
//! * `seed`: DRBG seed (NIST KAT framework)
//! * `mlen`: message length in bytes
//! * `msg`:  message bytes
//! * `pk`:   compact public key (4912 bytes for MAYO-2)
//! * `sk`:   compact secret key
//! * `smlen`: signed-message length in bytes (= sig_bytes + mlen)
//! * `sm`:   signed message (signature followed by message)

use std::fs;
use std::path::Path;

use super::oracle::SIG_BYTES;

/// One parsed KAT stanza.
#[derive(Clone, Debug)]
pub struct KatEntry {
    pub count: usize,
    pub seed: Vec<u8>,
    pub msg: Vec<u8>,
    pub pk: Vec<u8>,
    pub sk: Vec<u8>,
    /// Signed message: `signature ‖ message`.
    pub sm: Vec<u8>,
}

impl KatEntry {
    /// First `SIG_BYTES` (= 186 for MAYO-2) bytes of `sm` form the signature.
    pub fn signature(&self) -> &[u8] {
        &self.sm[..SIG_BYTES]
    }

    /// Remaining bytes of `sm` form the message.
    pub fn message(&self) -> &[u8] {
        &self.sm[SIG_BYTES..]
    }
}

/// Parse the KAT response file at `path`.
///
/// Returns one [`KatEntry`] per stanza. Stanzas missing required fields
/// are silently skipped (so partial files still parse cleanly).
pub fn load_rsp<P: AsRef<Path>>(path: P) -> Vec<KatEntry> {
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read KAT file {}: {}", path.as_ref().display(), e));

    let mut entries = Vec::new();
    let mut current: Vec<(String, String)> = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() {
            if !current.is_empty() {
                if let Some(entry) = build_entry(&current) {
                    entries.push(entry);
                }
                current.clear();
            }
            continue;
        }

        if trimmed.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = trimmed.split_once('=') {
            current.push((key.trim().to_string(), value.trim().to_string()));
        }
    }

    // Final stanza without trailing blank line.
    if !current.is_empty() {
        if let Some(entry) = build_entry(&current) {
            entries.push(entry);
        }
    }

    entries
}

fn build_entry(fields: &[(String, String)]) -> Option<KatEntry> {
    let mut count: Option<usize> = None;
    let mut seed: Option<Vec<u8>> = None;
    let mut msg: Option<Vec<u8>> = None;
    let mut pk: Option<Vec<u8>> = None;
    let mut sk: Option<Vec<u8>> = None;
    let mut sm: Option<Vec<u8>> = None;

    for (k, v) in fields {
        match k.as_str() {
            "count" => count = v.parse::<usize>().ok(),
            "seed" => seed = hex::decode(v).ok(),
            "msg" => msg = hex::decode(v).ok(),
            "pk" => pk = hex::decode(v).ok(),
            "sk" => sk = hex::decode(v).ok(),
            "sm" => sm = hex::decode(v).ok(),
            // mlen / smlen are redundant; derived from msg / sm length.
            _ => {}
        }
    }

    Some(KatEntry {
        count: count?,
        seed: seed?,
        msg: msg?,
        pk: pk?,
        sk: sk?,
        sm: sm?,
    })
}

//! Shared conversion helpers between flat byte arrays and `Word`-valued wires.

use binius_core::word::Word;
use binius_frontend::{Wire, WitnessFiller};

/// Pack `bytes` little-endian into `wires`, one `Word` per 8 input bytes.
///
/// `wires.len() * 8` must equal `bytes.len()`; this is the canonical layout used
/// throughout the MAYO-2 verifier (digests, salt, public commitments).
pub(crate) fn write_le_words(w: &mut WitnessFiller, wires: &[Wire], bytes: &[u8]) {
    assert_eq!(
        wires.len() * 8,
        bytes.len(),
        "write_le_words: wires/bytes length mismatch ({} wires × 8 ≠ {} bytes)",
        wires.len(),
        bytes.len()
    );
    for (wire, chunk) in wires.iter().zip(bytes.chunks_exact(8)) {
        let arr: [u8; 8] = chunk.try_into().expect("chunks_exact(8) yields 8 bytes");
        w[*wire] = Word(u64::from_le_bytes(arr));
    }
}

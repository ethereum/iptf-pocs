//! FSRT chain (SPEC FSRT Chain).

use ark_bn254::Fr;

use crate::{
    FSRT_DEPTH,
    FSRT_SLOT_COUNT,
    poseidon::{
        fr_from_be_bytes,
        fr_to_be_bytes,
        fsrt_prg_step,
        hash_merkle_node,
    },
    types::{
        Bytes32,
        SignerStateBytes,
    },
};

/// Eager expansion result, held briefly during enrollment.
pub struct ExpandedChain {
    pub v_values: Vec<Fr>,
    pub s_seeds: Vec<Fr>,
}

/// Eagerly expand `s_0` into `n_override` (or `FSRT_SLOT_COUNT`) per-slot values.
pub fn expand_chain(s_0: Fr, n_override: Option<u32>) -> ExpandedChain {
    let n = n_override.unwrap_or(FSRT_SLOT_COUNT) as usize;
    let mut v_values = Vec::with_capacity(n);
    let mut s_seeds = Vec::with_capacity(n);
    let mut s_i = s_0;
    for _ in 0..n {
        s_seeds.push(s_i);
        let (v_i, s_next) = fsrt_prg_step(s_i);
        v_values.push(v_i);
        s_i = s_next;
    }
    ExpandedChain { v_values, s_seeds }
}

/// Depth-`FSRT_DEPTH` Merkle root over `v_values` via sparse construction.
pub fn compute_chain_root(v_values: &[Fr]) -> Fr {
    let empty = compute_empty_subtree();
    if v_values.is_empty() {
        return empty[FSRT_DEPTH];
    }
    let mut layer: Vec<Fr> = v_values.to_vec();
    let mut level = 0usize;
    while level < FSRT_DEPTH {
        if layer.len() == 1 {
            return empty[level..FSRT_DEPTH]
                .iter()
                .fold(layer[0], |current, sib| hash_merkle_node(current, *sib));
        }
        if !layer.len().is_multiple_of(2) {
            layer.push(empty[level]);
        }
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(hash_merkle_node(pair[0], pair[1]));
        }
        layer = next;
        level += 1;
    }
    layer[0]
}

/// Merkle path from `v_values[index]` to the root.
pub fn compute_path(v_values: &[Fr], index: u32) -> (Vec<Fr>, Vec<u8>) {
    let empty = compute_empty_subtree();
    let mut siblings = Vec::with_capacity(FSRT_DEPTH);
    let mut indices = Vec::with_capacity(FSRT_DEPTH);

    let mut layer: Vec<Fr> = v_values.to_vec();
    let mut idx = index as usize;
    for level in 0..FSRT_DEPTH {
        if layer.len() <= 1 {
            for empty_sib in &empty[level..FSRT_DEPTH] {
                siblings.push(*empty_sib);
                indices.push(0);
            }
            break;
        }
        if !layer.len().is_multiple_of(2) {
            layer.push(empty[level]);
        }
        let sib_idx = idx ^ 1;
        let sib = if sib_idx < layer.len() {
            layer[sib_idx]
        } else {
            empty[level]
        };
        siblings.push(sib);
        indices.push((idx % 2) as u8);
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks(2) {
            next.push(hash_merkle_node(pair[0], pair[1]));
        }
        layer = next;
        idx /= 2;
    }
    (siblings, indices)
}

/// Caterpillar log-space frontier (SPEC Off-Chain Signer State).
#[derive(Debug, Clone)]
pub struct Caterpillar {
    frontier: [Fr; FSRT_DEPTH],
    active: [Option<Fr>; FSRT_DEPTH],
    t: u32,
    empty_subtree: [Fr; FSRT_DEPTH + 1],
}

impl Caterpillar {
    /// Empty frontier at slot 0.
    pub fn empty() -> Self {
        let empty_subtree = compute_empty_subtree();
        Self {
            frontier: [Fr::from(0u64); FSRT_DEPTH],
            active: [None; FSRT_DEPTH],
            t: 0,
            empty_subtree,
        }
    }

    pub fn slot(&self) -> u32 {
        self.t
    }

    /// Advance the frontier past `slot` by absorbing `v_slot`.
    pub fn advance(&mut self, slot: u32, v_slot: Fr) {
        assert_eq!(slot, self.t, "caterpillar: out-of-order advance");
        let mut carry = v_slot;
        let mut idx = self.t;
        for level in 0..FSRT_DEPTH {
            if idx.is_multiple_of(2) {
                self.active[level] = Some(carry);
                break;
            } else {
                let left = self.active[level].unwrap_or(self.empty_subtree[level]);
                self.frontier[level] = left;
                carry = hash_merkle_node(left, carry);
                self.active[level] = None;
                idx /= 2;
            }
        }
        self.t = self
            .t
            .checked_add(1)
            .expect("caterpillar: slot counter overflow; re-enroll required");
    }

    /// Merkle path for the slot the signer is about to sign at (`= self.t`).
    pub fn path_for_current_slot(&self) -> (Vec<Fr>, Vec<u8>) {
        let mut siblings = Vec::with_capacity(FSRT_DEPTH);
        let mut indices = Vec::with_capacity(FSRT_DEPTH);
        let mut idx = self.t;
        for level in 0..FSRT_DEPTH {
            let sib = if idx.is_multiple_of(2) {
                self.empty_subtree[level]
            } else {
                self.active[level].unwrap_or(self.empty_subtree[level])
            };
            siblings.push(sib);
            indices.push((idx % 2) as u8);
            idx /= 2;
        }
        (siblings, indices)
    }

    /// Byte form for `SignerStateBytes.caterpillar`.
    pub fn to_bytes(&self) -> [Bytes32; FSRT_DEPTH] {
        let mut out = [[0u8; 32]; FSRT_DEPTH];
        for (i, slot) in out.iter_mut().enumerate() {
            let value = self.active[i].unwrap_or(self.empty_subtree[i]);
            *slot = fr_to_be_bytes(&value);
        }
        out
    }
}

fn compute_empty_subtree() -> [Fr; FSRT_DEPTH + 1] {
    let mut levels = [Fr::from(0u64); FSRT_DEPTH + 1];
    levels[0] = Fr::from(0u64);
    for i in 1..=FSRT_DEPTH {
        levels[i] = hash_merkle_node(levels[i - 1], levels[i - 1]);
    }
    levels
}

/// Per-signer FSRT runtime state. `v_values` / `s_seeds` are wiped
/// via volatile writes past the last journaled slot, and on `Drop`,
/// to limit the window in which a memory-image compromise reveals
/// prior signed slots. The Vec heap allocation itself is freed by
/// the global allocator and is NOT explicitly wiped; production
/// deployments should hold the seeds in `mlock`-pinned memory.
#[derive(Debug)]
pub struct SignerChainState {
    pub s_curr: Fr,
    pub t: u32,
    pub caterpillar: Caterpillar,
    pub chain_root: Fr,
    pub attr_version: u32,
    v_values: Vec<Fr>,
    s_seeds: Vec<Fr>,
}

impl Drop for SignerChainState {
    fn drop(&mut self) {
        // Best-effort wipe via volatile writes. `compiler_fence` alone
        // does not prevent dead-store elimination; only `write_volatile`
        // creates a barrier LLVM cannot remove.
        unsafe {
            for v in self.v_values.iter_mut() {
                core::ptr::write_volatile(v as *mut Fr, Fr::from(0u64));
            }
            for s in self.s_seeds.iter_mut() {
                core::ptr::write_volatile(s as *mut Fr, Fr::from(0u64));
            }
            core::ptr::write_volatile(&mut self.s_curr as *mut Fr, Fr::from(0u64));
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl SignerChainState {
    /// Fresh state at enrollment.
    pub fn enroll(s_0: Fr, chain_len: u32, attr_version: u32) -> Self {
        let expanded = expand_chain(s_0, Some(chain_len));
        let chain_root = compute_chain_root(&expanded.v_values);
        Self {
            s_curr: s_0,
            t: 0,
            caterpillar: Caterpillar::empty(),
            chain_root,
            attr_version,
            v_values: expanded.v_values,
            s_seeds: expanded.s_seeds,
        }
    }

    /// Advance the ratchet head and caterpillar to `target_slot` (monotone).
    pub fn advance_to(&mut self, target_slot: u32) {
        assert!(target_slot < self.v_values.len() as u32);
        assert!(target_slot >= self.t, "FSRT advance must be monotone");
        while self.t < target_slot {
            let v = self.v_values[self.t as usize];
            self.caterpillar.advance(self.t, v);
            self.t += 1;
        }
    }

    /// Chain length the ratchet was enrolled for.
    pub fn chain_len(&self) -> u32 {
        self.v_values.len() as u32
    }

    /// `v_slot` at the current `t`.
    pub fn v_at_current_slot(&self) -> Fr {
        self.v_values[self.t as usize]
    }

    /// Per-slot seed `s_slot`; zero if zeroized.
    pub fn s_at(&self, slot: u32) -> Fr {
        self.s_seeds
            .get(slot as usize)
            .copied()
            .unwrap_or(Fr::from(0u64))
    }

    /// Merkle path from `v[self.t]` to `chain_root`.
    pub fn merkle_path_for_current_slot(&self) -> (Vec<Fr>, Vec<u8>) {
        compute_path(&self.v_values, self.t)
    }

    /// SPEC Per-Signature Generation step 5 + FSRT Chain. Writes the
    /// post-signing state to `journal_path` atomically (tmp file +
    /// fsync + atomic rename + parent-directory fsync), and only after
    /// the write durably lands does the in-memory mutation commit. This
    /// ordering ensures a power-loss between in-memory and on-disk
    /// state cannot leave the signer with a "future" in-memory ratchet
    /// against a stale on-disk snapshot (which would let the signer
    /// re-sign the same slot with a different v_slot).
    pub fn journal_finalized_signing(
        &mut self,
        slot: u32,
        journal_path: &std::path::Path,
    ) -> Result<SignerStateBytes, std::io::Error> {
        assert_eq!(
            slot, self.t,
            "journal_finalized_signing: slot mismatch (self.t = {}, slot = {})",
            self.t, slot
        );

        // 1. Compute the would-be next state (without mutating self).
        let s_slot = self.s_seeds[slot as usize];
        let (_, s_next) = fsrt_prg_step(s_slot);
        let v_slot = self.v_values[slot as usize];

        // 2. Materialize the post-mutation state-bytes in memory.
        let mut next_caterpillar = self.caterpillar.clone();
        next_caterpillar.advance(slot, v_slot);
        let next_t = slot + 1;
        let next_state = SignerStateBytes {
            s_curr: fr_to_be_bytes(&s_next),
            t: next_t,
            caterpillar: next_caterpillar.to_bytes(),
            chain_root: fr_to_be_bytes(&self.chain_root),
            attr_version: self.attr_version,
        };

        // 3. Persist atomically: tmp file -> fsync -> rename ->
        //    parent-dir fsync. Only on success do we mutate self.
        let parent = journal_path.parent().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent dir")
        })?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        // Serialize the state as bincode-ish: just concatenate raw
        // fields. The exact wire format is the signer's responsibility;
        // here we write enough bytes to detect truncation on read-back.
        use std::io::Write;
        tmp.write_all(&next_state.s_curr)?;
        tmp.write_all(&next_state.t.to_be_bytes())?;
        for chunk in &next_state.caterpillar {
            tmp.write_all(chunk)?;
        }
        tmp.write_all(&next_state.chain_root)?;
        tmp.write_all(&next_state.attr_version.to_be_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(journal_path)
            .map_err(|e: tempfile::PersistError| e.error)?;
        // Parent-dir fsync makes the rename(2) durable across power loss
        // on POSIX. rename(2) itself is atomic for content but the
        // dirent change is not durable until the dir is synced.
        let dir = std::fs::File::open(parent)?;
        dir.sync_all()?;

        // 4. Commit in-memory state ONLY after successful persistence.
        self.s_curr = s_next;
        self.caterpillar = next_caterpillar;
        self.t = next_t;
        // 5. Wipe past seeds via volatile writes (post-commit).
        for i in 0..=slot as usize {
            if i < self.v_values.len() {
                unsafe {
                    core::ptr::write_volatile(
                        &mut self.v_values[i] as *mut Fr,
                        Fr::from(0u64),
                    );
                }
            }
            if i < self.s_seeds.len() {
                unsafe {
                    core::ptr::write_volatile(
                        &mut self.s_seeds[i] as *mut Fr,
                        Fr::from(0u64),
                    );
                }
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);

        Ok(next_state)
    }

    /// SPEC's 840-byte off-chain state.
    pub fn to_bytes(&self) -> SignerStateBytes {
        SignerStateBytes {
            s_curr: fr_to_be_bytes(&self.s_curr),
            t: self.t,
            caterpillar: self.caterpillar.to_bytes(),
            chain_root: fr_to_be_bytes(&self.chain_root),
            attr_version: self.attr_version,
        }
    }
}

/// Lift `chain_root` from wire bytes.
pub fn chain_root_from_bytes(state: &SignerStateBytes) -> Fr {
    fr_from_be_bytes(&state.chain_root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_chain_is_deterministic() {
        let s_0 = Fr::from(0x1234u64);
        let a = expand_chain(s_0, Some(8));
        let b = expand_chain(s_0, Some(8));
        assert_eq!(a.v_values, b.v_values);
        assert_eq!(a.s_seeds, b.s_seeds);
    }

    #[test]
    fn test_journal_finalized_signing_zeroizes_past_slots() {
        let mut s = SignerChainState::enroll(Fr::from(13u64), 8, 0);
        s.advance_to(0);
        let s_before = s.s_at(0);
        assert_ne!(s_before, Fr::from(0u64));
        let v_before = s.v_at_current_slot();
        assert_ne!(v_before, Fr::from(0u64));
        let tmpdir = tempfile::tempdir().unwrap();
        let journal_path = tmpdir.path().join("signer.journal");
        let _ = s.journal_finalized_signing(0, &journal_path).unwrap();
        assert_eq!(s.t, 1);
        assert_eq!(s.s_at(0), Fr::from(0u64));
        assert_eq!(s.v_values[0], Fr::from(0u64));
        let (_, expected_s1) = crate::poseidon::fsrt_prg_step(s_before);
        assert_eq!(s.s_curr, expected_s1);
    }

    #[test]
    fn test_expand_chain_different_seeds_diverge() {
        let a = expand_chain(Fr::from(1u64), Some(8));
        let b = expand_chain(Fr::from(2u64), Some(8));
        assert_ne!(a.v_values, b.v_values);
    }

    #[test]
    fn test_compute_chain_root_distinct_inputs() {
        let r1 = compute_chain_root(&[Fr::from(1u64), Fr::from(2u64)]);
        let r2 = compute_chain_root(&[Fr::from(2u64), Fr::from(1u64)]);
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_compute_path_root_matches_full_tree() {
        let v: Vec<Fr> = (1..=4).map(|i| Fr::from(i as u64)).collect();
        let root = compute_chain_root(&v);
        for i in 0..v.len() as u32 {
            let (siblings, indices) = compute_path(&v, i);
            let mut current = v[i as usize];
            for (s, &dir) in siblings.iter().zip(indices.iter()) {
                current = if dir == 0 {
                    hash_merkle_node(current, *s)
                } else {
                    hash_merkle_node(*s, current)
                };
            }
            assert_eq!(current, root, "path failed for index {i}");
        }
    }

    #[test]
    fn test_signer_chain_state_advance_monotone() {
        let mut s = SignerChainState::enroll(Fr::from(7u64), 8, 0);
        assert_eq!(s.t, 0);
        s.advance_to(3);
        assert_eq!(s.t, 3);
    }

    #[test]
    #[should_panic(expected = "FSRT advance must be monotone")]
    fn test_signer_chain_state_advance_cannot_regress() {
        let mut s = SignerChainState::enroll(Fr::from(7u64), 8, 0);
        s.advance_to(5);
        s.advance_to(2);
    }

    #[test]
    fn test_signer_chain_state_journal_overwrites_s_curr() {
        let mut s = SignerChainState::enroll(Fr::from(7u64), 8, 0);
        let pre = s.s_curr;
        let tmpdir = tempfile::tempdir().unwrap();
        let journal_path = tmpdir.path().join("signer.journal");
        let _ = s.journal_finalized_signing(0, &journal_path).unwrap();
        assert_eq!(s.t, 1);
        let (_, expected_s1) = crate::poseidon::fsrt_prg_step(pre);
        assert_eq!(s.s_curr, expected_s1);
        assert_ne!(s.s_curr, pre);
    }

    #[test]
    fn test_signer_chain_state_to_bytes_carries_metadata() {
        let s = SignerChainState::enroll(Fr::from(7u64), 8, 5);
        let b = s.to_bytes();
        assert_eq!(b.attr_version, 5);
        assert_eq!(b.t, 0);
        assert_ne!(b.chain_root, [0u8; 32]);
    }

    #[test]
    fn test_caterpillar_advance_tracks_slot_counter() {
        let v: Vec<Fr> = (1..=8).map(|i| Fr::from(i as u64)).collect();
        let mut c = Caterpillar::empty();
        for (i, &v_i) in v.iter().enumerate() {
            assert_eq!(c.slot(), i as u32);
            c.advance(i as u32, v_i);
        }
        assert_eq!(c.slot(), v.len() as u32);
    }

    #[test]
    fn test_chain_root_from_bytes_roundtrip() {
        let s = SignerChainState::enroll(Fr::from(7u64), 8, 0);
        let bytes = s.to_bytes();
        let restored = chain_root_from_bytes(&bytes);
        assert_eq!(restored, s.chain_root);
    }
}

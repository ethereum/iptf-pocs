//! In-process signer-to-relayer channel with per-relay FIFO inboxes.

use std::{
    collections::{
        HashMap,
        VecDeque,
    },
    sync::Mutex,
};

use crate::{
    ports::submission::{
        RelaySubmission,
        SubmissionError,
    },
    types::{
        Bytes32,
        SignerSubmission,
    },
};

pub struct DirectRelaySubmission {
    inboxes: Mutex<HashMap<Bytes32, VecDeque<SignerSubmission>>>,
}

impl DirectRelaySubmission {
    pub fn new(relay_ids: impl IntoIterator<Item = Bytes32>) -> Self {
        let inboxes = relay_ids
            .into_iter()
            .map(|id| (id, VecDeque::new()))
            .collect();
        Self {
            inboxes: Mutex::new(inboxes),
        }
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<Bytes32, VecDeque<SignerSubmission>>> {
        self.inboxes
            .lock()
            .expect("DirectRelaySubmission inboxes poisoned")
    }

    /// Test-only relayer pull; production relays must not expose their inbox.
    #[cfg(test)]
    pub fn pull(&self, relay_id: &Bytes32) -> Option<SignerSubmission> {
        self.lock().get_mut(relay_id)?.pop_front()
    }

    /// Test-only; queue depth would leak timing signals in production.
    #[cfg(test)]
    pub fn pending(&self, relay_id: &Bytes32) -> usize {
        self.lock().get(relay_id).map(|q| q.len()).unwrap_or(0)
    }

    /// Test-only inbox drain.
    #[cfg(test)]
    pub fn drain(&self, relay_id: &Bytes32) -> Vec<SignerSubmission> {
        let mut g = self.lock();
        match g.get_mut(relay_id) {
            Some(q) => q.drain(..).collect(),
            None => Vec::new(),
        }
    }
}

impl RelaySubmission for DirectRelaySubmission {
    fn submit(
        &self,
        relay_id: &Bytes32,
        submission: SignerSubmission,
    ) -> Result<(), SubmissionError> {
        self.lock()
            .get_mut(relay_id)
            .ok_or(SubmissionError::UnknownRelay)?
            .push_back(submission);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_submission(seed: u8) -> SignerSubmission {
        SignerSubmission {
            petition_id: [seed; 32],
            r_root: [seed; 32],
            predicate_hash: [seed; 32],
            class_index: 0,
            slot: seed as u32,
            nullifier: [seed; 32],
            identity_tag: [seed; 32],
            class_tag: seed as u16,
            proof_bytes: vec![seed; 8],
        }
    }

    #[test]
    fn test_submit_then_pull() {
        let relay = [0x11u8; 32];
        let s = DirectRelaySubmission::new([relay]);
        s.submit(&relay, fake_submission(0xaa)).unwrap();
        assert_eq!(s.pending(&relay), 1);
        let pulled = s.pull(&relay).unwrap();
        assert_eq!(pulled.slot, 0xaa);
    }

    #[test]
    fn test_unknown_relay_rejected() {
        let known = [0x11u8; 32];
        let other = [0x22u8; 32];
        let s = DirectRelaySubmission::new([known]);
        let err = s.submit(&other, fake_submission(0));
        assert!(matches!(err, Err(SubmissionError::UnknownRelay)));
    }

    #[test]
    fn test_drain_returns_all_and_empties_inbox() {
        let r = [0x33u8; 32];
        let s = DirectRelaySubmission::new([r]);
        for i in 0..3 {
            s.submit(&r, fake_submission(i)).unwrap();
        }
        let drained = s.drain(&r);
        assert_eq!(drained.len(), 3);
        assert_eq!(s.pending(&r), 0);
    }

    #[test]
    fn test_fifo_order() {
        let r = [0x44u8; 32];
        let s = DirectRelaySubmission::new([r]);
        for i in 0..3 {
            s.submit(&r, fake_submission(i)).unwrap();
        }
        for i in 0..3 {
            let p = s.pull(&r).unwrap();
            assert_eq!(p.slot, i as u32);
        }
    }
}

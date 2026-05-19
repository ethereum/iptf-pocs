//! Block-number abstraction for the Registry state machine.

use std::sync::atomic::{
    AtomicU64,
    Ordering,
};

pub trait BlockClock: Send + Sync {
    fn block_number(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct MockBlockClock {
    inner: AtomicU64,
}

impl MockBlockClock {
    pub fn new(at: u64) -> Self {
        Self {
            inner: AtomicU64::new(at),
        }
    }
    pub fn set(&self, at: u64) {
        self.inner.store(at, Ordering::SeqCst)
    }
    pub fn advance(&self, by: u64) {
        self.inner.fetch_add(by, Ordering::SeqCst);
    }
}

impl BlockClock for MockBlockClock {
    fn block_number(&self) -> u64 {
        self.inner.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_block_clock_starts_at_initial_value() {
        let c = MockBlockClock::new(100);
        assert_eq!(c.block_number(), 100);
    }

    #[test]
    fn mock_block_clock_advance_adds_blocks() {
        let c = MockBlockClock::new(100);
        c.advance(7);
        assert_eq!(c.block_number(), 107);
    }

    #[test]
    fn mock_block_clock_set_replaces_value() {
        let c = MockBlockClock::new(100);
        c.set(500);
        assert_eq!(c.block_number(), 500);
    }
}

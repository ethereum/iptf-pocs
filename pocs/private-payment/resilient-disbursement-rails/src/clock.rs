//! Wall-clock abstraction. Production uses `SystemClock`; tests instantiate
//! `MockClock` directly.

use std::{
    sync::atomic::{
        AtomicU64,
        Ordering,
    },
    time::{
        SystemTime,
        UNIX_EPOCH,
    },
};

pub trait Clock: Send + Sync {
    fn now_unix(&self) -> u64;
}

#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_secs()
    }
}

pub struct MockClock {
    inner: AtomicU64,
}

impl MockClock {
    pub fn new(now: u64) -> Self {
        Self {
            inner: AtomicU64::new(now),
        }
    }

    pub fn set(&self, now: u64) {
        self.inner.store(now, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: u64) {
        self.inner.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for MockClock {
    fn now_unix(&self) -> u64 {
        self.inner.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_recent_unix_time() {
        let clock = SystemClock;
        let now = clock.now_unix();
        assert!(
            now > 1_700_000_000,
            "expected current unix time > 1_700_000_000, got {now}"
        );
    }

    #[test]
    fn mock_clock_advance_adds_seconds() {
        let clock = MockClock::new(1000);
        clock.advance(60);
        assert_eq!(clock.now_unix(), 1060);
    }

    #[test]
    fn mock_clock_set_replaces_value() {
        let clock = MockClock::new(1000);
        clock.set(2000);
        assert_eq!(clock.now_unix(), 2000);
    }
}

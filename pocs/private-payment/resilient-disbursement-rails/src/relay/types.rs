//! Relay key archive: current + previous static X25519 keys with rotation.

use std::time::{
    Duration,
    Instant,
};

use x25519_dalek::{
    PublicKey,
    StaticSecret,
};

pub struct KeyArchive {
    pub current_sk: StaticSecret,
    pub current_pk: PublicKey,
    pub previous_sk: Option<StaticSecret>,
    pub previous_pk: Option<PublicKey>,
    pub rotated_at: Instant,
    pub rotation_interval: Duration,
}

impl KeyArchive {
    pub fn rotate(&mut self) {
        let mut seed = [0u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        let new_sk = StaticSecret::from(seed);
        let new_pk = PublicKey::from(&new_sk);
        let prev_sk = std::mem::replace(&mut self.current_sk, new_sk);
        let prev_pk = std::mem::replace(&mut self.current_pk, new_pk);
        self.previous_sk = Some(prev_sk);
        self.previous_pk = Some(prev_pk);
        self.rotated_at = Instant::now();
    }

    pub fn is_due(&self) -> bool {
        self.rotated_at.elapsed() >= self.rotation_interval
    }
}

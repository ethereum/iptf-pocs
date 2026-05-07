use serde::{
    Deserialize,
    Serialize,
};

use crate::types::{
    Bytes32,
    SignedHeader,
};

/// One descriptor per relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayDescriptor {
    pub relay_id: Bytes32,
    pub static_pub_x25519: [u8; 32],
    /// Rotation epoch advertised by the relay; companions use it for
    /// freshness reasoning, not for cryptographic identity.
    pub rotation_epoch: u64,
}

/// Funder-signed list of currently-online relays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRoster {
    pub relays: Vec<RelayDescriptor>,
    pub signed_at_unix: u64,
    pub signature: Vec<u8>,
}

/// Round header with first-pool-leaf-index packaged together; the SPEC
/// distributes them as separate fields, but in this PoC the relay roster
/// signer also vouches for `first_pool_leaf_index` so the companion
/// receives them as a single bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderBundle {
    pub signed: SignedHeader,
    pub first_pool_leaf_index: u64,
}

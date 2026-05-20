//! Blob-carrier port; EIP-4844 in production, in-memory in the PoC adapter.

use crate::{
    error::BlobError,
    types::{
        Bytes32,
        KzgOpening,
        RecordEntry,
    },
};

pub trait BlobCarrier: Send + Sync {
    /// Publish a batch's record payload; returns `batch_versioned_hash`.
    fn publish(&mut self, records: &[RecordEntry]) -> Result<Bytes32, BlobError>;

    /// Open a single BLS12-381 field element at `field_element_index`.
    fn open(
        &self,
        batch_versioned_hash: &Bytes32,
        field_element_index: u32,
    ) -> Result<KzgOpening, BlobError>;

    /// Verify a single opening against `batch_versioned_hash`.
    fn verify(
        &self,
        batch_versioned_hash: &Bytes32,
        opening: &KzgOpening,
    ) -> Result<(), BlobError>;

    /// Read back the full record set for `batch_versioned_hash`.
    fn fetch_records(
        &self,
        batch_versioned_hash: &Bytes32,
    ) -> Result<Vec<RecordEntry>, BlobError>;
}

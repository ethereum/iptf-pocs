-- Down Migration: Drop tables and indexes created in the up migration.

--- Drop Indexes for Indexed Leaves
DROP INDEX IF EXISTS idx_indexed_leaves_low_index;
DROP INDEX IF EXISTS idx_indexed_leaves_index;
DROP INDEX IF EXISTS idx_indexed_leaves_get_leaf_and_key;

-- Drop Indexes for Merkle tree tables
DROP INDEX IF EXISTS idx_leaves_len_lookup;
DROP INDEX IF EXISTS idx_hash_nodes_lookup;

--- Drop Indexes for validity prover tables
DROP INDEX IF EXISTS idx_tx_tree_roots_block_number;

--- Drop Indexes for event tables
DROP INDEX IF EXISTS idx_full_blocks_sync;
DROP INDEX IF EXISTS idx_deposited_events_sync;
DROP INDEX IF EXISTS idx_deposited_events_pubkey_salt_hash;
DROP INDEX IF EXISTS idx_deposit_leaf_events_sync;
DROP INDEX IF EXISTS idx_deposit_leaf_events_deposit_hash;

--- Merkle tree tables
DROP TABLE IF EXISTS indexed_leaves;
DROP TABLE IF EXISTS leaves_len;
DROP TABLE IF EXISTS leaves;
DROP TABLE IF EXISTS hash_nodes;

--- Validity prover tables
DROP TABLE IF EXISTS tx_tree_roots;
DROP TABLE IF EXISTS validity_proofs;
DROP TABLE IF EXISTS validity_state;

-- event tables
DROP TABLE IF EXISTS full_blocks;
DROP TABLE IF EXISTS deposited_events;
DROP TABLE IF EXISTS deposit_leaf_events;

-- settings tables
DROP TABLE IF EXISTS event_sync_eth_block;
DROP TABLE IF EXISTS settings;

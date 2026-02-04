-- settings tables
CREATE TABLE IF NOT EXISTS settings (
    singleton_key BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton_key),
    rollup_contract_address VARCHAR(42) NOT NULL,
    liquidity_contract_address VARCHAR(42) NOT NULL
);

CREATE TABLE IF NOT EXISTS event_sync_eth_block (
    event_type TEXT PRIMARY KEY,
    eth_block_number BIGINT NOT NULL
);

-- event tables
CREATE TABLE IF NOT EXISTS deposit_leaf_events (
    deposit_index INTEGER PRIMARY KEY,
    deposit_hash BYTEA NOT NULL,
    eth_block_number BIGINT NOT NULL,
    eth_tx_index BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS deposited_events (
    deposit_id BIGINT PRIMARY KEY,
    depositor VARCHAR(42) NOT NULL,
    pubkey_salt_hash VARCHAR(66) NOT NULL,
    token_index BIGINT NOT NULL,
    amount VARCHAR(66) NOT NULL,
    is_eligible BOOLEAN NOT NULL,
    deposited_at BIGINT NOT NULL,
    deposit_hash VARCHAR(66) NOT NULL,
    tx_hash VARCHAR(66) NOT NULL,
    eth_block_number BIGINT NOT NULL,
    eth_tx_index BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS full_blocks (
    block_number INTEGER PRIMARY KEY,
    full_block BYTEA NOT NULL,
    eth_block_number BIGINT NOT NULL,
    eth_tx_index BIGINT NOT NULL
);

-- Validity prover tables
CREATE TABLE IF NOT EXISTS validity_state (
   block_number INTEGER NOT NULL PRIMARY KEY,
   validity_witness BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS validity_proofs (
    block_number INTEGER PRIMARY KEY,
    proof BYTEA NOT NULL
);

CREATE TABLE IF NOT EXISTS tx_tree_roots (
    tx_tree_root BYTEA PRIMARY KEY,
    block_number INTEGER NOT NULL
);

--- Merkle tree tables
CREATE TABLE IF NOT EXISTS hash_nodes (
    tag int NOT NULL,
    timestamp bigint NOT NULL,
    bit_path bytea NOT NULL,
    hash_value bytea NOT NULL,
    PRIMARY KEY (tag, timestamp, bit_path)
) PARTITION BY LIST (tag);

CREATE TABLE IF NOT EXISTS leaves (
    tag int NOT NULL,
    timestamp bigint NOT NULL,
    position bigint NOT NULL,
    leaf_hash bytea NOT NULL,
    leaf bytea NOT NULL,
    PRIMARY KEY (tag, timestamp, position)
) PARTITION BY LIST (tag);

CREATE TABLE IF NOT EXISTS leaves_len (
    tag int NOT NULL,
    timestamp bigint NOT NULL,
    len int NOT NULL,
    PRIMARY KEY (tag, timestamp)
) PARTITION BY LIST (tag);

CREATE TABLE IF NOT EXISTS indexed_leaves (
    tag int NOT NULL,
    timestamp bigint NOT NULL,
    position bigint NOT NULL,
    leaf_hash bytea NOT NULL,
    next_index bigint NOT NULL,
    key NUMERIC(78, 0) NOT NULL,
    next_key NUMERIC(78, 0) NOT NULL,
    value bigint NOT NULL,
    PRIMARY KEY (tag, position, timestamp)
) PARTITION BY LIST (tag);

--- Indexes for event tables
CREATE INDEX IF NOT EXISTS idx_deposit_leaf_events_deposit_hash ON deposit_leaf_events(deposit_hash);
CREATE INDEX IF NOT EXISTS idx_deposit_leaf_events_sync ON deposit_leaf_events(eth_block_number, eth_tx_index);
CREATE INDEX IF NOT EXISTS idx_deposited_events_pubkey_salt_hash ON deposited_events(pubkey_salt_hash);
CREATE INDEX IF NOT EXISTS idx_deposited_events_sync ON deposited_events(eth_block_number, eth_tx_index);
CREATE INDEX IF NOT EXISTS idx_full_blocks_sync ON full_blocks(eth_block_number, eth_tx_index);

--- Indexes for validity prover tables
CREATE INDEX IF NOT EXISTS idx_tx_tree_roots_block_number ON tx_tree_roots (block_number);

-- Indexes for Merkle tree tables
CREATE INDEX IF NOT EXISTS idx_hash_nodes_lookup ON hash_nodes (tag, bit_path, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_leaves_len_lookup ON leaves_len (tag, timestamp DESC);

-- Indexes for Indexed Leaves
CREATE INDEX IF NOT EXISTS idx_indexed_leaves_get_leaf_and_key ON indexed_leaves (tag, position, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_indexed_leaves_index ON indexed_leaves (tag, key, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_indexed_leaves_low_index ON indexed_leaves (tag, next_key, key, timestamp DESC);

-- Partition tables for Merkle tree tables
CREATE TABLE IF NOT EXISTS hash_nodes_tag1 PARTITION OF hash_nodes FOR VALUES IN (1);
CREATE TABLE IF NOT EXISTS hash_nodes_tag2 PARTITION OF hash_nodes FOR VALUES IN (2);
CREATE TABLE IF NOT EXISTS hash_nodes_tag3 PARTITION OF hash_nodes FOR VALUES IN (3);
CREATE TABLE  IF NOT EXISTS leaves_tag1 PARTITION OF leaves
    FOR VALUES IN (1);
CREATE TABLE  IF NOT EXISTS leaves_tag2 PARTITION OF leaves
    FOR VALUES IN (2);
CREATE TABLE  IF NOT EXISTS leaves_tag3 PARTITION OF leaves
    FOR VALUES IN (3);
CREATE TABLE  IF NOT EXISTS leaves_len_tag1 PARTITION OF leaves_len
    FOR VALUES IN (1);
CREATE TABLE  IF NOT EXISTS leaves_len_tag2 PARTITION OF leaves_len
    FOR VALUES IN (2);
CREATE TABLE  IF NOT EXISTS leaves_len_tag3 PARTITION OF leaves_len
    FOR VALUES IN (3);
CREATE TABLE  IF NOT EXISTS indexed_leaves_tag1 PARTITION OF indexed_leaves
    FOR VALUES IN (1);

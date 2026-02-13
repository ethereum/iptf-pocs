CREATE TABLE IF NOT EXISTS snapshot_data (
    pubkey VARCHAR(66) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    digest VARCHAR(66) NOT NULL,
    data BYTEA NOT NULL,
    timestamp BIGINT NOT NULL,
    UNIQUE (pubkey, topic)
);

CREATE TABLE IF NOT EXISTS historical_data (
    digest VARCHAR(66) PRIMARY KEY,
    pubkey VARCHAR(66) NOT NULL,
    topic VARCHAR(255) NOT NULL,
    data BYTEA NOT NULL,
    timestamp BIGINT NOT NULL
);
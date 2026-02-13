-- Drop indexes first
DROP INDEX IF EXISTS idx_claims_nullifier;
DROP INDEX IF EXISTS idx_claims_pubkey;
DROP INDEX IF EXISTS idx_withdrawals_withdrawal_hash;
DROP INDEX IF EXISTS idx_withdrawals_recipient;
DROP INDEX IF EXISTS idx_withdrawals_pubkey;

-- Drop tables
DROP TABLE IF EXISTS used_payments;
DROP TABLE IF EXISTS claims;
DROP TABLE IF EXISTS withdrawals;

-- Drop custom enum types
DROP TYPE IF EXISTS claim_status;
DROP TYPE IF EXISTS withdrawal_status;

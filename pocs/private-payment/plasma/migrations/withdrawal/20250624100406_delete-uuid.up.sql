-- Add up migration script here
BEGIN;

-- withdrawals
ALTER TABLE withdrawals DROP CONSTRAINT withdrawals_pkey;
ALTER TABLE withdrawals ADD PRIMARY KEY (withdrawal_hash);
DROP INDEX IF EXISTS idx_withdrawals_withdrawal_hash;
ALTER TABLE withdrawals DROP COLUMN uuid;

-- claims
ALTER TABLE claims DROP CONSTRAINT claims_pkey;
ALTER TABLE claims ADD PRIMARY KEY (nullifier);
DROP INDEX IF EXISTS idx_claims_nullifier;
ALTER TABLE claims DROP COLUMN uuid;

COMMIT;
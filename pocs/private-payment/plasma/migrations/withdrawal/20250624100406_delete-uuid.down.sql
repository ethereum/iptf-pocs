-- Add down migration script here
BEGIN;

-- withdrawals
ALTER TABLE withdrawals ADD COLUMN uuid TEXT;
CREATE INDEX IF NOT EXISTS idx_withdrawals_withdrawal_hash ON withdrawals(withdrawal_hash);
ALTER TABLE withdrawals DROP CONSTRAINT withdrawals_pkey;
ALTER TABLE withdrawals ADD PRIMARY KEY (uuid);

-- claims
ALTER TABLE claims ADD COLUMN uuid TEXT;
CREATE INDEX IF NOT EXISTS idx_claims_nullifier ON claims(nullifier);
ALTER TABLE claims DROP CONSTRAINT claims_pkey;
ALTER TABLE claims ADD PRIMARY KEY (uuid);

COMMIT;
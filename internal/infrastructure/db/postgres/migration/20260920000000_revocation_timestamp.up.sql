ALTER TABLE delegations ADD COLUMN IF NOT EXISTS last_revocation_timestamp BIGINT NOT NULL DEFAULT 0;

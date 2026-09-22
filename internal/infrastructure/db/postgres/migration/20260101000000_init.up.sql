CREATE TABLE IF NOT EXISTS delegations (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    address TEXT NOT NULL UNIQUE,
    tapscripts TEXT[] NOT NULL,
    renewal_window BIGINT NOT NULL,
    max_fee BIGINT NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'active',
    last_revocation_timestamp BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS renewals (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    delegation_id BIGINT NOT NULL REFERENCES delegations(id) ON DELETE CASCADE,
    outpoints TEXT[] NOT NULL,
    commitment_txid TEXT NOT NULL DEFAULT '',
    success BOOLEAN NOT NULL,
    error TEXT NOT NULL DEFAULT '',
    attempted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_delegations_status ON delegations(status);
CREATE INDEX IF NOT EXISTS idx_renewals_delegation ON renewals(delegation_id, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_renewals_attempted_at ON renewals(attempted_at);

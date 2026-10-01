CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    document BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS templates (
    id TEXT PRIMARY KEY,
    document BYTEA NOT NULL,
    artifact_ids TEXT[] NOT NULL DEFAULT '{}',
    params JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    failures INT NOT NULL DEFAULT 0,
    -- set by the operator: delegate-key leaves are signed, the failure valve skips it
    trusted BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS delegations (
    id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    fingerprint TEXT NOT NULL,
    -- slot 0 address of a watch, empty otherwise: not unique, a stopped watch may be registered again
    address TEXT NOT NULL DEFAULT '',
    template_id TEXT NOT NULL REFERENCES templates(id),
    variables JSONB NOT NULL DEFAULT '{}',
    -- the delegation whose settled transaction advertised this one; NULL for a watch
    parent_id BIGINT NULL REFERENCES delegations(id),
    expires_at TIMESTAMPTZ NULL,
    delegate_pubkey TEXT NOT NULL,
    slots JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
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

-- transactions the daemon built, kept until their successors exist
CREATE TABLE IF NOT EXISTS settlements (
    txid TEXT NOT NULL,
    -- what the indexer or the chain reports spending the coins
    spent_by TEXT NOT NULL,
    delegation_id BIGINT NOT NULL REFERENCES delegations(id) ON DELETE CASCADE,
    tx BYTEA NOT NULL,
    outpoints JSONB NOT NULL,
    sources BYTEA[] NOT NULL,
    coins TEXT[] NOT NULL,
    -- the unsigned checkpoints of an offchain tx the daemon submits itself
    checkpoints TEXT[] NOT NULL DEFAULT '{}',
    -- final checkpoints while arkd waits for FinalizeTx
    finals TEXT[] NOT NULL DEFAULT '{}',
    -- the transaction is known to have spent the coins: only the successors are left
    landed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (txid, spent_by)
);

CREATE INDEX IF NOT EXISTS idx_delegations_status ON delegations(status);
CREATE INDEX IF NOT EXISTS idx_delegations_template ON delegations(template_id);
CREATE INDEX IF NOT EXISTS idx_delegations_address ON delegations(address);
CREATE INDEX IF NOT EXISTS idx_delegations_parent ON delegations(parent_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_delegations_active_fingerprint ON delegations(fingerprint) WHERE status = 'active';
-- serves the newest row of a fingerprint: a cancelled one refuses registering it again
CREATE INDEX IF NOT EXISTS idx_delegations_fingerprint ON delegations(fingerprint, id DESC);
-- serves the "is this outpoint bound already" lookup at registration
CREATE INDEX IF NOT EXISTS idx_delegations_slots ON delegations USING GIN (slots jsonb_path_ops);
CREATE INDEX IF NOT EXISTS idx_templates_status ON templates(status);
CREATE INDEX IF NOT EXISTS idx_renewals_delegation ON renewals(delegation_id, attempted_at DESC);
CREATE INDEX IF NOT EXISTS idx_renewals_attempted_at ON renewals(attempted_at);
CREATE INDEX IF NOT EXISTS idx_settlements_delegation ON settlements(delegation_id);

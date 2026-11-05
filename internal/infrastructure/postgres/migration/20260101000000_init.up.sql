CREATE TABLE artifacts (
    id text PRIMARY KEY,
    document bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE templates (
    id text PRIMARY KEY,
    document bytea NOT NULL,
    artifact_ids text[] NOT NULL,
    params jsonb NOT NULL,
    type text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    failures int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX templates_status_idx ON templates (status);

CREATE TABLE streams (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    template_id text NOT NULL REFERENCES templates (id),
    variables jsonb NOT NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (template_id, variables)
);

CREATE INDEX streams_status_idx ON streams (status);

CREATE TABLE delegations (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    fingerprint text NOT NULL,
    address text NOT NULL DEFAULT '',
    template_id text NOT NULL REFERENCES templates (id),
    variables jsonb NOT NULL,
    inputs jsonb NOT NULL,
    stream_id bigint NULL REFERENCES streams (id),
    expires_at timestamptz NULL,
    status text NOT NULL DEFAULT 'active',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX delegations_status_idx ON delegations (status);
CREATE INDEX delegations_template_id_idx ON delegations (template_id);
CREATE INDEX delegations_address_idx ON delegations (address);
CREATE INDEX delegations_spawned_idx ON delegations (status, expires_at) WHERE stream_id IS NOT NULL;
CREATE UNIQUE INDEX delegations_active_fingerprint_idx ON delegations (fingerprint) WHERE status = 'active';
CREATE INDEX delegations_fingerprint_idx ON delegations (fingerprint, id DESC);

CREATE TABLE coins (
    outpoint text PRIMARY KEY,
    delegation_id bigint NOT NULL REFERENCES delegations (id) ON DELETE CASCADE,
    input int NOT NULL,
    script text NOT NULL,
    amount bigint NOT NULL,
    expiry timestamptz NULL,
    created_at timestamptz NOT NULL,
    due timestamptz NULL,
    status text NOT NULL,
    spent_by text NOT NULL DEFAULT '',
    onchain boolean NOT NULL DEFAULT false,
    height bigint NOT NULL DEFAULT 0,
    confirmations int NOT NULL DEFAULT 0,
    held boolean NOT NULL DEFAULT false,
    retry_at timestamptz NULL,
    ready_at timestamptz GENERATED ALWAYS AS (greatest(coalesce(due, 'epoch'), coalesce(retry_at, 'epoch'))) STORED,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX coins_delegation_id_idx ON coins (delegation_id);
CREATE INDEX coins_status_idx ON coins (status);
CREATE INDEX coins_script_idx ON coins (script) WHERE status = 'present';
CREATE INDEX coins_ready_idx ON coins (ready_at) WHERE status = 'present' AND NOT held;

-- the inputs of a delegation the daemon watches; only those of active delegations count
CREATE TABLE claims (
    delegation_id bigint NOT NULL REFERENCES delegations (id) ON DELETE CASCADE,
    input int NOT NULL,
    script text NOT NULL,
    onchain boolean NOT NULL,
    locktime bigint NOT NULL,
    PRIMARY KEY (delegation_id, input)
);

CREATE INDEX claims_script_idx ON claims (script);

CREATE TABLE script_status (
    script text PRIMARY KEY,
    status text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE attempts (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    delegation_id bigint NOT NULL REFERENCES delegations (id) ON DELETE CASCADE,
    coins text[] NOT NULL,
    txs jsonb NOT NULL DEFAULT '[]',
    status text NOT NULL,
    error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX attempts_delegation_id_idx ON attempts (delegation_id, id DESC);
CREATE INDEX attempts_status_idx ON attempts (status);

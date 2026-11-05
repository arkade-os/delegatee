-- name: InsertArtifact :one
INSERT INTO artifacts (id, document) VALUES (@id, @document) RETURNING *;

-- name: CountArtifacts :one
SELECT COUNT(*) FROM artifacts;

-- name: SelectArtifact :one
SELECT * FROM artifacts WHERE id = @id;

-- name: UpsertTemplate :one
INSERT INTO templates (id, document, artifact_ids, params, type, status, failures)
VALUES (@id, @document, @artifact_ids, @params, @type, @status, @failures)
ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status, failures = EXCLUDED.failures
RETURNING *;

-- name: CountTemplates :one
SELECT COUNT(*) FROM templates;

-- name: SelectTemplate :one
SELECT * FROM templates WHERE id = @id;

-- name: ListTemplates :many
SELECT id, artifact_ids, params, type, status, failures, created_at FROM templates
WHERE @status::text = '' OR status = @status::text
ORDER BY created_at DESC, id DESC;

-- name: DeleteTemplate :one
-- no row: not found; in_use: a delegation or a stream references the template, which then stays
WITH referenced AS (
    SELECT EXISTS (SELECT 1 FROM delegations WHERE template_id = @id::text)
        OR EXISTS (SELECT 1 FROM streams WHERE template_id = @id::text) AS in_use
), deleted AS (
    DELETE FROM templates WHERE templates.id = @id::text AND NOT (SELECT in_use FROM referenced)
)
SELECT referenced.in_use::boolean FROM templates, referenced WHERE templates.id = @id::text;

-- name: ListArtifacts :many
SELECT id, created_at FROM artifacts ORDER BY created_at DESC, id DESC;

-- name: DeleteArtifact :one
-- no row: not found; in_use: a template references the artifact, which then stays
WITH referenced AS (
    SELECT EXISTS (SELECT 1 FROM templates WHERE @id::text = ANY (artifact_ids)) AS in_use
), deleted AS (
    DELETE FROM artifacts WHERE artifacts.id = @id::text AND NOT (SELECT in_use FROM referenced)
)
SELECT referenced.in_use::boolean FROM artifacts, referenced WHERE artifacts.id = @id::text;

-- name: InsertDelegation :one
INSERT INTO delegations (fingerprint, address, template_id, variables, inputs, stream_id, expires_at)
VALUES (@fingerprint, @address, @template_id, @variables, @inputs, @stream_id, @expires_at)
RETURNING *;

-- name: SelectDelegation :one
SELECT * FROM delegations WHERE id = @id;

-- name: SelectDelegationByAddress :one
SELECT * FROM delegations WHERE address = @address ORDER BY (status = 'active') DESC, id DESC LIMIT 1;

-- name: SelectDelegationByFingerprint :one
SELECT * FROM delegations WHERE fingerprint = @fingerprint ORDER BY id DESC LIMIT 1;

-- name: CountActiveDelegations :one
SELECT COUNT(*) FILTER (WHERE stream_id IS NULL) AS clients, COUNT(*) FILTER (WHERE stream_id IS NOT NULL) AS spawned
FROM delegations WHERE status = 'active';

-- name: PruneDelegations :execrows
DELETE FROM delegations
WHERE stream_id IS NOT NULL AND status = 'expired' AND expires_at <= @before::timestamptz;

-- name: UpdateDelegationStatus :execrows
UPDATE delegations SET status = @status, updated_at = now() WHERE id = @id;

-- name: ExpireDelegations :many
UPDATE delegations SET status = 'expired', updated_at = now()
WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= @before::timestamptz
RETURNING *;

-- name: ListDelegations :many
SELECT * FROM delegations
WHERE (@status::text = '' OR status = @status::text)
  AND (@cursor::bigint = 0 OR id < @cursor::bigint)
ORDER BY id DESC
LIMIT @max_count::int;

-- name: ListDelegationSummaries :many
-- delegations holding present coins come first by their earliest due, then those holding none by id;
-- skip_held says the page starts among the latter, idle_after is the id it starts after; no coins is next_due at the epoch
WITH held AS (
    SELECT delegation_id, COUNT(*) AS coins, SUM(amount)::bigint AS amount, MIN(COALESCE(due, created_at))::timestamptz AS next_due
    FROM coins WHERE status = 'present' GROUP BY delegation_id
), with_coins AS (
    SELECT d.id, h.coins, h.amount, h.next_due FROM held h JOIN delegations d ON d.id = h.delegation_id
    WHERE NOT @skip_held::boolean AND (@status::text = '' OR d.status = @status::text)
      AND (h.next_due, d.id) > (@after_due::timestamptz, @after_id::bigint)
    ORDER BY h.next_due, d.id
    LIMIT @max_count::int
), idle AS (
    SELECT d.id, 0::bigint AS coins, 0::bigint AS amount, NULL::timestamptz AS next_due FROM delegations d
    WHERE d.id > @idle_after::bigint AND (@status::text = '' OR d.status = @status::text)
      AND NOT EXISTS (SELECT 1 FROM coins c WHERE c.delegation_id = d.id AND c.status = 'present')
    ORDER BY d.id
    LIMIT @max_count::int
), page AS (
    SELECT * FROM with_coins UNION ALL SELECT * FROM idle
    ORDER BY next_due NULLS LAST, id
    LIMIT @max_count::int
)
SELECT d.id, d.fingerprint, d.address, d.template_id, d.variables, d.inputs, d.stream_id, d.expires_at, d.status,
    d.created_at, d.updated_at, page.coins, page.amount, COALESCE(page.next_due, 'epoch'::timestamptz)::timestamptz AS next_due,
    COALESCE((SELECT a.status FROM attempts a WHERE a.delegation_id = d.id ORDER BY a.id DESC LIMIT 1), '')::text AS last_attempt
FROM page JOIN delegations d ON d.id = page.id
ORDER BY page.next_due NULLS LAST, d.id;

-- name: InsertStream :one
-- the stream of the same template and variables is returned as it is
WITH inserted AS (
    INSERT INTO streams (template_id, variables)
    VALUES (@template_id, @variables)
    ON CONFLICT (template_id, variables) DO NOTHING
    RETURNING *
)
SELECT * FROM inserted UNION ALL (SELECT * FROM streams WHERE template_id = @template_id AND variables = @variables) LIMIT 1;

-- name: SelectStream :one
SELECT * FROM streams WHERE id = @id;

-- name: ListStreams :many
SELECT * FROM streams WHERE @status::text = '' OR status = @status::text ORDER BY id;

-- name: UpdateStreamStatus :execrows
UPDATE streams SET status = @status WHERE id = @id;

-- name: UpsertCoin :exec
INSERT INTO coins (outpoint, delegation_id, input, script, amount, expiry, created_at, due, status, spent_by, onchain, height, confirmations)
VALUES (@outpoint, @delegation_id, @input, @script, @amount, @expiry, @created_at, @due, @status, @spent_by, @onchain, @height, @confirmations)
ON CONFLICT (outpoint) DO UPDATE SET
    delegation_id = EXCLUDED.delegation_id, input = EXCLUDED.input, amount = EXCLUDED.amount, expiry = EXCLUDED.expiry, created_at = EXCLUDED.created_at, due = EXCLUDED.due,
    status = EXCLUDED.status, spent_by = EXCLUDED.spent_by, height = EXCLUDED.height,
    confirmations = EXCLUDED.confirmations, updated_at = now();

-- name: ListCoinsByDelegation :many
SELECT * FROM coins WHERE delegation_id = @delegation_id ORDER BY created_at, outpoint;

-- name: ListCoinsAtScripts :many
SELECT * FROM coins WHERE script = ANY (@scripts::text[]) AND status = 'present' ORDER BY created_at, outpoint;

-- name: ListOnchainCoins :many
-- the present onchain coins of the active delegations
SELECT coins.* FROM coins JOIN delegations ON delegations.id = coins.delegation_id
WHERE coins.status = 'present' AND coins.onchain AND delegations.status = 'active';

-- name: MoveCoins :many
-- gives the present coins at script to the claim's delegation
UPDATE coins SET delegation_id = @delegation_id, input = @input, updated_at = now()
WHERE script = @script AND status = 'present' AND (delegation_id, input) <> (@delegation_id, @input)
RETURNING *;

-- name: ListStrandedScripts :many
-- the scripts an active delegation watches that hold present coins of an inactive one
SELECT DISTINCT coins.script FROM coins JOIN delegations ON delegations.id = coins.delegation_id
WHERE coins.status = 'present' AND delegations.status <> 'active' AND EXISTS (
    SELECT 1 FROM claims JOIN delegations a ON a.id = claims.delegation_id WHERE claims.script = coins.script AND a.status = 'active'
);

-- name: HoldCoins :exec
UPDATE coins SET held = true, updated_at = now() WHERE outpoint = ANY (@outpoints::text[]);

-- name: ReleaseCoins :exec
UPDATE coins SET held = false, retry_at = GREATEST(retry_at, @retry_at), updated_at = now() WHERE outpoint = ANY (@outpoints::text[]);

-- name: ResetHolds :exec
-- the coins held are those of the pending attempts; only the rows that disagree change
UPDATE coins SET held = NOT held, updated_at = now()
WHERE held <> EXISTS (
    SELECT 1 FROM attempts WHERE attempts.status NOT IN ('succeeded', 'failed') AND coins.outpoint = ANY (attempts.coins)
);

-- name: ListReadyCoins :many
-- the oldest coin ready by now at each input of the active delegations holding none, past the input's
-- locktime at the tip; only delegations with every input filled, at most max_count of them, by id then input
WITH picked AS (
    SELECT DISTINCT ON (coins.delegation_id, coins.input) coins.outpoint, coins.delegation_id
    FROM coins
    JOIN claims ON claims.delegation_id = coins.delegation_id AND claims.input = coins.input
    JOIN delegations ON delegations.id = coins.delegation_id
    WHERE coins.status = 'present' AND NOT coins.held AND coins.ready_at <= @now::timestamptz
      AND delegations.status = 'active'
      AND CASE WHEN claims.locktime >= 500000000 THEN claims.locktime <= @median_time::bigint ELSE claims.locktime <= @height::bigint END
      AND NOT EXISTS (SELECT 1 FROM coins h WHERE h.delegation_id = coins.delegation_id AND h.status = 'present' AND h.held)
    ORDER BY coins.delegation_id, coins.input, coins.created_at, coins.outpoint
), complete AS (
    SELECT picked.delegation_id FROM picked GROUP BY picked.delegation_id
    HAVING count(*) = (SELECT count(*) FROM claims WHERE claims.delegation_id = picked.delegation_id)
    ORDER BY picked.delegation_id
    LIMIT @max_count::int
)
SELECT coins.* FROM coins JOIN picked ON picked.outpoint = coins.outpoint
WHERE picked.delegation_id IN (SELECT delegation_id FROM complete)
ORDER BY coins.delegation_id, coins.input;

-- name: NextReadyAt :one
-- the earliest time after now a coin ListReadyCoins would consider becomes ready; no row when none will
SELECT coins.ready_at
FROM coins
JOIN claims ON claims.delegation_id = coins.delegation_id AND claims.input = coins.input
JOIN delegations ON delegations.id = coins.delegation_id
WHERE coins.status = 'present' AND NOT coins.held AND coins.ready_at > @now::timestamptz AND delegations.status = 'active'
  AND CASE WHEN claims.locktime >= 500000000 THEN claims.locktime <= @median_time::bigint ELSE claims.locktime <= @height::bigint END
  AND NOT EXISTS (SELECT 1 FROM coins h WHERE h.delegation_id = coins.delegation_id AND h.status = 'present' AND h.held)
ORDER BY coins.ready_at
LIMIT 1;

-- name: TotalPresentCoins :one
-- the present coins of active delegations and their amount
SELECT count(*)::int AS coins, coalesce(sum(coins.amount), 0)::bigint AS amount
FROM coins JOIN delegations ON delegations.id = coins.delegation_id
WHERE coins.status = 'present' AND delegations.status = 'active';

-- name: InsertClaim :exec
INSERT INTO claims (delegation_id, input, script, onchain, locktime) VALUES (@delegation_id, @input, @script, @onchain, @locktime);

-- name: ListClaimsAtScripts :many
-- the claims of the active delegations watching scripts
SELECT claims.script, claims.delegation_id, claims.input, claims.onchain, claims.locktime, (delegations.stream_id IS NOT NULL)::boolean AS spawned
FROM claims JOIN delegations ON delegations.id = claims.delegation_id
WHERE claims.script = ANY (@scripts::text[]) AND delegations.status = 'active'
ORDER BY claims.delegation_id, claims.input;

-- name: ListWatchedScripts :many
SELECT DISTINCT claims.script
FROM claims JOIN delegations ON delegations.id = claims.delegation_id
WHERE delegations.status = 'active' AND claims.onchain = @onchain
ORDER BY claims.script;

-- name: GetWatchedStatus :one
-- the stored status hash of script, and whether an active delegation watches it onchain
SELECT coalesce((SELECT status FROM script_status WHERE script_status.script = @script), '')::text AS status,
    EXISTS (
        SELECT 1 FROM claims JOIN delegations ON delegations.id = claims.delegation_id
        WHERE claims.script = @script AND claims.onchain AND delegations.status = 'active'
    ) AS watched;

-- name: UpsertScriptStatus :exec
INSERT INTO script_status (script, status) VALUES (@script, @status)
ON CONFLICT (script) DO UPDATE SET status = EXCLUDED.status, updated_at = now();

-- name: InsertAttempt :one
INSERT INTO attempts (delegation_id, coins, txs, status, error)
VALUES (@delegation_id, @coins, @txs, @status, @error)
RETURNING *;

-- name: UpdateAttempt :execrows
UPDATE attempts SET txs = @txs, status = @status, error = @error, updated_at = now() WHERE id = @id;

-- name: ListPendingAttempts :many
SELECT * FROM attempts WHERE status NOT IN ('succeeded', 'failed') ORDER BY id;

-- name: ListAttemptsByDelegation :many
SELECT * FROM attempts
WHERE delegation_id = @delegation_id AND (@cursor::bigint = 0 OR id < @cursor::bigint)
ORDER BY id DESC
LIMIT @max_count::int;

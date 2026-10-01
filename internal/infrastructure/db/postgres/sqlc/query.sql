-- name: InsertDelegation :one
-- no row: max_active (0 = uncapped) active delegations exist and none has the fingerprint
WITH inserted AS (
    INSERT INTO delegations (fingerprint, address, template_id, variables, parent_id, expires_at, delegate_pubkey, slots)
    SELECT @fingerprint::text, @address::text, @template_id::text, @variables::jsonb, sqlc.narg(parent_id)::bigint,
        sqlc.narg(expires_at)::timestamptz, @delegate_pubkey::text, @slots::jsonb
    WHERE @max_active::int = 0 OR (SELECT COUNT(*) FROM delegations WHERE status = 'active') < @max_active::int
    -- only active rows are unique: a stopped instance registered again is a new row
    ON CONFLICT (fingerprint) WHERE status = 'active' DO UPDATE SET fingerprint = EXCLUDED.fingerprint
    RETURNING *
)
SELECT * FROM inserted
UNION ALL (SELECT * FROM delegations WHERE fingerprint = @fingerprint AND status = 'active')
LIMIT 1;

-- name: SelectDelegation :one
SELECT * FROM delegations WHERE address = @address
ORDER BY (status = 'active') DESC, created_at DESC, id DESC
LIMIT 1;

-- name: SelectDelegationByID :one
SELECT * FROM delegations WHERE id = @id;

-- name: SelectLatestDelegationByFingerprint :one
SELECT * FROM delegations WHERE fingerprint = @fingerprint ORDER BY id DESC LIMIT 1;

-- name: SelectActiveDelegationByOutpoint :one
SELECT * FROM delegations
WHERE status = 'active' AND slots @> jsonb_build_array(jsonb_build_object('outpoint', @outpoint::text))
LIMIT 1;

-- name: SelectDelegations :many
SELECT * FROM delegations
WHERE sqlc.arg(status)::text = '' OR status = sqlc.arg(status)::text
ORDER BY created_at DESC, id DESC;

-- name: SelectDelegationPage :many
SELECT * FROM delegations
WHERE (sqlc.arg(status)::text = '' OR status = sqlc.arg(status)::text)
    AND (sqlc.arg(cursor)::bigint = 0 OR id < sqlc.arg(cursor)::bigint)
ORDER BY id DESC
LIMIT sqlc.arg(max_rows);

-- name: CountActiveDelegations :one
SELECT COUNT(*) FROM delegations WHERE status = 'active';

-- name: CountDelegationsByTemplate :many
SELECT template_id, COUNT(*) AS n FROM delegations GROUP BY template_id;

-- name: SetDelegationStatus :execrows
UPDATE delegations SET status = @status, updated_at = NOW() WHERE id = @id AND status = 'active';

-- name: ExpireDelegations :execrows
UPDATE delegations SET status = 'expired', updated_at = NOW()
WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= @before;

-- name: ResumeDelegation :execrows
UPDATE delegations SET status = 'active', updated_at = NOW() WHERE id = @id AND status = 'cancelled';

-- name: InsertRenewal :exec
INSERT INTO renewals (delegation_id, outpoints, commitment_txid, success, error)
VALUES (@delegation_id, @outpoints, @commitment_txid, @success, @error);

-- name: SelectRenewals :many
SELECT * FROM renewals
WHERE delegation_id = @delegation_id
ORDER BY attempted_at DESC
LIMIT @max_rows;

-- name: SelectLastRenewals :many
SELECT DISTINCT ON (delegation_id) * FROM renewals
ORDER BY delegation_id, attempted_at DESC;

-- name: DeleteRenewalsBefore :exec
DELETE FROM renewals r WHERE r.attempted_at < @before
    -- a failure is stored once: keep it while it is the delegation's latest state
    AND EXISTS (SELECT 1 FROM renewals newer
                WHERE newer.delegation_id = r.delegation_id AND newer.attempted_at > r.attempted_at);

-- name: UpsertSettlement :exec
INSERT INTO settlements (txid, spent_by, delegation_id, tx, outpoints, sources, coins, checkpoints, finals, landed)
VALUES (@txid, @spent_by, @delegation_id, @tx, @outpoints, @sources, @coins, @checkpoints, @finals, @landed)
ON CONFLICT (txid, spent_by) DO UPDATE SET finals = EXCLUDED.finals, landed = EXCLUDED.landed;

-- name: SelectSettlements :many
SELECT * FROM settlements ORDER BY created_at;

-- name: DeleteSettlement :exec
DELETE FROM settlements WHERE txid = @txid AND spent_by = @spent_by;

-- name: UpsertArtifact :one
-- no row: max_count (0 = uncapped) artifacts exist and none has the id
WITH inserted AS (
    INSERT INTO artifacts (id, document)
    SELECT @id::text, @document::bytea
    WHERE @max_count::int = 0 OR (SELECT COUNT(*) FROM artifacts) < @max_count::int
    ON CONFLICT (id) DO UPDATE SET id = artifacts.id
    RETURNING *
)
SELECT * FROM inserted UNION ALL (SELECT * FROM artifacts WHERE id = @id) LIMIT 1;

-- name: SelectArtifact :one
SELECT * FROM artifacts WHERE id = @id;

-- name: ArtifactReferenced :one
SELECT EXISTS (SELECT 1 FROM templates WHERE @id::text = ANY(artifact_ids));

-- name: DeleteArtifact :execrows
DELETE FROM artifacts WHERE id = @id;

-- name: SelectArtifactSummaries :many
SELECT id, created_at FROM artifacts ORDER BY created_at DESC;

-- name: UpsertTemplate :one
-- no row: max_count (0 = uncapped) templates exist and none has the id
WITH inserted AS (
    INSERT INTO templates (id, document, artifact_ids, params)
    SELECT @id::text, @document::bytea, @artifact_ids::text[], @params::jsonb
    WHERE @max_count::int = 0 OR (SELECT COUNT(*) FROM templates) < @max_count::int
    ON CONFLICT (id) DO UPDATE SET id = templates.id
    RETURNING *
)
SELECT * FROM inserted UNION ALL (SELECT * FROM templates WHERE id = @id) LIMIT 1;

-- name: SelectTemplate :one
SELECT * FROM templates WHERE id = @id;

-- name: SelectTemplateSummaries :many
SELECT id, artifact_ids, params, status, failures, trusted, created_at FROM templates
WHERE sqlc.arg(status)::text = '' OR status = sqlc.arg(status)::text
ORDER BY created_at DESC;

-- name: SetTemplateStatus :execrows
UPDATE templates
SET status = @status,
    failures = CASE WHEN @status = 'active' THEN 0 ELSE failures END,
    updated_at = NOW()
WHERE id = @id;

-- name: SetTemplateTrusted :execrows
UPDATE templates SET trusted = @trusted, updated_at = NOW() WHERE id = @id;

-- name: TemplateReferenced :one
SELECT EXISTS (SELECT 1 FROM delegations WHERE template_id = @id);

-- name: DeleteTemplate :execrows
DELETE FROM templates WHERE id = @id;

-- name: RecordTemplateOutcome :one
UPDATE templates
SET failures = CASE WHEN @success::boolean THEN 0 ELSE failures + 1 END,
    status = CASE WHEN NOT @success::boolean AND failures + 1 >= @max_failures::int THEN 'disabled' ELSE status END,
    updated_at = NOW()
WHERE id = @id
RETURNING failures, status;

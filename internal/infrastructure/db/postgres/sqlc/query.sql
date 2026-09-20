-- name: UpsertDelegation :one
INSERT INTO delegations (address, tapscripts, renewal_window, max_fee)
VALUES (@address, @tapscripts, @renewal_window, @max_fee)
ON CONFLICT (address) DO UPDATE SET status = 'active', updated_at = NOW()
    WHERE delegations.status <> 'active'
RETURNING *;

-- name: SelectDelegation :one
SELECT * FROM delegations WHERE address = @address;

-- name: SelectDelegations :many
SELECT * FROM delegations
WHERE sqlc.arg(status)::text = '' OR status = sqlc.arg(status)::text
ORDER BY created_at DESC;

-- name: CountActiveDelegations :one
SELECT COUNT(*) FROM delegations WHERE status = 'active';

-- name: CancelDelegation :execrows
UPDATE delegations SET status = @status, updated_at = NOW() WHERE address = @address;

-- name: RevokeDelegation :execrows
UPDATE delegations
SET status = 'revoked', last_revocation_timestamp = @timestamp, updated_at = NOW()
WHERE address = @address AND last_revocation_timestamp < @timestamp;

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

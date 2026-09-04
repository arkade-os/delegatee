-- name: UpsertDelegation :one
INSERT INTO delegations (address, tapscripts, renewal_window)
VALUES (@address, @tapscripts, @renewal_window)
ON CONFLICT (address) DO UPDATE SET status = 'active', updated_at = NOW()
    WHERE delegations.status = 'cancelled'
RETURNING *;

-- name: SelectDelegation :one
SELECT * FROM delegations WHERE address = @address;

-- name: SelectDelegations :many
SELECT * FROM delegations
WHERE sqlc.arg(status)::text = '' OR status = sqlc.arg(status)::text
ORDER BY created_at DESC;

-- name: CancelDelegation :execrows
UPDATE delegations SET status = 'cancelled', updated_at = NOW() WHERE address = @address;

-- name: InsertRenewal :exec
INSERT INTO renewals (delegation_id, outpoints, commitment_txid, success, error)
VALUES (@delegation_id, @outpoints, @commitment_txid, @success, @error);

-- name: SelectRenewals :many
SELECT * FROM renewals
WHERE delegation_id = @delegation_id
ORDER BY attempted_at DESC
LIMIT @max_rows;

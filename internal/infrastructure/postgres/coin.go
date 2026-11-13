package postgres

import (
	"context"
	"database/sql"
	"errors"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/infrastructure/postgres/sqlc/queries"
)

type CoinRepository struct{ db *DB }

func (d *DB) Coins() *CoinRepository { return &CoinRepository{db: d} }

func (r *CoinRepository) Upsert(ctx context.Context, coins ...delegation.Coin) error {
	if len(coins) == 0 {
		return nil
	}
	return r.db.inTx(ctx, func(q *queries.Queries) error {
		for _, c := range coins {
			err := q.UpsertCoin(ctx, queries.UpsertCoinParams{
				Outpoint:     c.Outpoint,
				DelegationID: c.DelegationID,
				Input:        int32(c.Input),
				Script:       c.Script,
				Amount: int64(
					c.Amount,
				),
				Expiry:    nullTime(c.ExpiresAt),
				CreatedAt: c.CreatedAt,
				Due:       nullTime(c.Due),
				Status: string(
					c.Status,
				),
				SpentBy:       c.SpentBy,
				Onchain:       c.Onchain,
				Height:        c.Height,
				Confirmations: int32(c.Confirmations),
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (r *CoinRepository) ListByDelegation(
	ctx context.Context, id int64,
) ([]delegation.Coin, error) {
	rows, err := r.db.querier.ListCoinsByDelegation(ctx, id)
	return toCoins(rows), err
}

func (r *CoinRepository) ScriptStatus(ctx context.Context, script string) (string, bool, error) {
	row, err := r.db.querier.GetWatchedStatus(ctx, script)
	return row.Status, row.Watched, err
}

func (r *CoinRepository) SetScriptStatus(ctx context.Context, script, status string) error {
	return r.db.querier.UpsertScriptStatus(
		ctx, queries.UpsertScriptStatusParams{Script: script, Status: status},
	)
}

func (r *CoinRepository) Move(
	ctx context.Context, script string, owner delegation.Claim,
) ([]delegation.Coin, error) {
	rows, err := r.db.querier.MoveCoins(
		ctx,
		queries.MoveCoinsParams{
			Script: script, DelegationID: owner.DelegationID, Input: int32(owner.Input),
		},
	)
	return toCoins(rows), err
}

func (r *CoinRepository) Hold(ctx context.Context, outpoints []string) error {
	return r.db.querier.HoldCoins(ctx, outpoints)
}

func (r *CoinRepository) Release(ctx context.Context, outpoints []string, readyAt time.Time) error {
	return r.db.querier.ReleaseCoins(
		ctx, queries.ReleaseCoinsParams{RetryAt: nullTime(readyAt), Outpoints: outpoints},
	)
}

func (r *CoinRepository) ResetHolds(ctx context.Context) error {
	return r.db.querier.ResetHolds(ctx)
}

func (r *CoinRepository) Ready(
	ctx context.Context, now time.Time, tip delegation.Tip, limit int,
) ([][]delegation.Coin, error) {
	rows, err := r.db.querier.ListReadyCoins(ctx, queries.ListReadyCoinsParams{
		Now: now, MedianTime: tip.MedianTime.Unix(), Height: tip.Height, MaxCount: int32(limit),
	})
	if err != nil {
		return nil, err
	}
	var out [][]delegation.Coin
	for _, c := range toCoins(rows) {
		if n := len(out); n == 0 || out[n-1][0].DelegationID != c.DelegationID {
			out = append(out, nil)
		}
		out[len(out)-1] = append(out[len(out)-1], c)
	}
	return out, nil
}

func (r *CoinRepository) NextReady(
	ctx context.Context, now time.Time, tip delegation.Tip,
) (time.Time, error) {
	at, err := r.db.querier.NextReadyAt(
		ctx,
		queries.NextReadyAtParams{Now: now, MedianTime: tip.MedianTime.Unix(), Height: tip.Height},
	)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return at.Time.UTC(), err
}

func (r *CoinRepository) Totals(ctx context.Context) (int, uint64, error) {
	row, err := r.db.querier.TotalPresentCoins(ctx)
	return int(row.Coins), uint64(row.Amount), err
}

func (r *CoinRepository) Watched(
	ctx context.Context, scripts []string,
) ([]delegation.Watched, error) {
	claims, err := r.db.querier.ListClaimsAtScripts(ctx, scripts)
	if err != nil || len(claims) == 0 {
		return nil, err
	}
	coins, err := r.db.querier.ListCoinsAtScripts(ctx, scripts)
	if err != nil {
		return nil, err
	}
	byScript := map[string]*delegation.Watched{}
	for _, row := range claims {
		w := byScript[row.Script]
		if w == nil {
			w = &delegation.Watched{Script: row.Script}
			byScript[row.Script] = w
		}
		w.Claims = append(w.Claims, delegation.Claim{
			DelegationID: row.DelegationID, Input: int(row.Input), Onchain: row.Onchain,
			Spawned: row.Spawned, Locktime: arklib.AbsoluteLocktime(row.Locktime),
		})
	}
	for _, c := range toCoins(coins) {
		if w := byScript[c.Script]; w != nil {
			w.Coins = append(w.Coins, c)
		}
	}
	out := make([]delegation.Watched, 0, len(byScript))
	for _, script := range scripts {
		if w := byScript[script]; w != nil {
			out = append(out, *w)
			delete(byScript, script)
		}
	}
	return out, nil
}

func (r *CoinRepository) Stranded(ctx context.Context) ([]string, error) {
	return r.db.querier.ListStrandedScripts(ctx)
}

func (r *CoinRepository) Onchain(ctx context.Context) ([]delegation.Coin, error) {
	rows, err := r.db.querier.ListOnchainCoins(ctx)
	return toCoins(rows), err
}

func (r *CoinRepository) Scripts(ctx context.Context, onchain bool) ([]string, error) {
	return r.db.querier.ListWatchedScripts(ctx, onchain)
}

func toCoins(rows []queries.Coin) []delegation.Coin {
	out := make([]delegation.Coin, 0, len(rows))
	for _, row := range rows {
		out = append(out, delegation.Coin{
			Outpoint:     row.Outpoint,
			DelegationID: row.DelegationID,
			Input:        int(row.Input),
			Script:       row.Script,
			Amount: uint64(
				row.Amount,
			),
			ExpiresAt: row.Expiry.Time.UTC(),
			CreatedAt: row.CreatedAt.UTC(),
			Due:       row.Due.Time.UTC(),
			Status: delegation.CoinStatus(
				row.Status,
			),
			SpentBy:       row.SpentBy,
			Onchain:       row.Onchain,
			Height:        row.Height,
			Confirmations: int(row.Confirmations),
		})
	}
	return out
}

func nullTime(t time.Time) sql.NullTime { return sql.NullTime{Time: t, Valid: !t.IsZero()} }

package execution

import (
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/ports"
)

// syncVtxos is the coins the vtxos reported at w's script add or spend; when complete, the report
// lists every vtxo there and a coin missing from it is spent. A new coin's due time is left zero.
func syncVtxos(w delegation.Watched, vtxos []ports.Output, complete bool) []delegation.Coin {
	known := byOutpoint(w.Coins)
	listed := map[string]bool{}
	var changes []delegation.Coin
	for _, v := range vtxos {
		if v.Script != w.Script {
			continue
		}
		listed[v.Outpoint] = true
		c, ok := known[v.Outpoint]
		switch {
		case ok && v.Spent:
			delete(known, v.Outpoint)
			changes = append(changes, spend(c, v.SpentBy))
		case !ok && !v.Spent:
			owner := w.Owner()
			c = delegation.Coin{
				Outpoint: v.Outpoint, DelegationID: owner.DelegationID, Input: owner.Input, Script: v.Script, Amount: v.Amount,
				ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt, Status: delegation.Present,
			}
			known[c.Outpoint] = c
			changes = append(changes, c)
		}
	}
	if complete {
		for _, c := range w.Coins {
			if _, ok := known[c.Outpoint]; ok && !listed[c.Outpoint] {
				changes = append(changes, spend(c, ""))
			}
		}
	}
	return changes
}

// syncUtxos is the coins the utxos listed at w's script add, move or spend; the listing is complete.
// A due time to ask again is left zero.
func syncUtxos(w delegation.Watched, utxos []ports.Output, tip delegation.Tip, now time.Time) []delegation.Coin {
	known := byOutpoint(w.Coins)
	listed := map[string]bool{}
	var changes []delegation.Coin
	for _, u := range utxos {
		if u.Script != w.Script {
			continue
		}
		listed[u.Outpoint] = true
		if old, ok := known[u.Outpoint]; ok {
			if c, changed := refresh(old, u.Height, tip, now); changed {
				changes = append(changes, c)
			}
			continue
		}
		owner := w.Owner()
		c := delegation.Coin{
			Outpoint: u.Outpoint, DelegationID: owner.DelegationID, Input: owner.Input, Script: u.Script, Amount: u.Amount,
			Status: delegation.Present, Onchain: true, Height: u.Height, Confirmations: tip.Confirmations(u.Height),
		}
		c.CreatedAt = blockTime(c, tip)
		changes = append(changes, c)
	}
	for _, c := range w.Coins {
		if !listed[c.Outpoint] {
			changes = append(changes, spend(c, ""))
		}
	}
	return changes
}

// refresh moves an onchain coin to height at tip; its due time is left zero, to ask again, while it is
// not due yet or when its height changed. The flag says the coin changed.
func refresh(c delegation.Coin, height int64, tip delegation.Tip, now time.Time) (delegation.Coin, bool) {
	next := c
	next.Height, next.Confirmations = height, tip.Confirmations(height)
	next.CreatedAt = blockTime(next, tip)
	if c.Due.After(now) || height != c.Height {
		next.Due = time.Time{}
	}
	return next, next.Height != c.Height || next.Confirmations != c.Confirmations || !next.Due.Equal(c.Due) || !next.CreatedAt.Equal(c.CreatedAt)
}

// blockTime is the coin's creation time: the tip's when the coin was mined in it, else what it had.
func blockTime(c delegation.Coin, tip delegation.Tip) time.Time {
	if c.CreatedAt.IsZero() && c.Height > 0 && c.Height == tip.Height {
		return tip.Time
	}
	return c.CreatedAt
}

func spend(c delegation.Coin, by string) delegation.Coin {
	c.Status, c.SpentBy = delegation.Spent, by
	return c
}

func byOutpoint(coins []delegation.Coin) map[string]delegation.Coin {
	known := make(map[string]delegation.Coin, len(coins))
	for _, c := range coins {
		known[c.Outpoint] = c
	}
	return known
}

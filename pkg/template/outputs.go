package template

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"slices"
)

// 21 million bitcoin in satoshis
const maxAmount = 21e14

type allocation struct {
	sats   []uint64            // per output, template order
	assets []map[string]uint64 // per output: hex asset id → amount
	fee    uint64
}

// allocate balances every pool separately; fee goes to fees.from's pool and dust is the minimum output.
func (i *Instance) allocate(d *draft, sources []*Source, fee uint64, dust uint64) (*allocation, error) {
	t := i.tmpl
	feeCap, _ := i.FeeCap()
	switch {
	case fee > 0 && t.fee == nil:
		return nil, fmt.Errorf("%w: the template pays no fee, asked %d", ErrIneligible, fee)
	case t.fee != nil && fee > feeCap:
		return nil, fmt.Errorf("%w: fee %d exceeds the cap %d", ErrIneligible, fee, feeCap)
	case len(sources) != len(t.inputs):
		return nil, fmt.Errorf("%w: %d sources for %d inputs", ErrIneligible, len(sources), len(t.inputs))
	}
	if k := slices.Index(sources, nil); k >= 0 {
		return nil, fmt.Errorf("%w: input %q has no source", ErrIneligible, t.inputs[k].name)
	}
	a := &allocation{sats: make([]uint64, len(t.outputs)), assets: make([]map[string]uint64, len(t.outputs)), fee: fee}
	for k := range a.assets {
		a.assets[k] = map[string]uint64{}
	}
	for slot, s := range sources {
		name := t.inputs[slot].name
		if s.Amount > maxAmount {
			return nil, fmt.Errorf("%w: input %q holds more than 21e14 satoshis", ErrIneligible, name)
		}
		held := map[string]uint64{}
		for _, as := range s.Assets {
			if len(as.ID) != 34 {
				return nil, fmt.Errorf("%w: input %q holds an asset id of %d bytes", ErrIneligible, name, len(as.ID))
			}
			if err := credit(held, hex.EncodeToString(as.ID), as.Amount); err != nil {
				return nil, fmt.Errorf("input %q: %w", name, err)
			}
		}

		if pool := t.poolOf(slot); pool[0] == slot {
			var sum uint64
			for _, k := range pool {
				sum += sources[k].Amount
			}
			if err := i.routeSats(d, pool, sum, dust, a); err != nil {
				return nil, err
			}
		}
		if err := i.routeAssets(d, slot, held, a); err != nil {
			return nil, err
		}
		for key, n := range held {
			if n > 0 {
				return nil, fmt.Errorf("%w: input %q has %d of asset %s without a route", ErrIneligible, name, n, key)
			}
		}
	}
	return a, nil
}

func (i *Instance) routeSats(d *draft, pool []int, amount, dust uint64, a *allocation) error {
	t := i.tmpl
	left := amount
	for k, o := range t.outputs {
		if !slices.Equal(o.pool, pool) || o.amount == nil {
			continue
		}
		n, err := i.fixedAmount(o.amount, d, o.from)
		if err != nil {
			return fmt.Errorf("output %q: %w", o.name, err)
		}
		if n > left || n < dust {
			return fmt.Errorf("%w: output %q draws %d of %d left, minimum %d", ErrIneligible, o.name, n, left, dust)
		}
		left -= n
		a.sats[k] = n
	}
	if t.fee != nil && slices.Contains(pool, t.fee.from) {
		if a.fee > left {
			return fmt.Errorf("%w: input %q cannot pay fee %d", ErrIneligible, t.inputs[t.fee.from].name, a.fee)
		}
		left -= a.fee
	}
	for k, o := range t.outputs {
		if slices.Equal(o.pool, pool) && o.amount == nil {
			if left < dust {
				return fmt.Errorf("%w: output %q remainder %d below %d", ErrIneligible, o.name, left, dust)
			}
			a.sats[k] = left
		}
	}
	return nil
}

// routeAssets credits fixed amounts, then named remainders, then the catch-all; what stays in held has no route.
func (i *Instance) routeAssets(d *draft, slot int, held map[string]uint64, a *allocation) error {
	for pass := range 3 {
		for k, o := range i.tmpl.outputs {
			for _, r := range o.assets {
				if r.from != slot || pass != routePass(r) {
					continue
				}
				key := hex.EncodeToString(r.asset)
				var err error
				switch pass {
				case 0:
					var n uint64
					if n, err = i.fixedAmount(r.amount, d, o.from); err != nil {
						return fmt.Errorf("output %q asset %s: %w", o.name, key, err)
					}
					if n > held[key] {
						return fmt.Errorf("%w: output %q draws %d of asset %s, input %q holds %d", ErrIneligible, o.name, n, key, i.tmpl.inputs[slot].name, held[key])
					}
					held[key] -= n
					err = credit(a.assets[k], key, n)
				case 1:
					err = credit(a.assets[k], key, held[key])
					delete(held, key)
				case 2:
					for key, n := range held {
						if err = credit(a.assets[k], key, n); err != nil {
							break
						}
					}
					clear(held)
				}
				if err != nil {
					return fmt.Errorf("output %q: %w", o.name, err)
				}
			}
		}
	}
	return nil
}

func routePass(r assetRoute) int {
	switch {
	case r.amount != nil:
		return 0
	case r.asset != nil:
		return 1
	}
	return 2
}

// credit leaves zero out of m.
func credit(m map[string]uint64, key string, n uint64) error {
	if n == 0 {
		return nil
	}
	sum, carry := bits.Add64(m[key], n, 0)
	if carry != 0 {
		return fmt.Errorf("%w: asset %s overflows", ErrIneligible, key)
	}
	m[key] = sum
	return nil
}

// fixedAmount requires a positive amount.
func (i *Instance) fixedAmount(b byteTemplate, d *draft, slot int) (uint64, error) {
	raw, err := i.resolve(b, d, d.index(slot))
	if err != nil {
		if !errors.Is(err, ErrIneligible) {
			err = fmt.Errorf("%w: %w", ErrIneligible, err)
		}
		return 0, err
	}
	n, err := parseScriptNum(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: amount of %d bytes is not a positive number", ErrIneligible, len(raw))
	}
	return uint64(n), nil
}

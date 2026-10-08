package template

import (
	"bytes"
	"encoding/hex"
	"math"
	"slices"
)

func (p *parser) output(v any) error {
	m, err := object(ErrInvalidTemplate, v, "output", []string{"name", "index", "value", "locking"}, "type", "assets")
	if err != nil {
		return err
	}
	o := output{}
	if o.name, err = p.slotName(m["name"], "output", slices.ContainsFunc(p.t.outputs, func(x output) bool { return x.name == m["name"] })); err != nil {
		return err
	}
	if o.onchain, err = p.slotType(m); err != nil {
		return err
	}
	idx, err := integer(m["index"], "index", 0, math.MaxUint16)
	if err != nil {
		return err
	}
	o.index = uint16(idx)
	vm, err := object(ErrInvalidTemplate, m["value"], "value", []string{"from"}, "amount")
	if err != nil {
		return err
	}
	if o.pool, err = p.pool(vm["from"]); err != nil {
		return err
	}
	o.from = o.pool[0]
	if raw, ok := vm["amount"]; ok {
		if o.amount, err = p.amount(raw); err != nil {
			return err
		}
	}
	if o.locking, err = p.locking(m["locking"]); err != nil {
		return err
	}
	assets, err := list(m, "assets")
	if err != nil {
		return err
	}
	if len(assets) > maxSlots {
		return bad("output %q has more than %d asset routes", o.name, maxSlots)
	}
	if len(assets) > 0 && (o.onchain || slices.ContainsFunc(o.pool, func(i int) bool { return p.t.inputs[i].onchain })) {
		return bad("output %q cannot carry assets", o.name)
	}
	for _, a := range assets {
		r, err := p.route(a)
		if err != nil {
			return err
		}
		if slices.ContainsFunc(o.assets, r.sameAsset) {
			return bad("output %q routes an asset of an input twice", o.name)
		}
		o.assets = append(o.assets, r)
	}
	p.t.outputs = append(p.t.outputs, o)
	return nil
}

// pool reads one input name or a list of them.
func (p *parser) pool(v any) ([]int, error) {
	names, ok := v.([]any)
	if !ok {
		i, err := p.inputIndex(v, "value")
		return []int{i}, err
	}
	if len(names) == 0 {
		return nil, bad("value names no input")
	}
	var pool []int
	for _, n := range names {
		i, err := p.inputIndex(n, "value")
		if err != nil {
			return nil, err
		}
		if slices.Contains(pool, i) {
			return nil, bad("value names input %q twice", n)
		}
		pool = append(pool, i)
	}
	slices.Sort(pool)
	return pool, nil
}

func (p *parser) locking(v any) (locking, error) {
	l := locking{from: -1}
	var err error
	if _, ok := v.(string); ok {
		l.script, err = p.bind(v, "", true)
		return l, err
	}
	m, err := object(ErrInvalidTemplate, v, "locking", nil, "from", "contract")
	if err != nil {
		return l, err
	}
	switch {
	case len(m) != 1:
		return l, bad("locking has exactly one of from and contract")
	case m["from"] != nil:
		l.from, err = p.inputIndex(m["from"], "locking")
	default:
		l.contract, err = p.construction(m["contract"])
	}
	return l, err
}

func (p *parser) route(v any) (assetRoute, error) {
	r := assetRoute{}
	m, err := object(ErrInvalidTemplate, v, "asset route", []string{"from"}, "asset", "amount")
	if err != nil {
		return r, err
	}
	if r.from, err = p.inputIndex(m["from"], "asset route"); err != nil {
		return r, err
	}
	if p.t.inputs[r.from].onchain {
		return r, bad("onchain input %q carries no assets", p.t.inputs[r.from].name)
	}
	if raw, ok := m["asset"]; ok {
		s, _ := raw.(string)
		if !assetHex.MatchString(s) {
			return r, bad("bad asset id %v", raw)
		}
		r.asset, _ = hex.DecodeString(s)
	}
	if raw, ok := m["amount"]; ok {
		if r.asset == nil {
			return r, bad("an asset amount needs an asset")
		}
		r.amount, err = p.amount(raw)
	}
	return r, err
}

// checkBalances: one pool per input, one remainder output per pool, one remainder route per input and asset.
func (t *Template) checkBalances() error {
	for i, in := range t.inputs {
		pool := t.poolOf(i)
		n := 0
		for _, o := range t.outputs {
			if !slices.Contains(o.pool, i) {
				continue
			}
			if !slices.Equal(o.pool, pool) {
				return bad("input %q shares its value with two sets of inputs", in.name)
			}
			if o.amount == nil {
				n++
			}
		}
		if n != 1 {
			return bad("input %q needs exactly one remainder output, has %d", in.name, n)
		}
	}
	var remainders []assetRoute
	for _, o := range t.outputs {
		for _, r := range o.assets {
			if r.amount != nil {
				continue
			}
			if slices.ContainsFunc(remainders, r.sameAsset) {
				return bad("input %q has two remainder routes for one asset", t.inputs[r.from].name)
			}
			remainders = append(remainders, r)
		}
	}
	return nil
}

// poolOf is nil when no output draws from slot.
func (t *Template) poolOf(slot int) []int {
	for _, o := range t.outputs {
		if slices.Contains(o.pool, slot) {
			return o.pool
		}
	}
	return nil
}

// checkPlacement requires indexes 0..n-1 once, laid out as offchain outputs, extension, onchain outputs.
func (t *Template) checkPlacement() error {
	var idx []int
	offchain := 0
	for _, o := range t.outputs {
		idx = append(idx, int(o.index))
		if !o.onchain {
			offchain++
		}
	}
	if t.packets != nil {
		idx = append(idx, int(t.packets.index))
	}
	slices.Sort(idx)
	for i, n := range idx {
		if n != i {
			return bad("output indexes must fill 0..%d once", len(idx)-1)
		}
	}
	if t.typ != Intent {
		return nil
	}
	for _, o := range t.outputs {
		if o.onchain == (int(o.index) < offchain) {
			return bad("an intent places offchain outputs, the extension, then onchain outputs")
		}
	}
	if t.packets != nil && int(t.packets.index) != offchain {
		return bad("an intent places its extension after the offchain outputs")
	}
	return nil
}

func (r assetRoute) sameAsset(x assetRoute) bool {
	return r.from == x.from && bytes.Equal(r.asset, x.asset)
}

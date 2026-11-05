package template

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math/bits"
	"slices"

	"github.com/arkade-os/delegatee/pkg/template/internal/asm"
	"github.com/arkade-os/delegatee/pkg/template/internal/contract"
	"github.com/arkade-os/delegatee/pkg/template/internal/schema"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/txscript/v2"
)

type locking struct {
	from     int          // input index, -1 when unused
	script   byteTemplate // set when the locking is a script template
	contract *construction
}

type output struct {
	name    string
	index   uint16
	onchain bool
	from    int          // the input it draws from
	amount  byteTemplate // nil: the remainder
	locking locking
	assets  []assetRoute
}

func (c *compiler) output(s *schema.Output) error {
	if slices.ContainsFunc(c.t.outputs, func(x output) bool { return x.name == s.Name }) {
		return bad("duplicate output %q", s.Name)
	}
	o := output{name: s.Name, index: uint16(s.Index)}
	var err error
	if o.onchain, err = c.slotType(s.Type); err != nil {
		return err
	}
	if o.from, err = c.inputIndex(s.Value.From, "value"); err != nil {
		return err
	}
	if s.Value.Amount != nil {
		if o.amount, err = c.amount(*s.Value.Amount); err != nil {
			return err
		}
	}
	if o.locking, err = c.locking(s.Locking); err != nil {
		return err
	}
	if len(s.Assets) > 0 && (o.onchain || c.t.inputs[o.from].onchain) {
		return bad("output %q cannot carry assets", o.name)
	}
	for i := range s.Assets {
		r, err := c.route(&s.Assets[i])
		if err != nil {
			return err
		}
		if slices.ContainsFunc(o.assets, r.sameAsset) {
			return bad("output %q routes an asset of an input twice", o.name)
		}
		o.assets = append(o.assets, r)
	}
	c.t.outputs = append(c.t.outputs, o)
	return nil
}

func (c *compiler) locking(s schema.Locking) (locking, error) {
	l := locking{from: -1}
	var err error
	switch {
	case s.Script != nil:
		l.script, err = c.bind(*s.Script, "", true)
	case s.Contract != nil:
		l.contract, err = c.construction(s.Contract)
		if err == nil && l.contract.taptree != "" {
			err = bad("a contract checked against a given taptree cannot lock an output")
		}
	default:
		l.from, err = c.inputIndex(s.From, "locking")
	}
	return l, err
}

// checkPrograms: a program binding names a contract output, whose own bindings name no program.
func (t *Template) checkPrograms() error {
	for _, o := range t.outputs {
		if o.locking.contract != nil && slices.ContainsFunc(slices.Collect(maps.Values(o.locking.contract.args)), hasProgram) {
			return bad("output %q binds an output program", o.name)
		}
	}
	for _, in := range t.inputs {
		for _, b := range in.contract.args {
			for _, pc := range b {
				if k := t.output(pc.program); pc.program != "" && (k < 0 || t.outputs[k].locking.contract == nil) {
					return bad("program %q names no output built from a contract", pc.program)
				}
			}
		}
	}
	return nil
}

// checkBalances: one remainder output per input, one remainder route per input and asset.
func (t *Template) checkBalances() error {
	for i, in := range t.inputs {
		n := 0
		for _, o := range t.outputs {
			if o.from == i && o.amount == nil {
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

// 21 million bitcoin in satoshis
const maxAmount = 21e14

type allocation struct {
	sats   []uint64            // per output, template order
	assets []map[string]uint64 // per output: hex asset id → amount
	fee    uint64
}

// allocate balances every input separately; fee comes out of fees.from and dust is the minimum output.
func (i *Instance) allocate(d *draft, sources []*Source, fee uint64, dust uint64) (*allocation, error) {
	t := i.tmpl
	feeCap := i.feeCap()
	switch {
	case fee > 0 && t.fee == nil:
		return nil, fmt.Errorf("%w: %w: the template pays no fee, asked %d", ErrIneligible, ErrUnaffordable, fee)
	case t.fee != nil && fee > feeCap:
		return nil, fmt.Errorf("%w: %w: fee %d exceeds the cap %d", ErrIneligible, ErrUnaffordable, fee, feeCap)
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

		if err := i.routeSats(d, slot, s.Amount, dust, a); err != nil {
			return nil, err
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

func (i *Instance) routeSats(d *draft, slot int, amount, dust uint64, a *allocation) error {
	t := i.tmpl
	left := amount
	for k, o := range t.outputs {
		if o.from != slot || o.amount == nil {
			continue
		}
		n, err := i.fixedAmount(o.amount, d, o.from)
		if err != nil {
			return fmt.Errorf("output %q: %w", o.name, err)
		}
		if n < dust {
			return fmt.Errorf("%w: %w: output %q draws %d, minimum %d", ErrIneligible, ErrUnaffordable, o.name, n, dust)
		}
		if n > left {
			return fmt.Errorf("%w: output %q draws %d of %d left", ErrIneligible, o.name, n, left)
		}
		left -= n
		a.sats[k] = n
	}
	if t.fee != nil && t.fee.from == slot {
		if a.fee > left {
			return fmt.Errorf("%w: input %q cannot pay fee %d", ErrIneligible, t.inputs[t.fee.from].name, a.fee)
		}
		left -= a.fee
	}
	for k, o := range t.outputs {
		if o.from == slot && o.amount == nil {
			if left < dust {
				return fmt.Errorf("%w: %w: output %q remainder %d below %d", ErrIneligible, ErrUnaffordable, o.name, left, dust)
			}
			a.sats[k] = left
		}
	}
	return nil
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
	n, err := asm.ParseScriptNum(raw)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%w: amount of %d bytes is not a positive number", ErrIneligible, len(raw))
	}
	return uint64(n), nil
}

func (i *Instance) outputScripts(d *draft, sources []*Source) ([][]byte, error) {
	out := make([][]byte, len(i.tmpl.outputs))
	for k, o := range i.tmpl.outputs {
		var err error
		switch l := o.locking; {
		case l.from >= 0:
			out[k] = bytes.Clone(pkScript(sources[l.from]))
		case l.contract != nil:
			var ct *contract.Contract
			if ct, err = i.contractOf(l.contract, d, o.from, false); err == nil {
				out[k] = ct.PkScript
			}
		default:
			out[k], err = i.resolve(l.script, d, d.index(o.from))
			if err == nil {
				err = checkScript(out[k], o.onchain)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("output %q: %w", o.name, err)
		}
	}
	return out, nil
}

// checkScript requires P2TR off chain and a script that parses on chain.
func checkScript(s []byte, onchain bool) error {
	if !onchain {
		if !txscript.IsPayToTaproot(s) {
			return fmt.Errorf("%w: an offchain output needs a P2TR script, got %d bytes", ErrIneligible, len(s))
		}
		if _, err := schnorr.ParsePubKey(s[2:]); err != nil {
			return fmt.Errorf("%w: an offchain output needs a valid taproot key", ErrIneligible)
		}
		return nil
	}
	tok := txscript.MakeScriptTokenizer(0, s)
	for tok.Next() {
	}
	if len(s) == 0 || tok.Err() != nil {
		return fmt.Errorf("%w: malformed script of %d bytes", ErrIneligible, len(s))
	}
	return nil
}

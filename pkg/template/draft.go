package template

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// Asset is an amount of one asset held by a source output.
type Asset struct {
	ID     []byte // 34 bytes
	Amount uint64
}

// Source is an output an action spends.
type Source struct {
	Outpoint  wire.OutPoint
	Tx        *wire.MsgTx // the transaction that created Outpoint
	Amount    uint64
	Assets    []Asset
	Expiry    time.Time // offchain: when the virtual output expires
	Confirms  int       // onchain: confirmations of Tx
	CreatedAt time.Time
	Swept     bool // offchain: swept by the server, hence recoverable
}

// draft is the transaction expressions see: inputs at their final position, no output; not safe for concurrent use.
type draft struct {
	tx      *wire.MsgTx
	sources []*Source         // aligned with tx.TxIn; nil for an intent's message input
	bound   []bool            // aligned with tx.TxIn; false for a source whose Tx is not its outpoint's
	secrets map[string][]byte // plaintexts opened for this draft
}

func newDraft(typ Type, sources []*Source) *draft {
	version := int32(2)
	if typ == Offchain {
		version = 3
	}
	d := &draft{tx: wire.NewMsgTx(version)}
	if typ == Intent {
		d.tx.AddTxIn(&wire.TxIn{Sequence: wire.MaxTxInSequenceNum})
		d.sources = append(d.sources, nil)
		d.bound = append(d.bound, true)
	}
	for _, s := range sources {
		d.tx.AddTxIn(&wire.TxIn{PreviousOutPoint: s.Outpoint, Sequence: wire.MaxTxInSequenceNum})
		d.sources = append(d.sources, s)
		d.bound = append(d.bound, isBound(s))
	}
	return d
}

func (d *draft) index(slot int) int {
	if len(d.sources) > 0 && d.sources[0] == nil {
		return slot + 1
	}
	return slot
}

func (d *draft) eval(tokens []string, input int, lookup asm.Lookup) ([]byte, error) {
	script, err := asm.Assemble(tokens, lookup)
	if err != nil {
		return nil, fmt.Errorf("%w: expression: %v", ErrIneligible, err)
	}
	if input < 0 || input >= len(d.sources) {
		return nil, fmt.Errorf("%w: expression: input %d out of range", ErrIneligible, input)
	}
	var amount int64
	src := d.sources[input]
	if src != nil {
		amount = int64(src.Amount)
	}
	vm, err := arkade.NewEngine(script, d.tx, input, nil, nil, amount, d)
	if err != nil {
		return nil, fmt.Errorf("%w: expression: %s", ErrIneligible, vmError(err))
	}
	if src != nil && !src.Expiry.IsZero() {
		arkade.WithExpiry(src.Expiry.Unix())(vm)
	}
	for done := false; !done; {
		if done, err = vm.Step(); err != nil {
			return nil, fmt.Errorf("%w: expression: %s", ErrIneligible, vmError(err))
		}
	}
	stack := vm.GetStack()
	if len(stack) != 1 {
		return nil, fmt.Errorf("%w: expression: stack holds %d elements", ErrIneligible, len(stack))
	}
	return stack[0], nil
}

// a VM error description can hold the values of secrets
func vmError(err error) string {
	var e txscript.Error
	if errors.As(err, &e) {
		return e.ErrorCode.String()
	}
	return "script failed"
}

// source is nil for an intent's message input; false when op is unknown or refused.
func (d *draft) source(op wire.OutPoint) (*Source, bool) {
	i := slices.IndexFunc(d.tx.TxIn, func(in *wire.TxIn) bool { return in.PreviousOutPoint == op })
	if i < 0 || !d.bound[i] {
		return nil, false
	}
	return d.sources[i], true
}

func (d *draft) FetchPrevOutput(op wire.OutPoint) *wire.TxOut {
	s, ok := d.source(op)
	if !ok {
		return nil
	}
	if s == nil {
		if len(d.sources) < 2 || !d.bound[1] {
			return nil
		}
		return &wire.TxOut{PkScript: pkScript(d.sources[1])}
	}
	return &wire.TxOut{Value: int64(s.Amount), PkScript: pkScript(s)}
}

func (d *draft) FetchPrevOutArkTx(op wire.OutPoint) *wire.MsgTx {
	if s, ok := d.source(op); ok && s != nil {
		return s.Tx
	}
	return nil
}

func (d *draft) FetchVtxoPrevOutPkScript(op wire.OutPoint) []byte {
	if out := d.FetchPrevOutput(op); out != nil {
		return out.PkScript
	}
	return nil
}

// isBound reports whether s.Tx, when set, created s.Outpoint holding s.Amount.
func isBound(s *Source) bool {
	if s.Tx == nil {
		return true
	}
	i := int(s.Outpoint.Index)
	return i < len(s.Tx.TxOut) && s.Tx.TxHash() == s.Outpoint.Hash && s.Tx.TxOut[i].Value == int64(s.Amount)
}

func pkScript(s *Source) []byte {
	if s.Tx == nil {
		return nil
	}
	return s.Tx.TxOut[s.Outpoint.Index].PkScript
}

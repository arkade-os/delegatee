// Package v1 owns the template/v1 language, canonical identity and execution semantics.
package v1

import (
	"fmt"
	"maps"
	"slices"

	"github.com/arkade-os/executor/pkg/template/internal/model"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
)

type Type = model.Type

const (
	Proof   = model.Proof
	Virtual = model.Virtual
	Onchain = model.Onchain
)

type Schedule = model.Schedule
type Slot = model.Slot

type Template struct {
	requiredKeys keyRequirements
	id           string
	spendID      string
	typ          Type
	variables    map[string]string
	sealed       map[string]bool // variables a service receives encrypted
	inputs       []input
	outputs      []output
	fee          *fee
	packets      *packetSpec
	triggers     []*Trigger
	artifacts    []string
}

// ID is the hex SHA-256 of the canonical document.
func (t *Template) ID() string { return t.id }

// SpendID is the hex SHA-256 of the canonical document without its delegation.
func (t *Template) SpendID() string { return t.spendID }

func (t *Template) Type() Type { return t.typ }

func (t *Template) Variables() []Field {
	out := make([]Field, 0, len(t.variables))
	for _, n := range slices.Sorted(maps.Keys(t.variables)) {
		out = append(out, Field{Name: n, Type: t.variables[n]})
	}
	return out
}

func (t *Template) Inputs() []Slot {
	out := make([]Slot, 0, len(t.inputs))
	for _, in := range t.inputs {
		out = append(out, Slot{Name: in.name, Onchain: in.onchain, Schedule: in.schedule})
	}
	return out
}

// Arkade reports whether a spend carries an arkade packet: an input runs a covenant function.
func (t *Template) Arkade() bool {
	return slices.ContainsFunc(t.inputs, func(in input) bool {
		fn := in.selected
		return fn != nil && fn.Arkade != nil
	})
}

func (t *Template) Artifacts() []string { return slices.Clone(t.artifacts) }
func (t *Template) Sealed() []string    { return slices.Sorted(maps.Keys(t.sealed)) }

// ContextFree reports whether the input contracts can be built without sources.
func (t *Template) ContextFree() bool {
	for _, in := range t.inputs {
		if !t.argsFree(in.contract.args) {
			return false
		}
	}
	return true
}

func (t *Template) argsFree(args map[string]byteTemplate) bool {
	for _, b := range args {
		if !exprsFree(b) {
			return false
		}
		for _, p := range b {
			if p.program != "" &&
				!t.argsFree(t.outputs[t.output(p.program)].locking.contract.args) {
				return false
			}
		}
	}
	return true
}

func (t *Template) output(name string) int {
	return slices.IndexFunc(t.outputs, func(o output) bool { return o.name == name })
}

// isTaptree: the variable holds a given tree, decoded and never pushed.
func (t *Template) isTaptree(name string) bool {
	return slices.ContainsFunc(t.inputs, func(in input) bool { return in.contract.taptree == name })
}

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTemplate, fmt.Sprintf(format, args...))
}

func exprsFree(b byteTemplate) bool {
	return !slices.ContainsFunc(
		b, func(p piece) bool { return p.expr != nil && !asm.ContextFree(p.expr) },
	)
}

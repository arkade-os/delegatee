// Package template parses delegation templates, binds them to keys, variables and sources, and
// builds the transactions they describe.
//
// A document is decoded into its typed form by internal/schema, compiled into a Template, and
// hashed in its canonical form to get its id. A Template bound to a Context is an Instance,
// which builds one Action per set of sources.
package template

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/arkade-os/delegatee/pkg/template/internal/asm"
	"github.com/arkade-os/delegatee/pkg/template/internal/schema"
)

// Type is the kind of transaction a template builds.
type Type string

const (
	// Intent is an Ark intent: a message input, then the template inputs.
	Intent Type = "intent"
	// Offchain is an Ark transaction spending virtual outputs.
	Offchain Type = "offchain"
	// Onchain is a Bitcoin transaction.
	Onchain Type = "onchain"
)

// Schedule is when an input becomes eligible; the zero value is immediately.
type Schedule struct {
	BeforeExpiry     time.Duration // offchain
	MinConfirmations int           // onchain
}

// Slot describes one template input.
type Slot struct {
	Name     string
	Onchain  bool
	Schedule Schedule
}

// Template is a parsed, validated template.
type Template struct {
	id        string
	typ       Type
	variables map[string]string
	secrets   map[string]secret
	inputs    []input
	outputs   []output
	fee       *fee
	packets   *packetSpec
	trigger   *Trigger
	artifacts []string
}

// ArtifactIDs lists the artifact ids a document references, in order of first appearance.
func ArtifactIDs(doc []byte) ([]string, error) {
	d, err := schema.Decode(doc)
	if err != nil {
		return nil, err
	}
	var ids []string
	add := func(c *schema.Construction) {
		if id := c.Definition.Artifact; c.Definition.Def == nil && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	for i := range d.Inputs {
		add(&d.Inputs[i].Contract)
	}
	for i := range d.Outputs {
		if c := d.Outputs[i].Locking.Contract; c != nil {
			add(c)
		}
	}
	return ids, nil
}

// Parse decodes and validates a template, with the documents of the artifacts it references keyed
// by id; its id is the hash of the normalized document.
func Parse(doc []byte, artifacts map[string][]byte) (*Template, error) {
	d, err := schema.Decode(doc)
	if err != nil {
		return nil, err
	}
	t, err := compile(d, artifacts)
	if err != nil {
		return nil, err
	}
	d.Normalize()
	b, err := d.Canonical()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	t.id = hex.EncodeToString(sum[:])
	return t, nil
}

// ID is the hex SHA-256 of the canonical document.
func (t *Template) ID() string { return t.id }

func (t *Template) Type() Type { return t.typ }

// Variables lists the declared variables, sorted by name.
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
		fn := in.contract.def.FindFunction(in.function)
		return fn != nil && fn.Arkade != nil
	})
}

// Artifacts lists the referenced artifact ids in order of first appearance.
func (t *Template) Artifacts() []string { return slices.Clone(t.artifacts) }

// Secrets reports whether the template declares secrets, which Instantiate must decrypt.
func (t *Template) Secrets() bool { return len(t.secrets) > 0 }

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTemplate, fmt.Sprintf(format, args...))
}

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
		for _, n := range b.names() {
			if s, ok := t.secrets[n]; ok && !exprsFree(s.ciphertext) {
				return false
			}
		}
		for _, p := range b {
			if p.program != "" && !t.argsFree(t.outputs[t.output(p.program)].locking.contract.args) {
				return false
			}
		}
	}
	return true
}

func (t *Template) output(name string) int {
	return slices.IndexFunc(t.outputs, func(o output) bool { return o.name == name })
}

func exprsFree(b byteTemplate) bool {
	return !slices.ContainsFunc(b, func(p piece) bool { return p.expr != nil && !asm.ContextFree(p.expr) })
}

// isTaptree: the variable holds a given tree, decoded and never pushed.
func (t *Template) isTaptree(name string) bool {
	return slices.ContainsFunc(t.inputs, func(in input) bool { return in.contract.taptree == name })
}

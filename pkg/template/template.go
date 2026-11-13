// Package template compiles versioned JSON templates and contract artifacts into
// unsigned transactions. It does not load dependencies, sign or broadcast.
package template

import (
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	v1 "github.com/arkade-os/executor/pkg/template/internal/version/v1"
	"github.com/btcsuite/btcd/psbt/v2"
)

// Template is immutable and safe for concurrent use. Its zero value is invalid.
type Template struct {
	version string
	v1      *v1.Template
}

// BoundTemplate holds keys and variables; each Build starts from its request alone.
type BoundTemplate struct{ v1 *v1.BoundTemplate }

type Instance struct{ v1 *v1.Instance }

type Trigger struct{ v1 *v1.Trigger }

func (t *Template) Version() string     { return t.version }
func (t *Template) ID() string          { return t.v1.ID() }
func (t *Template) SpendID() string     { return t.v1.SpendID() }
func (t *Template) Type() Type          { return t.v1.Type() }
func (t *Template) Variables() []Field  { return t.v1.Variables() }
func (t *Template) Inputs() []Slot      { return t.v1.Inputs() }
func (t *Template) Arkade() bool        { return t.v1.Arkade() }
func (t *Template) Artifacts() []string { return t.v1.Artifacts() }
func (t *Template) Sealed() []string    { return t.v1.Sealed() }
func (t *Template) ContextFree() bool   { return t.v1.ContextFree() }

// Triggers lists one stream rule per triggered input, in input order.
func (t *Template) Triggers() []*Trigger {
	var out []*Trigger
	for _, tr := range t.v1.Triggers() {
		out = append(out, &Trigger{tr})
	}
	return out
}

// Instantiate without sources derives the input contracts of a watch.
func (t *Template) Instantiate(c Context) (*Instance, error) {
	i, err := t.v1.Instantiate(c)
	if err != nil {
		return nil, wrap("instantiate", err)
	}
	return &Instance{i}, nil
}

func (t *Template) Bind(b Bindings) (*BoundTemplate, error) {
	bound, err := t.v1.Bind(b)
	if err != nil {
		return nil, wrap("bind", err)
	}
	return &BoundTemplate{bound}, nil
}

func (b *BoundTemplate) Build(r BuildRequest) (*Action, error) {
	a, err := b.v1.Build(r)
	return a, wrap("build", err)
}

func (b *BoundTemplate) InputContracts(r Runtime) (*Instance, error) {
	i, err := b.v1.InputContracts(r)
	if err != nil {
		return nil, wrap("derive", err)
	}
	return &Instance{i}, nil
}

func (i *Instance) Build(s []*Source, f Fee) (*Action, error) {
	a, err := i.v1.Build(s, f)
	return a, wrap("build", err)
}

func (i *Instance) PkScript(slot int) []byte     { return i.v1.PkScript(slot) }
func (i *Instance) Tapscripts(slot int) []string { return i.v1.Tapscripts(slot) }

func (i *Instance) Locktime(slot int) (arklib.AbsoluteLocktime, bool) {
	return i.v1.Locktime(slot)
}

func (i *Instance) DueAt(slot int, s *Source, now time.Time) time.Time {
	return i.v1.DueAt(slot, s, now)
}

func (t *Trigger) Input() int         { return t.v1.Input() }
func (t *Trigger) TTL() time.Duration { return t.v1.TTL() }
func (t *Trigger) Captured() []string { return t.v1.Captured() }

// Match returns the candidate outputs of p. given holds the stream's registered variables;
// decrypt opens a sealed variable a requirement reads. A requirement on a variable another
// rule captures is left to whoever completes the group.
func (t *Trigger) Match(
	p *psbt.Packet, k TriggerKeys, given map[string][]byte, decrypt func([]byte) ([]byte, error),
) ([]Capture, error) {
	c, err := t.v1.Match(p, k, given, decrypt)
	return c, wrap("match", err)
}

package template

import (
	"bytes"
	"fmt"
	"math"
	"slices"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/delegatee/pkg/template/internal/asm"
	"github.com/arkade-os/delegatee/pkg/template/internal/contract"
)

// Keys are the service keys a contract is resolved under; Cosigner is the daemon's cosigner.
type Keys = contract.Keys

// Context is what an instance is resolved under.
type Context struct {
	Keys      Keys
	Variables map[string][]byte
	Decrypt   func(ciphertext []byte) ([]byte, error) // called concurrently; errors must not contain plaintext
	// Sources are the outputs to spend, one per input; nil asks for a watch, built from the variables alone.
	Sources []*Source
}

// Instance is a template bound to keys, variables and, unless it is a watch, sources.
type Instance struct {
	tmpl      *Template
	keys      Keys
	vars      map[string][]byte
	decrypt   func([]byte) ([]byte, error)
	contracts []*contract.Contract       // per slot
	locktimes []*arklib.AbsoluteLocktime // per slot, nil without a CLTV spend leaf
}

func (t *Template) Instantiate(c Context) (*Instance, error) {
	if len(c.Variables) != len(t.variables) {
		return nil, fmt.Errorf("%w: %d values for %d variables", ErrInvalidVariables, len(c.Variables), len(t.variables))
	}
	for n, typ := range t.variables {
		v, ok := c.Variables[n]
		if !ok {
			return nil, fmt.Errorf("%w: missing %q", ErrInvalidVariables, n)
		}
		if t.isTaptree(n) {
			continue
		}
		if err := asm.CanonicalBytes(typ, v); err != nil {
			return nil, fmt.Errorf("%w: variable %q: %v", ErrInvalidVariables, n, err)
		}
	}
	if err := t.checkRanges(c.Variables); err != nil {
		return nil, err
	}
	if t.Secrets() && c.Decrypt == nil {
		return nil, fmt.Errorf("%w: no decryption for secrets", ErrUnsupported)
	}
	watch := c.Sources == nil
	sources := c.Sources
	if watch {
		if len(t.inputs) != 1 || !t.ContextFree() {
			return nil, fmt.Errorf("%w: a watch needs one input with context-free bindings", ErrUnsupported)
		}
		sources = []*Source{{}}
	} else if err := checkSources(sources, len(t.inputs)); err != nil {
		return nil, err
	}
	d := newDraft(t.typ, sources)

	i := &Instance{tmpl: t, keys: c.Keys, vars: map[string][]byte{}, decrypt: c.Decrypt}
	for n, v := range c.Variables {
		i.vars[n] = bytes.Clone(v)
	}
	for slot, in := range t.inputs {
		ct, err := i.contractOf(&in.contract, d, slot, watch)
		if err != nil {
			return nil, fmt.Errorf("input %q: %w", in.name, err)
		}
		lt, err := checkClosure(in, ct)
		if err != nil {
			return nil, err
		}
		i.locktimes = append(i.locktimes, lt)
		if !watch {
			if err := checkSourceScript(in, sources[slot], ct); err != nil {
				return nil, err
			}
		}
		i.contracts = append(i.contracts, ct)
	}
	if !sameDomain(i.locktimes) {
		return nil, fmt.Errorf("%w: locktimes mix block heights and timestamps", ErrUnsupported)
	}
	return i, nil
}

func checkSources(sources []*Source, n int) error {
	if len(sources) != n {
		return fmt.Errorf("%w: %d sources for %d inputs", ErrIneligible, len(sources), n)
	}
	for i, s := range sources {
		if s == nil || s.Tx == nil {
			return fmt.Errorf("%w: source %d or its transaction missing", ErrIneligible, i)
		}
		if !isBound(s) {
			return fmt.Errorf("%w: source %d is not the output of its transaction", ErrIneligible, i)
		}
		if slices.ContainsFunc(sources[:i], func(o *Source) bool { return o.Outpoint == s.Outpoint }) {
			return fmt.Errorf("%w: source %d repeats an outpoint", ErrIneligible, i)
		}
	}
	return nil
}

// checkRanges bounds the variables a schedule or a fee cap reads.
func (t *Template) checkRanges(vars map[string][]byte) error {
	check := func(name string, lo, hi int64) error {
		if n, err := asm.ParseScriptNum(vars[name]); err != nil || n < lo || n > hi {
			return fmt.Errorf("%w: %q must be in %d..%d", ErrInvalidVariables, name, lo, hi)
		}
		return nil
	}
	for _, in := range t.inputs {
		if in.leadVariable != "" {
			if err := check(in.leadVariable, 1, math.MaxUint32); err != nil {
				return err
			}
		}
	}
	if t.fee != nil && t.fee.maxVariable != "" {
		return check(t.fee.maxVariable, 0, asm.MaxScriptNum)
	}
	return nil
}

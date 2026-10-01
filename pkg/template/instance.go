package template

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
)

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
	contracts []*contract // per slot
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
	return !slices.ContainsFunc(b, func(p piece) bool { return p.expr != nil && !contextFree(p.expr) })
}

// Instantiate binds the template to c, building the contract of every input.
func (t *Template) Instantiate(_ context.Context, c Context) (*Instance, error) {
	if len(c.Variables) != len(t.variables) {
		return nil, fmt.Errorf("%w: %d values for %d variables", ErrInvalidVariables, len(c.Variables), len(t.variables))
	}
	for n, typ := range t.variables {
		v, ok := c.Variables[n]
		if !ok {
			return nil, fmt.Errorf("%w: missing %q", ErrInvalidVariables, n)
		}
		if err := canonicalBytes(typ, v); err != nil {
			return nil, fmt.Errorf("variable %q: %w", n, err)
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
		if err := checkClosure(in, ct); err != nil {
			return nil, err
		}
		if !watch {
			if err := checkSourceScript(in, sources[slot], ct); err != nil {
				return nil, err
			}
		}
		i.contracts = append(i.contracts, ct)
	}
	return i, nil
}

// a non-canonical value is ineligible, unless watch, where it can only come from the variables
func (i *Instance) contractOf(c *construction, d *draft, slot int, watch bool) (*contract, error) {
	flat, err := c.def.flatConstructor()
	if err != nil {
		return nil, err
	}
	args := map[string]value{}
	for _, f := range flat {
		raw, err := i.resolve(c.args[f.Name], d, d.index(slot))
		if err == nil {
			if err = canonicalBytes(f.Type, raw); err != nil && !watch {
				err = fmt.Errorf("%w: %v", ErrIneligible, err)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", f.Name, err)
		}
		args[f.Name] = value{f.Type, raw}
	}
	return build(c.def, args, i.keys)
}

// the emulator accepts only ark-lib closures on a leaf naming its key
func checkClosure(in input, ct *contract) error {
	f, _ := in.contract.def.function(in.function)
	l, _ := f.leaf(in.leaf)
	if !slices.ContainsFunc(l.Asm, func(tok string) bool {
		return strings.HasPrefix(tok, "<EMULATOR_KEY:") || strings.HasPrefix(tok, "<TWEAK:")
	}) {
		return nil
	}
	if _, err := script.DecodeClosure(ct.proofs[[2]string{in.function, in.leaf}].Script); err != nil {
		return fmt.Errorf("%w: input %q: leaf %q is not a closure", ErrUnsupported, in.name, in.leaf)
	}
	return nil
}

func checkSourceScript(in input, s *Source, ct *contract) error {
	if !bytes.Equal(pkScript(s), ct.pkScript) {
		return fmt.Errorf("%w: input %q: source script differs from the contract", ErrIneligible, in.name)
	}
	return nil
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

// Tapscripts lists the hex leaf scripts of the input's contract.
func (i *Instance) Tapscripts(slot int) []string { return slices.Clone(i.contracts[slot].tapscripts) }

// PkScript is the output script of the input's contract.
func (i *Instance) PkScript(slot int) []byte { return bytes.Clone(i.contracts[slot].pkScript) }

// checkRanges bounds the variables a schedule or a fee cap reads.
func (t *Template) checkRanges(vars map[string][]byte) error {
	check := func(name string, lo, hi int64) error {
		if n, err := parseScriptNum(vars[name]); err != nil || n < lo || n > hi {
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
		return check(t.fee.maxVariable, 0, maxScriptNum)
	}
	return nil
}

// FeeCap is the most the instance lets one of its transactions pay in fees; false when it pays none.
func (i *Instance) FeeCap() (uint64, bool) {
	f := i.tmpl.fee
	if f == nil {
		return 0, false
	}
	if f.maxVariable == "" {
		return f.max, true
	}
	n, _ := parseScriptNum(i.vars[f.maxVariable])
	return uint64(n), true
}

// lead is how long before expiry the input becomes due, zero without an expiry schedule.
func (i *Instance) lead(slot int) time.Duration {
	in := i.tmpl.inputs[slot]
	if in.leadVariable == "" {
		return in.schedule.BeforeExpiry
	}
	n, _ := parseScriptNum(i.vars[in.leadVariable])
	return time.Duration(n) * time.Second
}

// DueAt is the window start for an expiry lead, else the source's creation, or now when unknown.
// A fee-paying instance waits at least half the source's life: a longer lead would pay in every round.
func (i *Instance) DueAt(slot int, s *Source, now time.Time) time.Time {
	sch := i.tmpl.inputs[slot].schedule
	lead := i.lead(slot)
	if cap, _ := i.FeeCap(); cap > 0 && !s.CreatedAt.IsZero() {
		if life := s.Expiry.Sub(s.CreatedAt); life > 0 {
			lead = min(lead, life/2)
		}
	}
	switch {
	case lead > 0 && !s.Expiry.IsZero():
		return s.Expiry.Add(-lead)
	case lead > 0, s.Confirms < sch.MinConfirmations:
		return now.Add(time.Hour)
	case !s.CreatedAt.IsZero():
		return s.CreatedAt
	}
	return now
}

// secrets open at most once per draft and are kept only by it
func (i *Instance) resolve(b byteTemplate, d *draft, input int) ([]byte, error) {
	lookup := func(n string) (value, error) { return i.lookup(n, d) }
	out := []byte{}
	for _, p := range b {
		switch {
		case p.name != "":
			v, err := lookup(p.name)
			if err != nil {
				return nil, err
			}
			out = append(out, v.raw...)
		case p.program != "":
			o := i.tmpl.outputs[i.tmpl.output(p.program)]
			ct, err := i.contractOf(o.locking.contract, d, o.from, false)
			if err != nil {
				return nil, fmt.Errorf("output %q: %w", o.name, err)
			}
			out = append(out, ct.pkScript[2:]...)
		case p.expr != nil:
			r, err := d.eval(p.expr, input, lookup)
			if err != nil {
				return nil, err
			}
			out = append(out, r...)
		default:
			out = append(out, p.hex...)
		}
	}
	return out, nil
}

func (i *Instance) lookup(n string, d *draft) (value, error) {
	if typ, ok := i.tmpl.variables[n]; ok {
		return value{typ, i.vars[n]}, nil
	}
	s, ok := i.tmpl.secrets[n]
	if !ok {
		return value{}, fmt.Errorf("%w: unknown name %q", ErrInvalidTemplate, n)
	}
	if p, ok := d.secrets[n]; ok {
		return value{s.typ, p}, nil
	}
	ct, err := i.resolve(s.ciphertext, d, d.index(s.from))
	if err != nil {
		return value{}, fmt.Errorf("secret %q: %w", n, err)
	}
	p, err := i.decrypt(ct)
	if err == nil {
		err = canonicalBytes(s.typ, p)
	}
	if err != nil {
		return value{}, fmt.Errorf("%w: secret %q: %v", ErrIneligible, n, err)
	}
	if d.secrets == nil {
		d.secrets = map[string][]byte{}
	}
	d.secrets[n] = p
	return value{s.typ, p}, nil
}

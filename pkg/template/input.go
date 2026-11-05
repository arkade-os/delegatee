package template

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/delegatee/pkg/template/internal/abi"
	"github.com/arkade-os/delegatee/pkg/template/internal/asm"
	"github.com/arkade-os/delegatee/pkg/template/internal/contract"
	"github.com/arkade-os/delegatee/pkg/template/internal/schema"
)

type construction struct {
	def     *Definition
	args    map[string]byteTemplate // flattened constructor name → binding
	taptree string                  // bytes variable holding the whole tree; "" builds it from def
}

type input struct {
	name           string
	onchain        bool
	schedule       Schedule
	leadVariable   string // an int variable holding before_expiry_seconds
	contract       construction
	function, leaf string
	arguments      []byteTemplate          // covenant inputs, ABI order
	witness        map[string]byteTemplate // non-signature witness items
}

func (c *compiler) input(s *schema.Input) error {
	if slices.ContainsFunc(c.t.inputs, func(o input) bool { return o.name == s.Name }) {
		return bad("duplicate input %q", s.Name)
	}
	in := input{name: s.Name}
	var err error
	if in.onchain, err = c.slotType(s.Type); err != nil {
		return err
	}
	if s.Schedule != nil {
		if in.schedule, in.leadVariable, err = c.schedule(s.Schedule, in.onchain); err != nil {
			return err
		}
	}
	ct, err := c.construction(&s.Contract)
	if err != nil {
		return err
	}
	in.contract = *ct
	if err := c.spend(&in, &s.Spend); err != nil {
		return err
	}
	c.t.inputs = append(c.t.inputs, in)
	return nil
}

// schedule returns the fixed schedule, or the int variable an expiry lead reads.
func (c *compiler) schedule(s *schema.Schedule, onchain bool) (Schedule, string, error) {
	switch {
	case s.Immediate != nil:
		return Schedule{}, "", nil
	case s.BeforeExpiry != nil && !onchain:
		n, name, err := c.intVariable(*s.BeforeExpiry)
		if err != nil || name != "" {
			return Schedule{}, name, err
		}
		return Schedule{BeforeExpiry: time.Duration(n) * time.Second}, "", nil
	case s.MinConfirmations != nil && onchain:
		return Schedule{MinConfirmations: int(*s.MinConfirmations)}, "", nil
	}
	return Schedule{}, "", bad("the schedule does not fit the input")
}

func (c *compiler) construction(s *schema.Construction) (*construction, error) {
	def, err := c.definition(s.Definition)
	if err != nil {
		return nil, err
	}
	flat, err := def.FlatConstructor()
	if err != nil {
		return nil, err
	}
	ct := &construction{def: def, args: map[string]byteTemplate{}}
	if s.Taptree != "" {
		name := s.Taptree[1 : len(s.Taptree)-1] // <name>, checked by the schema
		if c.t.variables[name] != "bytes" {
			return nil, bad("taptree must name a bytes variable, got %q", s.Taptree)
		}
		ct.taptree = name
	}
	for _, f := range flat {
		raw, ok := s.Arguments[f.Name]
		if !ok {
			return nil, bad("missing argument %q", f.Name)
		}
		if raw.Program != nil {
			if f.Type != "bytes32" {
				return nil, bad("output program %q cannot fill a %s field", *raw.Program, f.Type)
			}
			ct.args[f.Name] = byteTemplate{{program: *raw.Program}}
			continue
		}
		if ct.args[f.Name], err = c.scriptBind(raw, f.Type); err != nil {
			return nil, err
		}
	}
	if len(s.Arguments) != len(flat) {
		return nil, bad("contract %q has arguments outside its constructor", def.ContractName)
	}
	return ct, nil
}

// definition returns the inline definition, or verifies the referenced artifact.
func (c *compiler) definition(ref schema.DefinitionRef) (*abi.Definition, error) {
	if d := ref.Def; d != nil {
		return d, nil
	}
	id := ref.Artifact
	doc, ok := c.artifacts[id]
	if !ok {
		return nil, bad("artifact %s not provided", id)
	}
	a, err := abi.Parse(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact %s: %w", ErrInvalidTemplate, id, err)
	}
	if a.ID != id {
		return nil, bad("artifact %s resolves to a document with id %s", id, a.ID)
	}
	if !slices.Contains(c.t.artifacts, id) {
		c.t.artifacts = append(c.t.artifacts, id)
	}
	return &a.Definition, nil
}

func (c *compiler) spend(in *input, s *schema.Spend) error {
	f := in.contract.def.FindFunction(s.Function)
	if f == nil {
		return bad("unknown function %q", s.Function)
	}
	l := f.FindLeaf(s.Leaf)
	if l == nil {
		return bad("unknown leaf %q", s.Leaf)
	}
	// arkd sets an absolute locktime only when it builds an offchain spend
	if slices.ContainsFunc(l.Asm, isCLTV) && c.t.typ != Offchain {
		return fmt.Errorf("%w: leaf %q needs an absolute locktime, which only an offchain template sets", ErrUnsupported, l.Name)
	}
	in.function, in.leaf = f.Name, l.Name
	var want []Field
	if f.Arkade != nil {
		want = f.Arkade.Inputs
	}
	for _, w := range want {
		if abi.ArrayType.MatchString(w.Type) {
			return fmt.Errorf("%w: function %q takes the array input %q, which a template cannot fill", ErrUnsupported, f.Name, w.Name)
		}
	}
	if len(s.Arguments) != len(want) {
		return bad("function %q takes %d arguments, got %d", f.Name, len(want), len(s.Arguments))
	}
	for i, a := range s.Arguments {
		b, err := c.bind(a, want[i].Type, true)
		if err != nil {
			return err
		}
		in.arguments = append(in.arguments, b)
	}
	in.witness = map[string]byteTemplate{}
	for _, w := range l.Witness {
		if w.Type == "signature" {
			if !w.Injected {
				return bad("leaf %q needs signature %q, which nobody injects", l.Name, w.Name)
			}
			continue
		}
		raw, ok := s.Witness[w.Name]
		if !ok {
			return bad("witness item %q is not bound", w.Name)
		}
		var err error
		if in.witness[w.Name], err = c.bind(raw, w.Type, true); err != nil {
			return err
		}
	}
	if len(s.Witness) != len(in.witness) {
		return bad("spend binds witness items that are signatures or absent from leaf %q", l.Name)
	}
	return nil
}

// a non-canonical value is ineligible, unless watch, where it can only come from the variables
func (i *Instance) contractOf(c *construction, d *draft, slot int, watch bool) (*contract.Contract, error) {
	flat, err := c.def.FlatConstructor()
	if err != nil {
		return nil, err
	}
	args := map[string]asm.Value{}
	for _, f := range flat {
		raw, err := i.resolve(c.args[f.Name], d, d.index(slot))
		if err == nil {
			if err = asm.CanonicalBytes(f.Type, raw); err != nil {
				sentinel := ErrIneligible
				if watch {
					sentinel = ErrInvalidVariables
				}
				err = fmt.Errorf("%w: %v", sentinel, err)
			}
		}
		if err != nil {
			return nil, fmt.Errorf("argument %q: %w", f.Name, err)
		}
		args[f.Name] = asm.Value{Type: f.Type, Raw: raw}
	}
	var taptree []byte
	if c.taptree != "" {
		taptree = append([]byte{}, i.vars[c.taptree]...) // non-nil: a given tree, empty or not
	}
	ct, err := contract.Build(c.def, args, i.keys, taptree)
	return ct, contractErr(err)
}

// contractErr maps the contract package's sentinels to this package's.
func contractErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, contract.ErrNoCosigner):
		return fmt.Errorf("%w: %v", ErrUnsupported, err)
	case errors.Is(err, contract.ErrBadTree):
		return fmt.Errorf("%w: %v", ErrIneligible, err)
	case errors.Is(err, contract.ErrBadLeaf):
		return fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
	}
	return err
}

func isCLTV(tok string) bool { return tok == "OP_CHECKLOCKTIMEVERIFY" || tok == "OP_NOP2" }

// checkClosure returns the spend leaf's absolute locktime, nil without one. The emulator accepts
// only ark-lib closures on a leaf naming its key, and arkd builds a locktime only from a CLTV multisig.
func checkClosure(in input, ct *contract.Contract) (*arklib.AbsoluteLocktime, error) {
	f := in.contract.def.FindFunction(in.function)
	l := f.FindLeaf(in.leaf)
	emulated := slices.ContainsFunc(l.Asm, func(tok string) bool {
		return strings.HasPrefix(tok, "<EMULATOR_KEY:") || strings.HasPrefix(tok, "<TWEAK:")
	})
	cltv := slices.ContainsFunc(l.Asm, isCLTV)
	if !emulated && !cltv {
		return nil, nil
	}
	c, err := script.DecodeClosure(ct.Proofs[[2]string{in.function, in.leaf}].Script)
	lock, isLock := c.(*script.CLTVMultisigClosure)
	switch {
	case cltv && !isLock:
		return nil, fmt.Errorf("%w: input %q: leaf %q is not a CLTV multisig closure", ErrUnsupported, in.name, in.leaf)
	case err != nil:
		return nil, fmt.Errorf("%w: input %q: leaf %q is not a closure", ErrUnsupported, in.name, in.leaf)
	case cltv:
		return &lock.Locktime, nil
	}
	return nil, nil
}

// offchain.BuildTxs refuses heights and timestamps in one transaction; refusing here names the delegation
func sameDomain(lts []*arklib.AbsoluteLocktime) bool {
	var first *arklib.AbsoluteLocktime
	for _, lt := range lts {
		if lt == nil {
			continue
		}
		if first != nil && first.IsSeconds() != lt.IsSeconds() {
			return false
		}
		first = lt
	}
	return true
}

// Locktime is the absolute locktime of slot's spend leaf, which arkd compares with its chain tip.
func (i *Instance) Locktime(slot int) (arklib.AbsoluteLocktime, bool) {
	if lt := i.locktimes[slot]; lt != nil {
		return *lt, true
	}
	return 0, false
}

func checkSourceScript(in input, s *Source, ct *contract.Contract) error {
	if !bytes.Equal(pkScript(s), ct.PkScript) {
		return fmt.Errorf("%w: input %q: source script differs from the contract", ErrIneligible, in.name)
	}
	return nil
}

func (i *Instance) Tapscripts(slot int) []string { return slices.Clone(i.contracts[slot].Tapscripts) }

func (i *Instance) PkScript(slot int) []byte { return bytes.Clone(i.contracts[slot].PkScript) }

// lead is how long before expiry the input becomes due, zero without an expiry schedule.
func (i *Instance) lead(slot int) time.Duration {
	in := i.tmpl.inputs[slot]
	if in.leadVariable == "" {
		return in.schedule.BeforeExpiry
	}
	n, _ := asm.ParseScriptNum(i.vars[in.leadVariable])
	return time.Duration(n) * time.Second
}

// DueAt is the schedule's due time, no earlier than a timestamp locktime; a height is the caller's to check.
func (i *Instance) DueAt(slot int, s *Source, now time.Time) time.Time {
	due := i.scheduleDue(slot, s, now)
	if lt := i.locktimes[slot]; lt != nil && lt.IsSeconds() {
		if at := time.Unix(int64(*lt), 0); at.After(due) {
			return at
		}
	}
	return due
}

// scheduleDue is the window start for an expiry lead, else the source's creation, or now when unknown.
// A fee-paying instance waits at least half the source's life: a longer lead would pay in every batch.
func (i *Instance) scheduleDue(slot int, s *Source, now time.Time) time.Time {
	sch := i.tmpl.inputs[slot].schedule
	lead := i.lead(slot)
	if i.feeCap() > 0 && !s.CreatedAt.IsZero() {
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

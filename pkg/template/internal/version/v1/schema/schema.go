// Package schema is the typed form of a template document: its shape, its syntactic rules,
// its defaults and its canonical bytes. Anything that relates one part of the document to
// another is the compiler's job, not this package's.
package schema

import (
	"fmt"
	"math"
	"regexp"
	"slices"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
)

const (
	format = "template/v1"
	// MaxSlots bounds inputs, outputs, variables and every list of rules.
	MaxSlots = 255
)

var (
	// Name matches an identifier: slot, variable and secret names.
	Name       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	idHex      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	assetHex   = regexp.MustCompile(`^[0-9a-f]{68}$`)
	namedVar   = regexp.MustCompile(`^<([a-z][a-z0-9_]{0,63})>$`)
	types      = []string{"proof", "virtual", "onchain"}
	slotTypes  = []string{"offchain", "onchain"}
	actions    = []string{"copy", "drop", "emit"}
	unmatcheds = []string{"reject", "drop"}
	decodes    = []string{"tlv", "raw"}
)

// Template is a whole document. Presence and null rules are specified by the typed readers.
type Template struct {
	Format     string            `json:"format"`
	Type       string            `json:"type"`                // proof, virtual or onchain
	Variables  map[string]string `json:"variables,omitempty"` // name → scalar type
	Inputs     []Input           `json:"inputs"`              // 1..MaxSlots
	Outputs    []Output          `json:"outputs"`             // 1..MaxSlots
	Fees       *Fees             `json:"fees,omitempty"`
	Packets    *Packets          `json:"packets,omitempty"`
	Delegation *Delegation       `json:"delegation,omitempty"`
}

// Delegation is how a service runs the spend unattended; it never changes the transaction.
type Delegation struct {
	Schedule map[string]Schedule `json:"schedule,omitempty"` // input → when it becomes eligible
	Sealed   []string            `json:"sealed,omitempty"`   // variables given encrypted to the service
	Trigger  map[string]Trigger  `json:"trigger,omitempty"`  // input → stream rule
}

type Input struct {
	Name     string       `json:"name"`
	Type     string       `json:"type,omitempty"` // offchain or onchain; defaults to the template's kind
	Contract Construction `json:"contract"`
	Spend    Spend        `json:"spend"`
}

// Schedule is when an input becomes eligible; exactly one field is set.
type Schedule struct {
	Immediate        *bool     `json:"immediate,omitempty"`             // true
	BeforeExpiry     *IntOrVar `json:"before_expiry_seconds,omitempty"` // 1..MaxUint32 or an int variable
	MinConfirmations *int64    `json:"min_confirmations,omitempty"`     // 1..MaxUint32
}

type Construction struct {
	Definition DefinitionRef      `json:"definition"`
	Arguments  map[string]Binding `json:"arguments,omitempty"` // flattened constructor field → binding
	Taptree    string             `json:"taptree,omitempty"`   // <bytes variable> holding the whole tree
}

// Spend names the leaf an input is spent through and binds what the leaf needs.
type Spend struct {
	Function  string             `json:"function"`
	Leaf      string             `json:"leaf"`
	Arguments []Binding          `json:"arguments,omitempty"` // covenant inputs, ABI order
	Witness   map[string]Binding `json:"witness,omitempty"`   // non-signature witness items
}

type Output struct {
	Name    string       `json:"name"`
	Type    string       `json:"type,omitempty"` // offchain or onchain; defaults to the template's kind
	Index   int64        `json:"index"`          // 0..MaxUint16
	Value   Value        `json:"value"`
	Locking Locking      `json:"locking"`
	Assets  []AssetRoute `json:"assets,omitempty"` // at most MaxSlots
}

type Value struct {
	From   string   `json:"from"`             // an input name
	Amount *Binding `json:"amount,omitempty"` // an int; absent takes the remainder
}

// AssetRoute moves an asset of an input into the output.
type AssetRoute struct {
	From   string   `json:"from"`             // an input name
	Asset  string   `json:"asset,omitempty"`  // 68 hex; absent routes every asset
	Amount *Binding `json:"amount,omitempty"` // an int, only with Asset; absent takes the remainder
}

type Fees struct {
	From string   `json:"from"` // an input name
	Max  IntOrVar `json:"max"`  // 0..MaxScriptNum or an int variable
}

// Packets is the extension output and how source packets are handled.
type Packets struct {
	OutputIndex int64    `json:"output_index"`        // 0..MaxUint16
	Unmatched   string   `json:"unmatched,omitempty"` // reject (default) or drop
	Rules       []Rule   `json:"rules,omitempty"`     // at most MaxSlots
	Advertise   []Advert `json:"advertise,omitempty"` // at most MaxSlots
}

// Rule handles one packet type of one input.
type Rule struct {
	Type   int64    `json:"type"`           // 2..255, 5 reserved
	Action string   `json:"action"`         // copy, drop or emit
	From   string   `json:"from"`           // an input name
	Data   *Binding `json:"data,omitempty"` // the body, with emit only
}

// Advert names the template that claims outputs.
type Advert struct {
	Template string   `json:"template"` // self or a template id
	Outputs  []string `json:"outputs"`  // output names, non-empty
}

// Trigger is the stream rule of one input: it selects transactions by a packet and captures
// variables.
type Trigger struct {
	Packet       int64             `json:"packet"`                // 0..255
	Decode       string            `json:"decode"`                // tlv or raw
	MinValue     int64             `json:"min_value,omitempty"`   // 0..MaxScriptNum; 0 is the default
	Require      map[string]string `json:"require"`               // source → literal, key, <variable> or $(expression); non-empty
	Capture      map[string]string `json:"capture"`               // variable → source, output:taptree or $(expression); non-empty
	Group        string            `json:"group,omitempty"`       // a source; exactly when there are several rules
	ExpiresAfter int64             `json:"expires_after_seconds"` // 1..MaxInt32
}

func (t *Template) check() error {
	if t.Format != format {
		return bad("format must be %q", format)
	}
	if !slices.Contains(types, t.Type) {
		return bad("unknown type %q", t.Type)
	}
	for _, n := range sortedKeys(t.Variables) {
		typ := t.Variables[n]
		if !Name.MatchString(n) {
			return bad("bad variable name %q", n)
		}
		if !slices.Contains(asm.ScalarTypes, typ) {
			return bad("variable %q has unsupported type %q", n, typ)
		}
	}
	if len(t.Variables) > MaxSlots {
		return bad("more than %d variables", MaxSlots)
	}
	if n := len(t.Inputs); n == 0 || n > MaxSlots {
		return bad("a template has 1 to %d inputs", MaxSlots)
	}
	if n := len(t.Outputs); n == 0 || n > MaxSlots {
		return bad("a template has 1 to %d outputs", MaxSlots)
	}
	for _, in := range t.Inputs {
		if err := in.check(); err != nil {
			return err
		}
	}
	for _, o := range t.Outputs {
		if err := o.check(); err != nil {
			return err
		}
	}
	if t.Fees != nil {
		if err := t.Fees.Max.check("fees max", 0, asm.MaxScriptNum); err != nil {
			return err
		}
	}
	if t.Packets != nil {
		if err := t.Packets.check(); err != nil {
			return err
		}
	}
	if t.Delegation != nil {
		return t.Delegation.check(t.Inputs)
	}
	return nil
}

// check runs before normalization, which drops immediate schedules, so their keys are checked here.
func (d *Delegation) check(inputs []Input) error {
	for _, n := range append(sortedKeys(d.Schedule), sortedKeys(d.Trigger)...) {
		if !slices.ContainsFunc(inputs, func(in Input) bool { return in.Name == n }) {
			return bad("delegation names no input %q", n)
		}
	}
	for _, n := range sortedKeys(d.Schedule) {
		s := d.Schedule[n]
		if err := s.check(); err != nil {
			return err
		}
	}
	for i, n := range d.Sealed {
		if !Name.MatchString(n) {
			return bad("bad sealed name %q", n)
		}
		if slices.Contains(d.Sealed[:i], n) {
			return bad("%q is sealed twice", n)
		}
	}
	for _, n := range sortedKeys(d.Trigger) {
		tr := d.Trigger[n]
		if err := tr.check(); err != nil {
			return err
		}
		if (tr.Group != "") != (len(d.Trigger) > 1) {
			return bad("trigger %q: group goes with several rules and only with several rules", n)
		}
	}
	return nil
}

func (in *Input) check() error {
	if !Name.MatchString(in.Name) {
		return bad("bad input name %q", in.Name)
	}
	if in.Type != "" && !slices.Contains(slotTypes, in.Type) {
		return bad("unknown slot type %q", in.Type)
	}
	return in.Contract.check()
}

func (s *Schedule) check() error {
	set := 0
	for _, isSet := range []bool{s.Immediate != nil, s.BeforeExpiry != nil, s.MinConfirmations != nil} {
		if isSet {
			set++
		}
	}
	switch {
	case set != 1:
		return bad("a schedule has exactly one field")
	case s.Immediate != nil && !*s.Immediate:
		return bad("immediate must be true")
	case s.BeforeExpiry != nil:
		return s.BeforeExpiry.check("before_expiry_seconds", 1, math.MaxUint32)
	case s.MinConfirmations != nil:
		return integer(*s.MinConfirmations, "min_confirmations", 1, math.MaxUint32)
	}
	return nil
}

func (c *Construction) check() error {
	if c.Taptree != "" && !namedVar.MatchString(c.Taptree) {
		return bad("taptree must name a bytes variable, got %q", c.Taptree)
	}
	return nil
}

func (o *Output) check() error {
	if !Name.MatchString(o.Name) {
		return bad("bad output name %q", o.Name)
	}
	if o.Type != "" && !slices.Contains(slotTypes, o.Type) {
		return bad("unknown slot type %q", o.Type)
	}
	if err := integer(o.Index, "index", 0, math.MaxUint16); err != nil {
		return err
	}
	if o.Locking.Contract != nil {
		if err := o.Locking.Contract.check(); err != nil {
			return err
		}
	}
	if len(o.Assets) > MaxSlots {
		return bad("output %q has more than %d asset routes", o.Name, MaxSlots)
	}
	for _, r := range o.Assets {
		if r.Asset != "" && !assetHex.MatchString(r.Asset) {
			return bad("bad asset id %q", r.Asset)
		}
		if r.Amount != nil && r.Asset == "" {
			return bad("an asset amount needs an asset")
		}
	}
	return nil
}

func (p *Packets) check() error {
	if err := integer(p.OutputIndex, "output_index", 0, math.MaxUint16); err != nil {
		return err
	}
	if p.Unmatched != "" && !slices.Contains(unmatcheds, p.Unmatched) {
		return bad("unmatched must be reject or drop")
	}
	if len(p.Rules) > MaxSlots {
		return bad("more than %d packet rules", MaxSlots)
	}
	for _, r := range p.Rules {
		if err := integer(r.Type, "rule type", 2, math.MaxUint8); err != nil {
			return err
		}
		if r.Type == 5 {
			return bad("packet type 5 is reserved")
		}
		if !slices.Contains(actions, r.Action) {
			return bad("unknown rule action %q", r.Action)
		}
		if (r.Data != nil) != (r.Action == "emit") {
			return bad("data goes with emit and only with emit")
		}
	}
	if len(p.Advertise) > MaxSlots {
		return bad("more than %d advertisements", MaxSlots)
	}
	for _, a := range p.Advertise {
		if a.Template != "self" && !idHex.MatchString(a.Template) {
			return bad("bad advertisement target %q", a.Template)
		}
		if len(a.Outputs) == 0 {
			return bad("an advertisement needs outputs")
		}
	}
	return nil
}

func (tr *Trigger) check() error {
	if err := integer(tr.Packet, "trigger packet", 0, math.MaxUint8); err != nil {
		return err
	}
	if !slices.Contains(decodes, tr.Decode) {
		return bad("trigger decode must be tlv or raw")
	}
	if err := integer(tr.ExpiresAfter, "expires_after_seconds", 1, math.MaxInt32); err != nil {
		return err
	}
	if err := integer(tr.MinValue, "trigger min_value", 0, asm.MaxScriptNum); err != nil {
		return err
	}
	if len(tr.Require) == 0 {
		return bad("a trigger rule requires at least one field")
	}
	if len(tr.Capture) == 0 {
		return bad("a trigger rule captures at least one variable")
	}
	return nil
}

func integer(n int64, what string, lo, hi int64) error {
	if n < lo || n > hi {
		return bad("%s must be an integer in %d..%d, got %d", what, lo, hi, n)
	}
	return nil
}

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

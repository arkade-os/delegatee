package template

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	templateFormat = "delegateed-template/v1"
	maxSlots       = 255
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

// Resolver returns the stored document of an artifact.
type Resolver func(ctx context.Context, artifactID string) ([]byte, error)

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
	artifacts []string
}

type construction struct {
	def  *Definition
	args map[string]byteTemplate // flattened constructor name → binding
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

type locking struct {
	from     int          // input index, -1 when unused
	script   byteTemplate // set when the locking is a script template
	contract *construction
}

type assetRoute struct {
	from   int
	asset  []byte       // 34 bytes, nil for catch-all
	amount byteTemplate // nil for the remainder
}

type output struct {
	name    string
	index   uint16
	onchain bool
	from    int
	amount  byteTemplate // nil: the remainder
	locking locking
	assets  []assetRoute
}

type rule struct {
	typ    uint8
	action string // copy | drop | emit
	from   int
	data   byteTemplate
}

type advert struct {
	self    bool
	target  [32]byte
	outputs []int // output positions in t.outputs, in the target's slot order
}

type secret struct {
	typ        string
	from       int
	ciphertext byteTemplate
}

type fee struct {
	from        int
	max         uint64
	maxVariable string // an int variable holding max
}

type packetSpec struct {
	index   uint16
	drop    bool // unmatched source packets are dropped, not rejected
	rules   []rule
	adverts []advert
}

var (
	idHex    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	assetHex = regexp.MustCompile(`^[0-9a-f]{68}$`)
)

// Parse decodes and validates a template; defaults are stripped as read so the rest hashes to the id.
func Parse(ctx context.Context, doc []byte, resolve Resolver) (*Template, error) {
	v, err := decodeStrict(doc)
	if err != nil {
		return nil, err
	}
	m, err := object(ErrInvalidTemplate, v, "template", []string{"format", "type", "inputs", "outputs"}, "variables", "secrets", "fees", "packets")
	if err != nil {
		return nil, err
	}
	if m["format"] != templateFormat {
		return nil, bad("format must be %q", templateFormat)
	}
	typ, _ := m["type"].(string)
	if !slices.Contains([]Type{Intent, Offchain, Onchain}, Type(typ)) {
		return nil, bad("unknown type %q", typ)
	}
	p := &parser{ctx: ctx, resolve: resolve, t: &Template{
		typ: Type(typ), variables: map[string]string{}, secrets: map[string]secret{},
	}}
	secrets, err := p.declarations(m)
	if err != nil {
		return nil, err
	}
	ins, err := slots(m, "inputs")
	if err != nil {
		return nil, err
	}
	for _, in := range ins {
		if err := p.input(in); err != nil {
			return nil, err
		}
	}
	if err := p.secretBodies(secrets); err != nil {
		return nil, err
	}
	outs, err := slots(m, "outputs")
	if err != nil {
		return nil, err
	}
	for _, o := range outs {
		if err := p.output(o); err != nil {
			return nil, err
		}
	}
	if err := p.t.checkPrograms(); err != nil {
		return nil, err
	}
	if err := p.t.checkBalances(); err != nil {
		return nil, err
	}
	if err := p.fees(m); err != nil {
		return nil, err
	}
	if err := p.packets(m); err != nil {
		return nil, err
	}
	if err := p.t.checkPlacement(); err != nil {
		return nil, err
	}
	b, err := canonical(m)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	p.t.id = hex.EncodeToString(sum[:])
	return p.t, nil
}

// ID is the hex SHA-256 of the canonical document.
func (t *Template) ID() string { return t.id }

// Type is the kind of transaction the template builds.
func (t *Template) Type() Type { return t.typ }

// Variables lists the declared variables, sorted by name.
func (t *Template) Variables() []Field {
	out := make([]Field, 0, len(t.variables))
	for _, n := range slices.Sorted(maps.Keys(t.variables)) {
		out = append(out, Field{Name: n, Type: t.variables[n]})
	}
	return out
}

// Inputs describes the template inputs in slot order.
func (t *Template) Inputs() []Slot {
	out := make([]Slot, 0, len(t.inputs))
	for _, in := range t.inputs {
		out = append(out, Slot{Name: in.name, Onchain: in.onchain, Schedule: in.schedule})
	}
	return out
}

// Artifacts lists the referenced artifact ids in order of first appearance.
func (t *Template) Artifacts() []string { return slices.Clone(t.artifacts) }

// Secrets reports whether the template declares secrets, which Instantiate must decrypt.
func (t *Template) Secrets() bool { return len(t.secrets) > 0 }

type parser struct {
	ctx     context.Context
	resolve Resolver
	t       *Template
}

func (p *parser) declarations(m map[string]any) (map[string]any, error) {
	vars, err := dict(m, "variables")
	if err != nil {
		return nil, err
	}
	for n, v := range vars {
		if err := ident(n, "variable"); err != nil {
			return nil, err
		}
		typ, _ := v.(string)
		if !slices.Contains(scalarTypes, typ) {
			return nil, bad("variable %q has unsupported type %v", n, v)
		}
		p.t.variables[n] = typ
	}
	secrets, err := dict(m, "secrets")
	if err != nil {
		return nil, err
	}
	for n, v := range secrets {
		if err := ident(n, "secret"); err != nil {
			return nil, err
		}
		if _, dup := p.t.variables[n]; dup {
			return nil, bad("%q is both a variable and a secret", n)
		}
		sm, err := object(ErrInvalidTemplate, v, "secret", []string{"type", "from", "ciphertext"})
		if err != nil {
			return nil, err
		}
		typ, _ := sm["type"].(string)
		if !slices.Contains(scalarTypes, typ) {
			return nil, bad("secret %q has unsupported type %v", n, sm["type"])
		}
		p.t.secrets[n] = secret{typ: typ}
	}
	if len(vars)+len(secrets) > maxSlots {
		return nil, bad("more than %d variables and secrets", maxSlots)
	}
	return secrets, nil
}

func (p *parser) secretBodies(secrets map[string]any) error {
	for n, v := range secrets {
		sm := v.(map[string]any)
		s := p.t.secrets[n]
		var err error
		if s.from, err = p.inputIndex(sm["from"], "secret "+n); err != nil {
			return err
		}
		if s.ciphertext, err = p.bind(sm["ciphertext"], "", false); err != nil {
			return err
		}
		p.t.secrets[n] = s
	}
	return nil
}

func (p *parser) input(v any) error {
	m, err := object(ErrInvalidTemplate, v, "input", []string{"name", "contract", "spend"}, "type", "schedule")
	if err != nil {
		return err
	}
	var in input
	if in.name, err = p.slotName(m["name"], "input", slices.ContainsFunc(p.t.inputs, func(o input) bool { return o.name == m["name"] })); err != nil {
		return err
	}
	if in.onchain, err = p.slotType(m); err != nil {
		return err
	}
	if raw, ok := m["schedule"]; ok {
		if in.schedule, in.leadVariable, err = p.schedule(raw, in.onchain); err != nil {
			return err
		}
		if in.schedule == (Schedule{}) && in.leadVariable == "" {
			delete(m, "schedule")
		}
	}
	c, err := p.construction(m["contract"])
	if err != nil {
		return err
	}
	in.contract = *c
	if err := p.spend(&in, m["spend"]); err != nil {
		return err
	}
	p.t.inputs = append(p.t.inputs, in)
	return nil
}

func (p *parser) schedule(v any, onchain bool) (Schedule, string, error) {
	m, err := object(ErrInvalidTemplate, v, "schedule", nil, "immediate", "before_expiry_seconds", "min_confirmations")
	if err != nil {
		return Schedule{}, "", err
	}
	if len(m) != 1 {
		return Schedule{}, "", bad("a schedule has exactly one field")
	}
	switch {
	case m["immediate"] == true:
		return Schedule{}, "", nil
	case m["before_expiry_seconds"] != nil && !onchain:
		if name, ok, err := p.intVariable(m["before_expiry_seconds"]); ok {
			return Schedule{}, name, err
		}
		n, err := integer(m["before_expiry_seconds"], "before_expiry_seconds", 1, math.MaxUint32)
		return Schedule{BeforeExpiry: time.Duration(n) * time.Second}, "", err
	case m["min_confirmations"] != nil && onchain:
		n, err := integer(m["min_confirmations"], "min_confirmations", 1, math.MaxUint32)
		return Schedule{MinConfirmations: int(n)}, "", err
	}
	return Schedule{}, "", bad("schedule %v does not fit the input", v)
}

// intVariable reports whether v is a string, which must then name an int variable.
func (p *parser) intVariable(v any) (string, bool, error) {
	s, ok := v.(string)
	if !ok {
		return "", false, nil
	}
	name := strings.TrimSuffix(strings.TrimPrefix(s, "<"), ">")
	if s != "<"+name+">" || p.t.variables[name] != "int" {
		return "", true, bad("%q is not an int variable", s)
	}
	return name, true, nil
}

func (p *parser) construction(v any) (*construction, error) {
	m, err := object(ErrInvalidTemplate, v, "contract", []string{"definition"}, "arguments")
	if err != nil {
		return nil, err
	}
	def, err := p.definition(m)
	if err != nil {
		return nil, err
	}
	flat, err := def.flatConstructor()
	if err != nil {
		return nil, err
	}
	args, err := dict(m, "arguments")
	if err != nil {
		return nil, err
	}
	c := &construction{def: def, args: map[string]byteTemplate{}}
	for _, f := range flat {
		raw, ok := args[f.Name]
		if !ok {
			return nil, bad("missing argument %q", f.Name)
		}
		if ref, ok := raw.(map[string]any); ok {
			if c.args[f.Name], err = program(ref, f.Type); err != nil {
				return nil, err
			}
			continue
		}
		if c.args[f.Name], err = p.scriptBind(raw, f.Type); err != nil {
			return nil, err
		}
	}
	if len(args) != len(flat) {
		return nil, bad("contract %q has arguments outside its constructor", def.ContractName)
	}
	return c, nil
}

// program binds the witness program of an output built from a contract.
func program(ref map[string]any, typ string) (byteTemplate, error) {
	if _, err := object(ErrInvalidTemplate, ref, "program reference", []string{"program"}); err != nil {
		return nil, err
	}
	name, _ := ref["program"].(string)
	if typ != "bytes32" {
		return nil, bad("output program %q cannot fill a %s field", name, typ)
	}
	return byteTemplate{{program: name}}, nil
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

func hasProgram(b byteTemplate) bool {
	return slices.ContainsFunc(b, func(p piece) bool { return p.program != "" })
}

func (p *parser) definition(m map[string]any) (*Definition, error) {
	ref, ok := m["definition"].(map[string]any)
	if _, isRef := ref["artifact"]; !ok || !isRef {
		d, err := parseDefinition(m["definition"])
		if err != nil {
			return nil, err
		}
		// an inline definition is hashed in its canonical form
		m["definition"] = d.json()
		return d, nil
	}
	if _, err := object(ErrInvalidTemplate, ref, "artifact reference", []string{"artifact"}); err != nil {
		return nil, err
	}
	id, _ := ref["artifact"].(string)
	if !idHex.MatchString(id) {
		return nil, bad("bad artifact id %v", ref["artifact"])
	}
	if p.resolve == nil {
		return nil, bad("no resolver for artifact %s", id)
	}
	doc, err := p.resolve(p.ctx, id)
	if err != nil {
		return nil, fmt.Errorf("artifact %s: %w", id, err)
	}
	a, err := ParseArtifact(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: artifact %s: %w", ErrInvalidTemplate, id, err)
	}
	if a.ID != id {
		return nil, bad("artifact %s resolves to a document with id %s", id, a.ID)
	}
	if !slices.Contains(p.t.artifacts, id) {
		p.t.artifacts = append(p.t.artifacts, id)
	}
	return &a.Definition, nil
}

func (p *parser) spend(in *input, v any) error {
	m, err := object(ErrInvalidTemplate, v, "spend", []string{"function", "leaf"}, "arguments", "witness")
	if err != nil {
		return err
	}
	fname, _ := m["function"].(string)
	f, err := in.contract.def.function(fname)
	if err != nil {
		return err
	}
	lname, _ := m["leaf"].(string)
	l, err := f.leaf(lname)
	if err != nil {
		return err
	}
	// arkd sets an absolute locktime only when it builds an offchain spend
	if slices.ContainsFunc(l.Asm, isCLTV) && p.t.typ != Offchain {
		return fmt.Errorf("%w: leaf %q needs an absolute locktime, which only an offchain template sets", ErrUnsupported, l.Name)
	}
	in.function, in.leaf = f.Name, l.Name
	args, err := list(m, "arguments")
	if err != nil {
		return err
	}
	var want []Field
	if f.Arkade != nil {
		want = f.Arkade.Inputs
	}
	if len(args) != len(want) {
		return bad("function %q takes %d arguments, got %d", f.Name, len(want), len(args))
	}
	for i, a := range args {
		b, err := p.bind(a, want[i].Type, true)
		if err != nil {
			return err
		}
		in.arguments = append(in.arguments, b)
	}
	wit, err := dict(m, "witness")
	if err != nil {
		return err
	}
	in.witness = map[string]byteTemplate{}
	for _, w := range l.Witness {
		if w.Type == "signature" {
			if !w.Injected {
				return bad("leaf %q needs signature %q, which nobody injects", l.Name, w.Name)
			}
			continue
		}
		raw, ok := wit[w.Name]
		if !ok {
			return bad("witness item %q is not bound", w.Name)
		}
		if in.witness[w.Name], err = p.bind(raw, w.Type, true); err != nil {
			return err
		}
	}
	if len(wit) != len(in.witness) {
		return bad("spend binds witness items that are signatures or absent from leaf %q", l.Name)
	}
	return nil
}

func (p *parser) fees(m map[string]any) error {
	if m["fees"] == nil {
		delete(m, "fees")
		return nil
	}
	if p.t.typ == Offchain {
		return bad("an offchain template has no fees")
	}
	fm, err := object(ErrInvalidTemplate, m["fees"], "fees", []string{"from", "max"})
	if err != nil {
		return err
	}
	f := &fee{}
	if f.from, err = p.inputIndex(fm["from"], "fees"); err != nil {
		return err
	}
	name, isVariable, err := p.intVariable(fm["max"])
	if err != nil {
		return err
	}
	if isVariable {
		f.maxVariable = name
	} else {
		max, err := integer(fm["max"], "fees max", 0, maxScriptNum)
		if err != nil {
			return err
		}
		f.max = uint64(max)
	}
	p.t.fee = f
	return nil
}

// bind type-checks literals and lone names here, the rest at evaluation; typ "" is any bytes.
func (p *parser) bind(v any, typ string, secrets bool) (byteTemplate, error) {
	switch v.(type) {
	case json.Number:
		if typ != "int" {
			return nil, bad("an integer cannot fill a %s field", typ)
		}
	case bool:
		if typ != "bool" {
			return nil, bad("a boolean cannot fill a %s field", typ)
		}
	}
	b, err := parseBinding(v)
	if err != nil {
		return nil, err
	}
	for _, n := range b.names() {
		_, isVar := p.t.variables[n]
		_, isSecret := p.t.secrets[n]
		if !isVar && (!secrets || !isSecret) {
			return nil, bad("undeclared name %q", n)
		}
	}
	for _, pc := range b {
		if err := checkExpression(pc.expr); err != nil {
			return nil, err
		}
	}
	if typ == "" {
		return b, nil
	}
	if lit, ok := b.literal(); ok {
		if err := canonicalBytes(typ, lit); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
		}
	}
	if len(b) == 1 && b[0].name != "" && typ != "bytes" {
		n := b[0].name
		declared, isVar := p.t.variables[n]
		if !isVar {
			declared = p.t.secrets[n].typ
		}
		if declared != typ {
			return nil, bad("%s %q cannot fill a %s field", declared, n, typ)
		}
	}
	return b, nil
}

// tapscripts are stored and returned: a secret may appear only under a hash
func (p *parser) scriptBind(v any, typ string) (byteTemplate, error) {
	b, err := p.bind(v, typ, true)
	if err != nil {
		return nil, err
	}
	for _, pc := range b {
		for _, n := range (byteTemplate{pc}).names() {
			if _, ok := p.t.secrets[n]; ok && (pc.expr == nil || !slices.Contains(hashOps, pc.expr[len(pc.expr)-1])) {
				return nil, bad("secret %q must be hashed in a script", n)
			}
		}
	}
	return b, nil
}

var hashOps = []string{"OP_HASH160", "OP_SHA256", "OP_HASH256", "OP_RIPEMD160"}

// amount requires a positive literal.
func (p *parser) amount(v any) (byteTemplate, error) {
	b, err := p.bind(v, "int", true)
	if err != nil {
		return nil, err
	}
	if lit, ok := b.literal(); ok {
		if n, _ := parseScriptNum(lit); n < 1 {
			return nil, bad("an amount must be positive")
		}
	}
	return b, nil
}

func (p *parser) inputIndex(v any, what string) (int, error) {
	i := slices.IndexFunc(p.t.inputs, func(in input) bool { return in.name == v })
	if i < 0 {
		return 0, bad("%s names no input: %v", what, v)
	}
	return i, nil
}

func (p *parser) slotName(v any, what string, taken bool) (string, error) {
	s, _ := v.(string)
	if err := ident(s, what); err != nil {
		return "", err
	}
	if taken {
		return "", bad("duplicate %s %q", what, s)
	}
	return s, nil
}

// slotType removes the type from m when it is the mode's default.
func (p *parser) slotType(m map[string]any) (bool, error) {
	def := Offchain
	if p.t.typ == Onchain {
		def = Onchain
	}
	typ := def
	if raw, ok := m["type"]; ok {
		s, _ := raw.(string)
		if typ = Type(s); typ != Onchain && typ != Offchain {
			return false, bad("unknown slot type %v", raw)
		}
		if typ == def {
			delete(m, "type")
		}
	}
	if p.t.typ != Intent && typ != def {
		return false, bad("%s slot in a template of type %s", typ, p.t.typ)
	}
	return typ == Onchain, nil
}

func ident(s, what string) error {
	if !nameRe.MatchString(s) {
		return bad("bad %s name %q", what, s)
	}
	return nil
}

func integer(v any, what string, lo, hi int64) (int64, error) {
	n, _ := v.(json.Number)
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil || i < lo || i > hi {
		return 0, bad("%s must be an integer in %d..%d, got %v", what, lo, hi, v)
	}
	return i, nil
}

// dict removes an empty object field from m.
func dict(m map[string]any, key string) (map[string]any, error) {
	raw, ok := m[key]
	if !ok {
		return nil, nil
	}
	d, ok := raw.(map[string]any)
	if !ok {
		return nil, bad("%s is not an object", key)
	}
	if len(d) == 0 {
		delete(m, key)
	}
	return d, nil
}

func slots(m map[string]any, key string) ([]any, error) {
	l, err := list(m, key)
	if err == nil && (len(l) == 0 || len(l) > maxSlots) {
		err = bad("a template has 1 to %d %s", maxSlots, key)
	}
	return l, err
}

// list removes an empty array field from m.
func list(m map[string]any, key string) ([]any, error) {
	raw, ok := m[key]
	if !ok {
		return nil, nil
	}
	l, ok := raw.([]any)
	if !ok {
		return nil, bad("%s is not an array", key)
	}
	if len(l) == 0 {
		delete(m, key)
	}
	return l, nil
}

func bad(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidTemplate, fmt.Sprintf(format, args...))
}

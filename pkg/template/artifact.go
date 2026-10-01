package template

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Field is a named, typed value: a constructor input, a struct field or a covenant input.
type Field struct{ Name, Type string }

// Struct is a user-defined constructor type.
type Struct struct {
	Name   string
	Fields []Field
}

// WitnessItem is a stack item a leaf's spender provides; Injected signatures are added by someone else.
type WitnessItem struct {
	Name, Type, Encoding string
	Injected             bool
}

// Leaf is one tapscript of a function.
type Leaf struct {
	Name    string
	Asm     []string
	Witness []WitnessItem
}

// Covenant is the emulator script a function runs, with its inputs in declaration order.
type Covenant struct {
	Inputs []Field
	Asm    []string
}

// Function is a spending path of a contract: its tapscript leaves and, optionally, a covenant.
type Function struct {
	Name   string
	Arkade *Covenant // nil for a plain tapscript path
	Leaves []Leaf
}

// Definition is a contract as a compiler emits it, without metadata.
type Definition struct {
	ContractName      string
	ConstructorInputs []Field
	Structs           []Struct
	Functions         []Function
}

// Artifact is a parsed contract definition and its content id.
type Artifact struct {
	ID         string
	Definition Definition
}

const (
	maxArray = 1024
	// bounds the flattened constructor and the walk that builds it
	maxConstructor = 1024
)

var (
	scalarTypes = []string{"pubkey", "bytes", "bytes20", "bytes32", "asset", "int", "bool"}
	encodings   = []string{"compressed-33", "schnorr-64", "raw", "raw-20", "raw-32", "scriptnum"}
	metadata    = []string{"formatVersion", "source", "compiler", "updatedAt", "fingerprint"}
	builtins    = map[string][]Field{
		"AssetId":  {{"txid", "bytes32"}, {"gidx", "int"}},
		"Outpoint": {{"txid", "bytes32"}, {"vout", "int"}},
		"ECPoint":  {{"x", "int"}, {"y", "int"}},
	}

	arrayType   = regexp.MustCompile(`^([a-z0-9]+)\[([1-9][0-9]*)\]$`)
	decimalTok  = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
	hexTok      = regexp.MustCompile(`^0x([0-9a-f]{2})+$`)
	placeholder = regexp.MustCompile(`^<([^<>]+)>$`)
)

// ParseArtifact parses a compiler artifact, dropping its metadata, and derives its id.
func ParseArtifact(doc []byte) (*Artifact, error) {
	v, err := decodeStrict(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArtifact, err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: not an object", ErrInvalidArtifact)
	}
	for _, k := range metadata {
		delete(m, k)
	}
	d, err := parseDefinition(m)
	if err != nil {
		return nil, err
	}
	b, err := canonical(d.json())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidArtifact, err)
	}
	id := sha256.Sum256(b)
	return &Artifact{ID: hex.EncodeToString(id[:]), Definition: *d}, nil
}

func parseDefinition(v any) (*Definition, error) {
	m, err := object(ErrInvalidArtifact, v, "definition", []string{"contractName", "constructorInputs", "functions"}, "structs")
	if err != nil {
		return nil, err
	}
	d := &Definition{}
	if d.ContractName, err = name(m["contractName"], "contractName"); err != nil {
		return nil, err
	}
	if d.ConstructorInputs, err = parseFields(m["constructorInputs"], "constructor input"); err != nil {
		return nil, err
	}
	if raw, ok := m["structs"]; ok {
		if d.Structs, err = parseStructs(raw); err != nil {
			return nil, err
		}
	}
	flat, err := d.flatConstructor()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, f := range flat {
		if _, dup := names[f.Name]; dup {
			return nil, invalid("duplicate constructor field %q", f.Name)
		}
		names[f.Name] = f.Type
	}

	list, ok := m["functions"].([]any)
	if !ok || len(list) == 0 {
		return nil, invalid("functions must be a non-empty array")
	}
	for _, e := range list {
		f, err := parseFunction(e)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(d.Functions, func(o Function) bool { return o.Name == f.Name }) {
			return nil, invalid("duplicate function %q", f.Name)
		}
		d.Functions = append(d.Functions, *f)
	}
	for _, f := range d.Functions {
		if f.Arkade != nil {
			if err := d.checkAsm(f.Arkade.Asm, names); err != nil {
				return nil, err
			}
		}
		for _, l := range f.Leaves {
			if err := d.checkAsm(l.Asm, names); err != nil {
				return nil, err
			}
		}
	}
	return d, nil
}

// a field can only use a struct declared before it
func parseStructs(v any) ([]Struct, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, invalid("structs is not an array")
	}
	declared := map[string]bool{}
	for n := range builtins {
		declared[n] = true
	}
	var out []Struct
	for _, e := range list {
		m, err := object(ErrInvalidArtifact, e, "struct", []string{"name", "fields"})
		if err != nil {
			return nil, err
		}
		s := Struct{}
		if s.Name, err = name(m["name"], "struct name"); err != nil {
			return nil, err
		}
		if declared[s.Name] {
			return nil, invalid("duplicate struct %q", s.Name)
		}
		if s.Fields, err = parseFields(m["fields"], "struct field"); err != nil {
			return nil, err
		}
		for _, f := range s.Fields {
			if !validType(f.Type, declared) {
				return nil, invalid("unsupported type %q", f.Type)
			}
		}
		declared[s.Name] = true
		out = append(out, s)
	}
	return out, nil
}

func parseFunction(v any) (*Function, error) {
	m, err := object(ErrInvalidArtifact, v, "function", []string{"name", "leaves"}, "arkade")
	if err != nil {
		return nil, err
	}
	f := &Function{}
	if f.Name, err = name(m["name"], "function name"); err != nil {
		return nil, err
	}
	if raw, ok := m["arkade"]; ok {
		am, err := object(ErrInvalidArtifact, raw, "arkade", []string{"inputs", "asm"})
		if err != nil {
			return nil, err
		}
		c := &Covenant{}
		if c.Inputs, err = parseFields(am["inputs"], "arkade input"); err != nil {
			return nil, err
		}
		for _, in := range c.Inputs {
			if !slices.Contains(scalarTypes, in.Type) {
				return nil, invalid("unsupported arkade input type %q", in.Type)
			}
		}
		if c.Asm, err = strs(am["asm"], "asm"); err != nil {
			return nil, err
		}
		f.Arkade = c
	}
	list, ok := m["leaves"].([]any)
	if !ok || len(list) == 0 {
		return nil, invalid("function %q needs leaves", f.Name)
	}
	for _, e := range list {
		l, err := parseLeaf(e)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(f.Leaves, func(o Leaf) bool { return o.Name == l.Name }) {
			return nil, invalid("duplicate leaf %q", l.Name)
		}
		f.Leaves = append(f.Leaves, *l)
	}
	return f, nil
}

func parseLeaf(v any) (*Leaf, error) {
	m, err := object(ErrInvalidArtifact, v, "leaf", []string{"name", "asm", "witness"})
	if err != nil {
		return nil, err
	}
	l := &Leaf{}
	if l.Name, err = name(m["name"], "leaf name"); err != nil {
		return nil, err
	}
	if l.Asm, err = strs(m["asm"], "asm"); err != nil {
		return nil, err
	}
	ws, ok := m["witness"].([]any)
	if !ok {
		return nil, invalid("witness is not an array")
	}
	for _, w := range ws {
		wm, err := object(ErrInvalidArtifact, w, "witness item", []string{"name", "type", "encoding"}, "injected")
		if err != nil {
			return nil, err
		}
		it := WitnessItem{}
		if it.Name, err = name(wm["name"], "witness name"); err != nil {
			return nil, err
		}
		if it.Type, _ = wm["type"].(string); it.Type != "signature" && !slices.Contains(scalarTypes, it.Type) {
			return nil, invalid("unsupported witness type %v", wm["type"])
		}
		if it.Encoding, _ = wm["encoding"].(string); !slices.Contains(encodings, it.Encoding) {
			return nil, invalid("unsupported witness encoding %v", wm["encoding"])
		}
		if raw, ok := wm["injected"]; ok {
			if it.Injected, ok = raw.(bool); !ok {
				return nil, invalid("injected is not a boolean")
			}
		}
		if slices.ContainsFunc(l.Witness, func(o WitnessItem) bool { return o.Name == it.Name }) {
			return nil, invalid("duplicate witness item %q", it.Name)
		}
		l.Witness = append(l.Witness, it)
	}
	return l, nil
}

// covenant inputs reach the VM on the stack and are never placeholders
func (d *Definition) checkAsm(asm []string, names map[string]string) error {
	for _, tok := range asm {
		if strings.HasPrefix(tok, "OP_") {
			if _, err := opcode(tok); err != nil {
				return invalid("%v", err)
			}
			continue
		}
		if decimalTok.MatchString(tok) {
			if _, err := parseDecimal(tok); err != nil {
				return invalid("%v", err)
			}
			continue
		}
		if hexTok.MatchString(tok) {
			continue
		}
		p := placeholder.FindStringSubmatch(tok)
		if p == nil {
			return invalid("unsupported token %q", tok)
		}
		parts := strings.Split(p[1], ":")
		switch {
		case p[1] == "SERVER_KEY", p[1] == "DELEGATE_KEY":
		case parts[0] == "EMULATOR_KEY" && len(parts) == 2:
			if !d.hasCovenant(parts[1]) {
				return invalid("%q names no function with arkade", tok)
			}
		case parts[0] == "TWEAK" && len(parts) == 3:
			if names[parts[1]] != "pubkey" || !d.hasCovenant(parts[2]) {
				return invalid("bad tweak %q", tok)
			}
		case len(parts) == 1:
			if _, ok := names[p[1]]; !ok {
				return invalid("unknown placeholder %q", tok)
			}
		default:
			return invalid("unsupported placeholder %q", tok)
		}
	}
	return nil
}

func (d *Definition) hasCovenant(fn string) bool {
	return slices.ContainsFunc(d.Functions, func(f Function) bool { return f.Name == fn && f.Arkade != nil })
}

// json is the canonical form the id commits to.
func (d *Definition) json() map[string]any {
	fields := func(fs []Field) []any {
		out := []any{}
		for _, f := range fs {
			out = append(out, map[string]any{"name": f.Name, "type": f.Type})
		}
		return out
	}
	strList := func(ss []string) []any {
		out := []any{}
		for _, s := range ss {
			out = append(out, s)
		}
		return out
	}
	structs := []any{}
	for _, s := range d.Structs {
		structs = append(structs, map[string]any{"name": s.Name, "fields": fields(s.Fields)})
	}
	funcs := []any{}
	for _, f := range d.Functions {
		fm := map[string]any{"name": f.Name}
		if f.Arkade != nil {
			fm["arkade"] = map[string]any{"inputs": fields(f.Arkade.Inputs), "asm": strList(f.Arkade.Asm)}
		}
		leaves := []any{}
		for _, l := range f.Leaves {
			ws := []any{}
			for _, w := range l.Witness {
				wm := map[string]any{"name": w.Name, "type": w.Type, "encoding": w.Encoding}
				if w.Injected {
					wm["injected"] = true
				}
				ws = append(ws, wm)
			}
			leaves = append(leaves, map[string]any{"name": l.Name, "asm": strList(l.Asm), "witness": ws})
		}
		fm["leaves"] = leaves
		funcs = append(funcs, fm)
	}
	return map[string]any{
		"contractName":      d.ContractName,
		"constructorInputs": fields(d.ConstructorInputs),
		"structs":           structs,
		"functions":         funcs,
	}
}

// flatConstructor lists the scalar constructor fields: arrays as name.0, structs as name.field.
func (d *Definition) flatConstructor() ([]Field, error) {
	var out []Field
	steps := 0
	var walk func(name, typ string) error
	walk = func(name, typ string) error {
		if steps++; steps > maxConstructor || len(out) >= maxConstructor {
			return invalid("constructor flattens to more than %d fields", maxConstructor)
		}
		if slices.Contains(scalarTypes, typ) {
			out = append(out, Field{name, typ})
			return nil
		}
		if m := arrayType.FindStringSubmatch(typ); m != nil {
			n, _ := strconv.Atoi(m[2])
			if n > maxArray || !slices.Contains(scalarTypes, m[1]) {
				return invalid("unsupported type %q", typ)
			}
			if len(out)+n > maxConstructor {
				return invalid("constructor flattens to more than %d fields", maxConstructor)
			}
			for i := range n {
				out = append(out, Field{name + "." + strconv.Itoa(i), m[1]})
			}
			return nil
		}
		fs, ok := builtins[typ]
		if !ok {
			i := slices.IndexFunc(d.Structs, func(s Struct) bool { return s.Name == typ })
			if i < 0 {
				return invalid("unsupported type %q", typ)
			}
			fs = d.Structs[i].Fields
		}
		for _, f := range fs {
			if err := walk(name+"."+f.Name, f.Type); err != nil {
				return err
			}
		}
		return nil
	}
	for _, f := range d.ConstructorInputs {
		if err := walk(f.Name, f.Type); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (d *Definition) function(name string) (*Function, error) {
	i := slices.IndexFunc(d.Functions, func(f Function) bool { return f.Name == name })
	if i < 0 {
		return nil, fmt.Errorf("%w: unknown function %q", ErrInvalidTemplate, name)
	}
	return &d.Functions[i], nil
}

func (f *Function) leaf(name string) (*Leaf, error) {
	i := slices.IndexFunc(f.Leaves, func(l Leaf) bool { return l.Name == name })
	if i < 0 {
		return nil, fmt.Errorf("%w: unknown leaf %q", ErrInvalidTemplate, name)
	}
	return &f.Leaves[i], nil
}

func validType(t string, structs map[string]bool) bool {
	if m := arrayType.FindStringSubmatch(t); m != nil {
		n, _ := strconv.Atoi(m[2])
		return n <= maxArray && slices.Contains(scalarTypes, m[1])
	}
	return slices.Contains(scalarTypes, t) || structs[t]
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArtifact, fmt.Sprintf(format, args...))
}

// object requires every required key and none outside required and optional.
func object(sentinel error, v any, what string, required []string, optional ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not an object", sentinel, what)
	}
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return nil, fmt.Errorf("%w: %s misses %q", sentinel, what, k)
		}
	}
	for k := range m {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return nil, fmt.Errorf("%w: %s has unknown field %q", sentinel, what, k)
		}
	}
	return m, nil
}

func name(v any, what string) (string, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", invalid("%s must be a non-empty string", what)
	}
	return s, nil
}

func strs(v any, what string) ([]string, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, invalid("%s is not an array", what)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, invalid("%s holds a non-string", what)
		}
		out = append(out, s)
	}
	return out, nil
}

func parseFields(v any, what string) ([]Field, error) {
	list, ok := v.([]any)
	if !ok {
		return nil, invalid("%ss is not an array", what)
	}
	out := make([]Field, 0, len(list))
	for _, e := range list {
		m, err := object(ErrInvalidArtifact, e, what, []string{"name", "type"})
		if err != nil {
			return nil, err
		}
		n, err := name(m["name"], what+" name")
		if err != nil {
			return nil, err
		}
		t, err := name(m["type"], what+" type")
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(out, func(f Field) bool { return f.Name == n }) {
			return nil, invalid("duplicate %s %q", what, n)
		}
		out = append(out, Field{n, t})
	}
	return out, nil
}

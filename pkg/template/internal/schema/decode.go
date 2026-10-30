package schema

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/arkade-os/delegatee/pkg/template/internal/abi"
)

// Decode parses a document strictly: unknown keys, keys in another case, null where a value is
// due, and shapes other than the declared ones are refused, then the syntactic rules run.
func Decode(doc []byte) (*Template, error) {
	v, err := jcsDecode(doc)
	if err != nil {
		return nil, err
	}
	t := &Template{}
	if err := decodeInto(v, reflect.ValueOf(t).Elem(), "template"); err != nil {
		return nil, err
	}
	if err := t.check(); err != nil {
		return nil, err
	}
	return t, nil
}

// union is a field that accepts more than one JSON shape and decodes itself.
type union interface {
	fromJSON(v any, path string) error
}

var unionType = reflect.TypeFor[union]()

func decodeInto(v any, dst reflect.Value, path string) error {
	if dst.CanAddr() && dst.Addr().Type().Implements(unionType) {
		return dst.Addr().Interface().(union).fromJSON(v, path)
	}
	switch dst.Kind() {
	case reflect.Pointer:
		dst.Set(reflect.New(dst.Type().Elem()))
		return decodeInto(v, dst.Elem(), path)
	case reflect.Struct:
		return decodeStruct(v, dst, path)
	case reflect.String:
		// no field of the format takes an empty string; refusing it keeps a given "" apart from an absent key
		s, ok := v.(string)
		if !ok || s == "" {
			return bad("%s must be a non-empty string", path)
		}
		dst.SetString(s)
	case reflect.Bool:
		b, ok := v.(bool)
		if !ok {
			return bad("%s must be a boolean", path)
		}
		dst.SetBool(b)
	case reflect.Int64:
		n, ok := v.(json.Number)
		if !ok {
			return bad("%s must be an integer", path)
		}
		i, err := strconv.ParseInt(string(n), 10, 64)
		if err != nil {
			return bad("%s must be an integer", path)
		}
		dst.SetInt(i)
	case reflect.Slice:
		list, ok := v.([]any)
		if !ok {
			return bad("%s must be an array", path)
		}
		out := reflect.MakeSlice(dst.Type(), len(list), len(list))
		for i, e := range list {
			if err := decodeInto(e, out.Index(i), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		dst.Set(out)
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok {
			return bad("%s must be an object", path)
		}
		out := reflect.MakeMapWithSize(dst.Type(), len(m))
		for k, e := range m {
			if e == nil {
				return bad("%s.%s is null", path, k)
			}
			elem := reflect.New(dst.Type().Elem()).Elem()
			if err := decodeInto(e, elem, path+"."+k); err != nil {
				return err
			}
			out.SetMapIndex(reflect.ValueOf(k), elem)
		}
		dst.Set(out)
	default:
		return bad("%s: unsupported field kind %s", path, dst.Kind())
	}
	return nil
}

// decodeStruct matches keys to json tags exactly; a missing key is an error unless the field is
// opt, a null value unless the field is null.
func decodeStruct(v any, dst reflect.Value, path string) error {
	m, ok := v.(map[string]any)
	if !ok {
		return bad("%s must be an object", path)
	}
	typ := dst.Type()
	known := make([]string, 0, typ.NumField())
	for i := range typ.NumField() {
		f := typ.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		opts := strings.Split(f.Tag.Get("schema"), ",")
		known = append(known, key)
		val, present := m[key]
		switch {
		case !present && slices.Contains(opts, "opt"):
			continue
		case !present:
			return bad("%s misses %q", path, key)
		case val == nil && slices.Contains(opts, "null"):
			continue
		case val == nil:
			return bad("%s.%s is null", path, key)
		}
		if err := decodeInto(val, dst.Field(i), path+"."+key); err != nil {
			return err
		}
	}
	for k := range m {
		if !slices.Contains(known, k) {
			return bad("%s has unknown field %q", path, k)
		}
	}
	return nil
}

// object requires v to be an object holding exactly keys.
func object(v any, path string, keys ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, bad("%s must be an object", path)
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return nil, bad("%s misses %q", path, k)
		}
	}
	for k := range m {
		if !slices.Contains(keys, k) {
			return nil, bad("%s has unknown field %q", path, k)
		}
	}
	return m, nil
}

// Binding is a value bound into a template: an integer, a boolean, a byte template string or
// the witness program of an output. Exactly one field is set.
type Binding struct {
	Int     *int64
	Bool    *bool
	Str     *string
	Program *string
}

func (b *Binding) fromJSON(v any, path string) error {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return bad("%s: integer %s out of range", path, x)
		}
		b.Int = &n
	case bool:
		b.Bool = &x
	case string:
		b.Str = &x
	case map[string]any:
		m, err := object(v, path, "program")
		if err != nil {
			return err
		}
		name, ok := m["program"].(string)
		if !ok {
			return bad("%s.program must be a string", path)
		}
		b.Program = &name
	default:
		return bad("%s: binding must be an integer, boolean, string or program reference", path)
	}
	return nil
}

// MarshalJSON writes the binding in the form it was given.
func (b Binding) MarshalJSON() ([]byte, error) {
	switch {
	case b.Int != nil:
		return json.Marshal(*b.Int)
	case b.Bool != nil:
		return json.Marshal(*b.Bool)
	case b.Str != nil:
		return json.Marshal(*b.Str)
	case b.Program != nil:
		return json.Marshal(map[string]string{"program": *b.Program})
	}
	return nil, fmt.Errorf("empty binding")
}

// IntOrVar is an integer literal or the name of an int variable, without its brackets.
type IntOrVar struct {
	Int *int64
	Var string
}

func (iv *IntOrVar) fromJSON(v any, path string) error {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseInt(string(x), 10, 64)
		if err != nil {
			return bad("%s: integer %s out of range", path, x)
		}
		iv.Int = &n
	case string:
		m := namedVar.FindStringSubmatch(x)
		if m == nil {
			return bad("%s: %q is not an int variable", path, x)
		}
		iv.Var = m[1]
	default:
		return bad("%s must be an integer or an int variable", path)
	}
	return nil
}

// check bounds a literal; a variable is bounded when its value is known.
func (iv IntOrVar) check(what string, lo, hi int64) error {
	if iv.Int == nil {
		return nil
	}
	return integer(*iv.Int, what, lo, hi)
}

// MarshalJSON writes the literal or the bracketed variable.
func (iv IntOrVar) MarshalJSON() ([]byte, error) {
	if iv.Int != nil {
		return json.Marshal(*iv.Int)
	}
	return json.Marshal("<" + iv.Var + ">")
}

// Pool is the inputs an output draws its value from: one name, or a list given as a list.
type Pool struct {
	Names []string
	List  bool
}

func (p *Pool) fromJSON(v any, path string) error {
	switch x := v.(type) {
	case string:
		p.Names = []string{x}
	case []any:
		if len(x) == 0 {
			return bad("%s names no input", path)
		}
		p.List = true
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return bad("%s holds a non-string", path)
			}
			p.Names = append(p.Names, s)
		}
	default:
		return bad("%s must be an input name or a list of them", path)
	}
	return nil
}

// MarshalJSON writes the pool in the form it was given.
func (p Pool) MarshalJSON() ([]byte, error) {
	if p.List {
		return json.Marshal(p.Names)
	}
	return json.Marshal(p.Names[0])
}

// Locking is an output's script: a byte template, the script of an input, or a contract.
type Locking struct {
	Script   *Binding
	From     string
	Contract *Construction
}

func (l *Locking) fromJSON(v any, path string) error {
	switch x := v.(type) {
	case string:
		l.Script = &Binding{Str: &x}
	case map[string]any:
		if len(x) != 1 {
			return bad("%s has exactly one of from and contract", path)
		}
		if from, ok := x["from"]; ok {
			s, ok := from.(string)
			if !ok {
				return bad("%s.from must be a string", path)
			}
			l.From = s
			return nil
		}
		c, ok := x["contract"]
		if !ok {
			return bad("%s has exactly one of from and contract", path)
		}
		l.Contract = &Construction{}
		return decodeInto(c, reflect.ValueOf(l.Contract).Elem(), path+".contract")
	default:
		return bad("%s must be a string or an object", path)
	}
	return nil
}

// MarshalJSON writes the locking in the form it was given.
func (l Locking) MarshalJSON() ([]byte, error) {
	switch {
	case l.Script != nil:
		return json.Marshal(*l.Script.Str)
	case l.Contract != nil:
		return json.Marshal(map[string]*Construction{"contract": l.Contract})
	}
	return json.Marshal(map[string]string{"from": l.From})
}

// DefinitionRef is a contract definition: given inline, or by the id of a stored artifact.
type DefinitionRef struct {
	Artifact string
	Def      *abi.Definition // inline definition, nil for an artifact reference
}

// fromJSON hands anything but an artifact reference to abi, whose errors are returned as they are.
func (r *DefinitionRef) fromJSON(v any, path string) error {
	if m, ok := v.(map[string]any); ok {
		if _, isRef := m["artifact"]; isRef {
			if _, err := object(v, path, "artifact"); err != nil {
				return err
			}
			id, _ := m["artifact"].(string)
			if !idHex.MatchString(id) {
				return bad("%s: bad artifact id %v", path, m["artifact"])
			}
			r.Artifact = id
			return nil
		}
	}
	d, err := abi.ParseDefinition(v)
	if err != nil {
		return err
	}
	r.Def = d
	return nil
}

// MarshalJSON writes the reference, or the canonical form of the inline definition.
func (r DefinitionRef) MarshalJSON() ([]byte, error) {
	if r.Def == nil {
		return json.Marshal(map[string]string{"artifact": r.Artifact})
	}
	return json.Marshal(r.Def.Canonical())
}

// TriggerBind is where a trigger variable comes from: a source name, or a push captured from a
// source by matching an asm pattern.
type TriggerBind struct {
	Source string
	From   string
	Asm    []string
}

func (b *TriggerBind) fromJSON(v any, path string) error {
	switch x := v.(type) {
	case string:
		b.Source = x
	case map[string]any:
		m, err := object(v, path, "from", "asm")
		if err != nil {
			return err
		}
		from, ok := m["from"].(string)
		if !ok {
			return bad("%s.from must be a string", path)
		}
		list, ok := m["asm"].([]any)
		if !ok || len(list) == 0 {
			return bad("%s.asm needs a token list", path)
		}
		b.From = from
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return bad("%s.asm holds a non-string", path)
			}
			b.Asm = append(b.Asm, s)
		}
	default:
		return bad("%s is neither a source nor a capture", path)
	}
	return nil
}

// MarshalJSON writes the bind in the form it was given.
func (b TriggerBind) MarshalJSON() ([]byte, error) {
	if b.Asm == nil {
		return json.Marshal(b.Source)
	}
	return json.Marshal(map[string]any{"from": b.From, "asm": b.Asm})
}

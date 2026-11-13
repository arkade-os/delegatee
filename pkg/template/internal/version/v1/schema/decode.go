package schema

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/arkade-os/executor/pkg/template/internal/jcs"

	"github.com/arkade-os/executor/pkg/template/artifact"
)

// Binding is a value bound into a template: an integer, a boolean, a byte template string or
// the witness program of an output. Exactly one field is set.
type Binding struct {
	Int     *int64
	Bool    *bool
	Str     *string
	Program *string
}

// IntOrVar is an integer literal or the name of an int variable, without its brackets.
type IntOrVar struct {
	Int *int64
	Var string
}

// Locking is an output's script: a byte template, the script of an input, or a contract.
type Locking struct {
	Script   *Binding
	From     string
	Contract *Construction
}

// DefinitionRef is a contract definition: given inline, or by the id of a stored artifact.
type DefinitionRef struct {
	Artifact string
	Def      *artifact.Definition // inline definition, nil for an artifact reference
}

// Decode parses a document strictly: unknown keys, keys in another case, null where a value is
// due, and shapes other than the declared ones are refused, then the syntactic rules run.
func Decode(doc []byte) (*Template, error) {
	v, err := jcsDecode(doc)
	if err != nil {
		return nil, err
	}
	return DecodeValue(v)
}

func DecodeValue(v any) (*Template, error) {
	if err := jcs.CheckNumbers(v); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	decoded, err := readTemplate(v, "")
	if err != nil {
		return nil, err
	}
	t := &decoded
	if err := t.check(); err != nil {
		return nil, err
	}
	return t, nil
}

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

func (iv IntOrVar) MarshalJSON() ([]byte, error) {
	if iv.Int != nil {
		return json.Marshal(*iv.Int)
	}
	return json.Marshal("<" + iv.Var + ">")
}

func (l Locking) MarshalJSON() ([]byte, error) {
	switch {
	case l.Script != nil:
		return json.Marshal(*l.Script.Str)
	case l.Contract != nil:
		return json.Marshal(map[string]*Construction{"contract": l.Contract})
	}
	return json.Marshal(map[string]string{"from": l.From})
}

func (r DefinitionRef) MarshalJSON() ([]byte, error) {
	if r.Def == nil {
		return json.Marshal(map[string]string{"artifact": r.Artifact})
	}
	return json.Marshal(r.Def.Canonical())
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
		decoded, err := readConstruction(c, child(path, "contract"))
		if err != nil {
			return err
		}
		*l.Contract = decoded
		return nil
	default:
		return bad("%s must be a string or an object", path)
	}
	return nil
}

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
	d, err := artifact.ParseDefinitionV1(v)
	if err != nil {
		return err
	}
	r.Def = d
	return nil
}

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
	for _, k := range sortedKeys(m) {
		if !slices.Contains(keys, k) {
			return nil, bad("%s has unknown field %q", path, k)
		}
	}
	return m, nil
}

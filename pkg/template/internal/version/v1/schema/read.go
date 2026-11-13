package schema

import (
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// PathError retains the JSON Pointer without changing the original error category.
type PathError struct {
	Path string
	Err  error
}

type presence uint8

const (
	required presence = iota
	optional
)

type objectReader struct {
	values map[string]any
	path   string
	err    error
}

func (e *PathError) Error() string       { return e.Err.Error() }
func (e *PathError) Unwrap() error       { return e.Err }
func (e *PathError) JSONPointer() string { return e.Path }

func at(path string, err error) error {
	if err == nil {
		return nil
	}
	var p *PathError
	if errors.As(err, &p) {
		return err
	}
	return &PathError{path, err}
}

func child(path, key string) string {
	return path + "/" + strings.ReplaceAll(strings.ReplaceAll(key, "~", "~0"), "/", "~1")
}

func sortedKeys[T any](m map[string]T) []string { return slices.Sorted(maps.Keys(m)) }

func newObject(v any, path string, keys ...string) *objectReader {
	r := &objectReader{path: path}
	m, ok := v.(map[string]any)
	if !ok {
		r.err = at(path, bad("%s must be an object", path))
		return r
	}
	r.values = m
	for _, k := range sortedKeys(m) {
		if !slices.Contains(keys, k) {
			r.err = at(child(path, k), bad("%s has unknown field %q", path, k))
			break
		}
	}
	return r
}

func field[T any](
	r *objectReader, key string, dst *T, mode presence, read func(any, string) (T, error),
) {
	if r.err != nil {
		return
	}
	path := child(r.path, key)
	v, ok := r.values[key]
	if !ok {
		if mode == required {
			r.err = at(path, bad("%s misses %q", r.path, key))
		}
		return
	}
	if v == nil {
		r.err = at(path, bad("%s is null", path))
		return
	}
	x, err := read(v, path)
	r.err = at(path, err)
	if err == nil {
		*dst = x
	}
}

func readString(v any, path string) (string, error) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", bad("%s must be a non-empty string", path)
	}
	return s, nil
}

func readBool(v any, path string) (bool, error) {
	b, ok := v.(bool)
	if !ok {
		return false, bad("%s must be a boolean", path)
	}
	return b, nil
}

func readInt(v any, path string) (int64, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, bad("%s must be an integer", path)
	}
	i, err := strconv.ParseInt(string(n), 10, 64)
	if err != nil {
		return 0, bad("%s must be an integer", path)
	}
	return i, nil
}

func pointer[T any](read func(any, string) (T, error)) func(any, string) (*T, error) {
	return func(v any, path string) (*T, error) {
		x, err := read(v, path)
		if err != nil {
			return nil, err
		}
		return &x, nil
	}
}

func list[T any](read func(any, string) (T, error)) func(any, string) ([]T, error) {
	return func(v any, path string) ([]T, error) {
		a, ok := v.([]any)
		if !ok {
			return nil, bad("%s must be an array", path)
		}
		out := make([]T, len(a))
		for i, e := range a {
			x, err := read(e, child(path, strconv.Itoa(i)))
			if err != nil {
				return nil, at(child(path, strconv.Itoa(i)), err)
			}
			out[i] = x
		}
		return out, nil
	}
}

func dictionary[T any](read func(any, string) (T, error)) func(any, string) (map[string]T, error) {
	return func(v any, path string) (map[string]T, error) {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, bad("%s must be an object", path)
		}
		out := make(map[string]T, len(m))
		for _, k := range sortedKeys(m) {
			p := child(path, k)
			if m[k] == nil {
				return nil, at(p, bad("%s is null", p))
			}
			x, err := read(m[k], p)
			if err != nil {
				return nil, at(p, err)
			}
			out[k] = x
		}
		return out, nil
	}
}

func readBinding(v any, path string) (Binding, error) {
	var out Binding
	err := out.fromJSON(v, path)
	return out, at(path, err)
}

func readIntOrVar(v any, path string) (IntOrVar, error) {
	var out IntOrVar
	err := out.fromJSON(v, path)
	return out, at(path, err)
}

func readLocking(v any, path string) (Locking, error) {
	var out Locking
	err := out.fromJSON(v, path)
	return out, at(path, err)
}

func readDefinitionRef(v any, path string) (DefinitionRef, error) {
	var out DefinitionRef
	err := out.fromJSON(v, path)
	return out, at(path, err)
}

func readTemplate(v any, path string) (Template, error) {
	var out Template
	r := newObject(
		v, path, "format", "type", "variables", "inputs", "outputs", "fees", "packets",
		"delegation",
	)
	field(r, "format", &out.Format, required, readString)
	field(r, "type", &out.Type, required, readString)
	field(r, "variables", &out.Variables, optional, dictionary(readString))
	field(r, "inputs", &out.Inputs, required, list(readInput))
	field(r, "outputs", &out.Outputs, required, list(readOutput))
	field(r, "fees", &out.Fees, optional, pointer(readFees))
	field(r, "packets", &out.Packets, optional, pointer(readPackets))
	field(r, "delegation", &out.Delegation, optional, pointer(readDelegation))
	return out, r.err
}

func readDelegation(v any, path string) (Delegation, error) {
	var out Delegation
	r := newObject(v, path, "schedule", "sealed", "trigger")
	field(r, "schedule", &out.Schedule, optional, dictionary(readSchedule))
	field(r, "sealed", &out.Sealed, optional, list(readString))
	field(r, "trigger", &out.Trigger, optional, dictionary(readTrigger))
	return out, r.err
}

func readInput(v any, path string) (Input, error) {
	var out Input
	r := newObject(v, path, "name", "type", "contract", "spend")
	field(r, "name", &out.Name, required, readString)
	field(r, "type", &out.Type, optional, readString)
	field(r, "contract", &out.Contract, required, readConstruction)
	field(r, "spend", &out.Spend, required, readSpend)
	return out, r.err
}

func readSchedule(v any, path string) (Schedule, error) {
	var out Schedule
	r := newObject(v, path, "immediate", "before_expiry_seconds", "min_confirmations")
	field(r, "immediate", &out.Immediate, optional, pointer(readBool))
	field(r, "before_expiry_seconds", &out.BeforeExpiry, optional, pointer(readIntOrVar))
	field(r, "min_confirmations", &out.MinConfirmations, optional, pointer(readInt))
	return out, r.err
}

func readConstruction(v any, path string) (Construction, error) {
	var out Construction
	r := newObject(v, path, "definition", "arguments", "taptree")
	field(r, "definition", &out.Definition, required, readDefinitionRef)
	field(r, "arguments", &out.Arguments, optional, dictionary(readBinding))
	field(r, "taptree", &out.Taptree, optional, readString)
	return out, r.err
}

func readSpend(v any, path string) (Spend, error) {
	var out Spend
	r := newObject(v, path, "function", "leaf", "arguments", "witness")
	field(r, "function", &out.Function, required, readString)
	field(r, "leaf", &out.Leaf, required, readString)
	field(r, "arguments", &out.Arguments, optional, list(readBinding))
	field(r, "witness", &out.Witness, optional, dictionary(readBinding))
	return out, r.err
}

func readOutput(v any, path string) (Output, error) {
	var out Output
	r := newObject(v, path, "name", "type", "index", "value", "locking", "assets")
	field(r, "name", &out.Name, required, readString)
	field(r, "type", &out.Type, optional, readString)
	field(r, "index", &out.Index, required, readInt)
	field(r, "value", &out.Value, required, readValue)
	field(r, "locking", &out.Locking, required, readLocking)
	field(r, "assets", &out.Assets, optional, list(readAssetRoute))
	return out, r.err
}

func readValue(v any, path string) (Value, error) {
	var out Value
	r := newObject(v, path, "from", "amount")
	field(r, "from", &out.From, required, readString)
	field(r, "amount", &out.Amount, optional, pointer(readBinding))
	return out, r.err
}

func readAssetRoute(v any, path string) (AssetRoute, error) {
	var out AssetRoute
	r := newObject(v, path, "from", "asset", "amount")
	field(r, "from", &out.From, required, readString)
	field(r, "asset", &out.Asset, optional, readString)
	field(r, "amount", &out.Amount, optional, pointer(readBinding))
	return out, r.err
}

func readFees(v any, path string) (Fees, error) {
	var out Fees
	r := newObject(v, path, "from", "max")
	field(r, "from", &out.From, required, readString)
	field(r, "max", &out.Max, required, readIntOrVar)
	return out, r.err
}

func readPackets(v any, path string) (Packets, error) {
	var out Packets
	r := newObject(v, path, "output_index", "unmatched", "rules", "advertise")
	field(r, "output_index", &out.OutputIndex, required, readInt)
	field(r, "unmatched", &out.Unmatched, optional, readString)
	field(r, "rules", &out.Rules, optional, list(readRule))
	field(r, "advertise", &out.Advertise, optional, list(readAdvert))
	return out, r.err
}

func readRule(v any, path string) (Rule, error) {
	var out Rule
	r := newObject(v, path, "type", "action", "from", "data")
	field(r, "type", &out.Type, required, readInt)
	field(r, "action", &out.Action, required, readString)
	field(r, "from", &out.From, required, readString)
	field(r, "data", &out.Data, optional, pointer(readBinding))
	return out, r.err
}

func readAdvert(v any, path string) (Advert, error) {
	var out Advert
	r := newObject(v, path, "template", "outputs")
	field(r, "template", &out.Template, required, readString)
	field(r, "outputs", &out.Outputs, required, list(readString))
	return out, r.err
}

func readTrigger(v any, path string) (Trigger, error) {
	var out Trigger
	r := newObject(
		v, path, "packet", "decode", "require", "capture", "group", "expires_after_seconds",
		"min_value",
	)
	field(r, "packet", &out.Packet, required, readInt)
	field(r, "decode", &out.Decode, required, readString)
	field(r, "require", &out.Require, required, dictionary(readString))
	field(r, "capture", &out.Capture, required, dictionary(readString))
	field(r, "group", &out.Group, optional, readString)
	field(r, "expires_after_seconds", &out.ExpiresAfter, required, readInt)
	field(r, "min_value", &out.MinValue, optional, readInt)
	return out, r.err
}

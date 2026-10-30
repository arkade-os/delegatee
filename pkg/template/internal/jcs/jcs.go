// Package jcs decodes JSON strictly and writes it in RFC 8785 canonical form.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	maxSafeInt = 1<<53 - 1
	maxDepth   = 64
)

// ErrInvalid marks a document this package refuses.
var ErrInvalid = errors.New("invalid json")

// Decode parses one JSON value, rejecting invalid UTF-8, duplicate keys and trailing data.
// Numbers are kept as json.Number; CheckNumbers judges them.
func Decode(doc []byte) (any, error) {
	if !utf8.Valid(doc) {
		return nil, fmt.Errorf("%w: invalid utf-8", ErrInvalid)
	}
	if err := scan(doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalid)
	}
	return v, nil
}

// CheckNumbers refuses any number in v that Canonical would: a fraction, an exponent, -0 or a
// magnitude above 2^53-1.
func CheckNumbers(v any) error {
	switch x := v.(type) {
	case json.Number:
		_, err := safeInt(x)
		return err
	case []any:
		for _, e := range x {
			if err := CheckNumbers(e); err != nil {
				return err
			}
		}
	case map[string]any:
		for _, e := range x {
			if err := CheckNumbers(e); err != nil {
				return err
			}
		}
	}
	return nil
}

func safeInt(x json.Number) (int64, error) {
	s := x.String()
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || s == "-0" || strings.ContainsAny(s, ".eE") || n > maxSafeInt || n < -maxSafeInt {
		return 0, fmt.Errorf("%w: unsupported number %s", ErrInvalid, s)
	}
	return n, nil
}

// scan rejects excessive nesting and unpaired surrogate escapes, which encoding/json would replace silently.
func scan(doc []byte) error {
	depth := 0
	for i := 0; i < len(doc); i++ {
		switch doc[i] {
		case '[', '{':
			if depth++; depth > maxDepth {
				return fmt.Errorf("nesting deeper than %d", maxDepth)
			}
		case ']', '}':
			depth--
		case '"':
			for i++; i < len(doc) && doc[i] != '"'; i++ {
				if doc[i] != '\\' {
					continue
				}
				if i++; i >= len(doc) || doc[i] != 'u' {
					continue
				}
				u, ok := hex4(doc, i+1)
				if !ok || u < 0xD800 || u > 0xDFFF {
					continue
				}
				i += 4
				if u >= 0xDC00 {
					return fmt.Errorf("lone low surrogate escape")
				}
				if l, ok := hex4(doc, i+3); !ok || doc[i+1] != '\\' || doc[i+2] != 'u' || l < 0xDC00 || l > 0xDFFF {
					return fmt.Errorf("lone high surrogate escape")
				}
				i += 6
			}
		}
	}
	return nil
}

func hex4(doc []byte, at int) (int, bool) {
	if at+4 > len(doc) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(doc[at:at+4]), 16, 16)
	return int(n), err == nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	if d == '[' {
		arr := []any{}
		for dec.More() {
			v, err := decodeValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, v)
		}
		_, err := dec.Token()
		return arr, err
	}
	obj := map[string]any{}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key := k.(string)
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		if obj[key], err = decodeValue(dec); err != nil {
			return nil, err
		}
	}
	_, err = dec.Token()
	return obj, err
}

// Canonical serializes a decoded value per RFC 8785, restricted to safe integers.
func Canonical(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeCanonical(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(x))
	case string:
		writeString(b, x)
	case json.Number:
		n, err := safeInt(x)
		if err != nil {
			return err
		}
		b.WriteString(strconv.FormatInt(n, 10))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := slices.Collect(maps.Keys(x))
		slices.SortFunc(keys, func(a, c string) int {
			return slices.Compare(utf16.Encode([]rune(a)), utf16.Encode([]rune(c)))
		})
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("%w: unsupported type %T", ErrInvalid, v)
	}
	return nil
}

func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

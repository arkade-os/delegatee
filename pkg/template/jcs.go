package template

import (
	"bytes"
	"encoding/json"
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

// decodeStrict parses one JSON value, rejecting invalid UTF-8, duplicate keys and trailing data.
func decodeStrict(doc []byte) (any, error) {
	if !utf8.Valid(doc) {
		return nil, fmt.Errorf("%w: invalid utf-8", ErrInvalidTemplate)
	}
	if err := scan(doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", ErrInvalidTemplate)
	}
	return v, nil
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

// canonical serializes a decoded value per RFC 8785, restricted to safe integers.
func canonical(v any) ([]byte, error) {
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
		s := x.String()
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || s == "-0" || strings.ContainsAny(s, ".eE") || n > maxSafeInt || n < -maxSafeInt {
			return fmt.Errorf("%w: unsupported number %s", ErrInvalidTemplate, s)
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
		return fmt.Errorf("%w: unsupported type %T", ErrInvalidTemplate, v)
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

package template

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
)

const maxScriptNum = 1<<53 - 1

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// piece is a literal, a placeholder, an expression or an output's witness program; only one field is set.
type piece struct {
	hex     []byte
	name    string
	expr    []string
	program string // an output name
}

type byteTemplate []piece

func canonicalBytes(typ string, raw []byte) error {
	var err error
	switch typ {
	case "pubkey":
		if _, e := btcec.ParsePubKey(raw); len(raw) != 33 || e != nil {
			err = fmt.Errorf("pubkey must be a valid 33-byte key")
		}
	case "bytes":
		if len(raw) > maxPushSize {
			err = fmt.Errorf("bytes longer than %d", maxPushSize)
		}
	case "bytes20":
		if len(raw) != 20 {
			err = fmt.Errorf("bytes20 must be 20 bytes")
		}
	case "bytes32", "asset":
		if len(raw) != 32 {
			err = fmt.Errorf("%s must be 32 bytes", typ)
		}
	case "int":
		_, err = parseScriptNum(raw)
	case "bool":
		if len(raw) > 1 || (len(raw) == 1 && raw[0] != 1) {
			err = fmt.Errorf("bool must be empty or 01")
		}
	default:
		err = fmt.Errorf("unknown type %q", typ)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidVariables, err)
	}
	return nil
}

// scriptNum encodes n as a minimal Script number.
func scriptNum(n int64) []byte {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return b
}

// parseScriptNum decodes a minimal Script number with magnitude up to 2^53-1.
func parseScriptNum(b []byte) (int64, error) {
	n, err := arkade.MakeScriptNum(b, true, 8)
	if err != nil || n > maxScriptNum || n < -maxScriptNum {
		return 0, fmt.Errorf("%w: bad number of %d bytes", ErrInvalidVariables, len(b))
	}
	return int64(n), nil
}

func parseByteTemplate(s string) (byteTemplate, error) {
	var out byteTemplate
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '<':
			end := strings.IndexByte(s[i:], '>')
			if end < 0 || !nameRe.MatchString(s[i+1:i+end]) {
				return nil, fmt.Errorf("%w: bad placeholder at %d", ErrInvalidTemplate, i)
			}
			out = append(out, piece{name: s[i+1 : i+end]})
			i += end + 1
		case strings.HasPrefix(s[i:], "$("):
			end := strings.IndexByte(s[i:], ')')
			if end < 0 {
				return nil, fmt.Errorf("%w: unclosed expression at %d", ErrInvalidTemplate, i)
			}
			body := s[i+2 : i+end]
			if body == "" || strings.ContainsAny(body, "$(") ||
				strings.HasPrefix(body, " ") || strings.HasSuffix(body, " ") || strings.Contains(body, "  ") {
				return nil, fmt.Errorf("%w: bad expression at %d", ErrInvalidTemplate, i)
			}
			toks := strings.Split(body, " ")
			for _, t := range toks {
				if strings.HasPrefix(t, "<") && (!strings.HasSuffix(t, ">") || !nameRe.MatchString(t[1:len(t)-1])) {
					return nil, fmt.Errorf("%w: bad placeholder %q", ErrInvalidTemplate, t)
				}
			}
			out = append(out, piece{expr: toks})
			i += end + 1
		case isHex(c):
			j := i
			for j < len(s) && isHex(s[j]) {
				j++
			}
			if (j-i)%2 != 0 {
				return nil, fmt.Errorf("%w: odd number of hex digits at %d", ErrInvalidTemplate, i)
			}
			raw, _ := hex.DecodeString(s[i:j])
			out = append(out, piece{hex: raw})
			i = j
		default:
			return nil, fmt.Errorf("%w: unexpected %q at %d", ErrInvalidTemplate, c, i)
		}
	}
	return out, nil
}

// names lists the placeholders, including those inside expressions, once each in order of appearance.
func (b byteTemplate) names() []string {
	var out []string
	add := func(n string) {
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	for _, p := range b {
		if p.name != "" {
			add(p.name)
		}
		for _, t := range p.expr {
			if strings.HasPrefix(t, "<") {
				add(t[1 : len(t)-1])
			}
		}
	}
	return out
}

// literal returns the bytes of a template made of hex pieces only.
func (b byteTemplate) literal() ([]byte, bool) {
	var out []byte
	for _, p := range b {
		if p.name != "" || p.expr != nil || p.program != "" {
			return nil, false
		}
		out = append(out, p.hex...)
	}
	return out, true
}

func parseBinding(v any) (byteTemplate, error) {
	switch v := v.(type) {
	case json.Number:
		n, err := v.Int64()
		if err != nil || n > maxScriptNum || n < -maxScriptNum {
			return nil, fmt.Errorf("%w: integer %s out of range", ErrInvalidTemplate, v)
		}
		return byteTemplate{{hex: scriptNum(n)}}, nil
	case bool:
		if v {
			return byteTemplate{{hex: []byte{1}}}, nil
		}
		return byteTemplate{{hex: []byte{}}}, nil
	case string:
		return parseByteTemplate(v)
	}
	return nil, fmt.Errorf("%w: binding must be an integer, boolean or string", ErrInvalidTemplate)
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

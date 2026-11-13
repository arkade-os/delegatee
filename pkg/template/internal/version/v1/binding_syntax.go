package v1

import (
	"encoding/hex"
	"slices"
	"strings"

	"github.com/arkade-os/executor/pkg/template/internal/version/v1/schema"
)

// piece is a literal, a placeholder, an expression or an output's witness program; only one field
// is set.
type piece struct {
	hex     []byte
	name    string
	expr    []string
	program string // an output name
}

// byteTemplate is a bound value: pieces concatenated once the names and expressions resolve.
type byteTemplate []piece

// names lists the placeholders, including those inside expressions, once each in order of
// appearance.
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
				add(tokenName(t))
			}
		}
	}
	return out
}

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

func parseByteTemplate(s string) (byteTemplate, error) {
	var out byteTemplate
	for i := 0; i < len(s); {
		switch c := s[i]; {
		case c == '<':
			end := strings.IndexByte(s[i:], '>')
			if end < 0 || !schema.Name.MatchString(s[i+1:i+end]) {
				return nil, bad("bad placeholder at %d", i)
			}
			out = append(out, piece{name: s[i+1 : i+end]})
			i += end + 1
		case strings.HasPrefix(s[i:], "$("):
			end := strings.IndexByte(s[i:], ')')
			if end < 0 {
				return nil, bad("unclosed expression at %d", i)
			}
			body := s[i+2 : i+end]
			if body == "" || strings.ContainsAny(body, "$(") ||
				strings.HasPrefix(
					body, " ",
				) || strings.HasSuffix(body, " ") || strings.Contains(body, "  ") {
				return nil, bad("bad expression at %d", i)
			}
			toks := strings.Split(body, " ")
			for _, t := range toks {
				if strings.HasPrefix(t, "<") &&
					(!strings.HasSuffix(t, ">") || !schema.Name.MatchString(tokenName(t))) {
					return nil, bad("bad placeholder %q", t)
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
				return nil, bad("odd number of hex digits at %d", i)
			}
			raw, _ := hex.DecodeString(s[i:j])
			out = append(out, piece{hex: raw})
			i = j
		default:
			return nil, bad("unexpected %q at %d", c, i)
		}
	}
	return out, nil
}

func hasProgram(b byteTemplate) bool {
	return slices.ContainsFunc(b, func(p piece) bool { return p.program != "" })
}

func tokenName(t string) string { return strings.TrimPrefix(t[1:len(t)-1], "!") }
func isHex(c byte) bool         { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

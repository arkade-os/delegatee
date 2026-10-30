package template

import (
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/delegatee/pkg/template/internal/asm"
	"github.com/arkade-os/delegatee/pkg/template/internal/schema"
)

// hashOps are the opcodes a secret may appear under in a script.
var hashOps = []string{"OP_HASH160", "OP_SHA256", "OP_HASH256", "OP_RIPEMD160"}

// piece is a literal, a placeholder, an expression or an output's witness program; only one field is set.
type piece struct {
	hex     []byte
	name    string
	expr    []string
	program string // an output name
}

// byteTemplate is a bound value: pieces concatenated once the names and expressions resolve.
type byteTemplate []piece

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
				strings.HasPrefix(body, " ") || strings.HasSuffix(body, " ") || strings.Contains(body, "  ") {
				return nil, bad("bad expression at %d", i)
			}
			toks := strings.Split(body, " ")
			for _, t := range toks {
				if strings.HasPrefix(t, "<") && (!strings.HasSuffix(t, ">") || !schema.Name.MatchString(t[1:len(t)-1])) {
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

func hasProgram(b byteTemplate) bool {
	return slices.ContainsFunc(b, func(p piece) bool { return p.program != "" })
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' }

// bind type-checks literals and lone names here, the rest at evaluation; typ "" is any bytes.
// A program reference is accepted only by a contract argument, which binds it before calling here.
func (c *compiler) bind(v schema.Binding, typ string, secrets bool) (byteTemplate, error) {
	var b byteTemplate
	switch {
	case v.Program != nil:
		return nil, bad("output program %q can only fill a contract argument", *v.Program)
	case v.Int != nil:
		if typ != "int" {
			return nil, bad("an integer cannot fill a %s field", typ)
		}
		b = byteTemplate{{hex: asm.ScriptNum(*v.Int)}}
	case v.Bool != nil:
		if typ != "bool" {
			return nil, bad("a boolean cannot fill a %s field", typ)
		}
		b = byteTemplate{{hex: []byte{}}}
		if *v.Bool {
			b = byteTemplate{{hex: []byte{1}}}
		}
	case v.Str != nil:
		var err error
		if b, err = parseByteTemplate(*v.Str); err != nil {
			return nil, err
		}
	default:
		return nil, bad("empty binding")
	}
	for _, n := range b.names() {
		_, isVar := c.t.variables[n]
		_, isSecret := c.t.secrets[n]
		if !isVar && (!secrets || !isSecret) {
			return nil, bad("undeclared name %q", n)
		}
		c.named[n] = true
	}
	for _, pc := range b {
		if err := asm.CheckExpression(pc.expr); err != nil {
			return nil, fmt.Errorf("%w: expression: %v", ErrInvalidTemplate, err)
		}
	}
	if typ == "" {
		return b, nil
	}
	if lit, ok := b.literal(); ok {
		if err := asm.CanonicalBytes(typ, lit); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
		}
	}
	if len(b) == 1 && b[0].name != "" && typ != "bytes" {
		n := b[0].name
		declared, isVar := c.t.variables[n]
		if !isVar {
			declared = c.t.secrets[n].typ
		}
		if declared != typ {
			return nil, bad("%s %q cannot fill a %s field", declared, n, typ)
		}
	}
	return b, nil
}

// scriptBind binds a value that ends in a tapscript, which is stored and returned: a secret may
// appear in it only under a hash.
func (c *compiler) scriptBind(v schema.Binding, typ string) (byteTemplate, error) {
	b, err := c.bind(v, typ, true)
	if err != nil {
		return nil, err
	}
	for _, pc := range b {
		for _, n := range (byteTemplate{pc}).names() {
			if _, ok := c.t.secrets[n]; ok && (pc.expr == nil || !slices.Contains(hashOps, pc.expr[len(pc.expr)-1])) {
				return nil, bad("secret %q must be hashed in a script", n)
			}
		}
	}
	return b, nil
}

// amount binds an int that, when literal, must be positive.
func (c *compiler) amount(v schema.Binding) (byteTemplate, error) {
	b, err := c.bind(v, "int", true)
	if err != nil {
		return nil, err
	}
	if lit, ok := b.literal(); ok {
		if n, _ := asm.ParseScriptNum(lit); n < 1 {
			return nil, bad("an amount must be positive")
		}
	}
	return b, nil
}

// secrets open at most once per draft and are kept only by it
func (i *Instance) resolve(b byteTemplate, d *draft, input int) ([]byte, error) {
	lookup := func(n string) (asm.Value, error) { return i.lookup(n, d) }
	out := []byte{}
	for _, p := range b {
		switch {
		case p.name != "":
			v, err := lookup(p.name)
			if err != nil {
				return nil, err
			}
			out = append(out, v.Raw...)
		case p.program != "":
			o := i.tmpl.outputs[i.tmpl.output(p.program)]
			ct, err := i.contractOf(o.locking.contract, d, o.from, false)
			if err != nil {
				return nil, fmt.Errorf("output %q: %w", o.name, err)
			}
			out = append(out, ct.PkScript[2:]...)
		case p.expr != nil:
			r, err := d.eval(p.expr, input, lookup)
			if err != nil {
				return nil, err
			}
			out = append(out, r...)
		default:
			out = append(out, p.hex...)
		}
	}
	return out, nil
}

func (i *Instance) lookup(n string, d *draft) (asm.Value, error) {
	if typ, ok := i.tmpl.variables[n]; ok {
		return asm.Value{Type: typ, Raw: i.vars[n]}, nil
	}
	return i.secret(n, d)
}

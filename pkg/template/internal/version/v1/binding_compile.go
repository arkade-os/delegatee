package v1

import (
	"fmt"
	"slices"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/arkade-os/executor/pkg/template/internal/version/v1/schema"
)

// hashOps are the opcodes a sealed variable may appear under in a contract argument.
var hashOps = []string{"OP_HASH160", "OP_SHA256", "OP_HASH256", "OP_RIPEMD160"}

// bind type-checks literals and lone names here, the rest at evaluation; typ "" is any bytes.
// A program reference is accepted only by a contract argument, which binds it before calling here.
func (c *compiler) bind(v schema.Binding, typ string) (byteTemplate, error) {
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
		if _, ok := c.t.variables[n]; !ok {
			return nil, bad("undeclared name %q", n)
		}
		c.named[n] = true
	}
	for _, pc := range b {
		if err := c.checkExpression(pc.expr); err != nil {
			return nil, err
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
		if declared := c.t.variables[n]; declared != typ {
			return nil, bad("%s %q cannot fill a %s field", declared, n, typ)
		}
	}
	return b, nil
}

func (c *compiler) checkExpression(expr []string) error {
	for _, tok := range expr {
		if m := asm.Splice.FindStringSubmatch(tok); m != nil && c.t.variables[m[1]] != "bytes" {
			return bad("spliced variable %q is not bytes", m[1])
		}
	}
	if err := asm.CheckExpression(expr); err != nil {
		return fmt.Errorf("%w: expression: %v", ErrInvalidTemplate, err)
	}
	return nil
}

// scriptBind: a sealed variable appears in a contract argument only under a hash.
func (c *compiler) scriptBind(v schema.Binding, typ string) (byteTemplate, error) {
	b, err := c.bind(v, typ)
	if err != nil {
		return nil, err
	}
	for _, pc := range b {
		for _, n := range (byteTemplate{pc}).names() {
			if c.t.sealed[n] &&
				(pc.expr == nil || !slices.Contains(hashOps, pc.expr[len(pc.expr)-1])) {
				return nil, bad("sealed %q must be hashed in a contract argument", n)
			}
		}
	}
	return b, nil
}

func (c *compiler) amount(v schema.Binding) (byteTemplate, error) {
	b, err := c.bind(v, "int")
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

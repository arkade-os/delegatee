package template

import (
	"fmt"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
)

type secret struct {
	typ        string
	from       int
	ciphertext byteTemplate
}

// declarations records the variables and the secrets' types; the secrets' bodies need the inputs.
func (c *compiler) declarations() error {
	for n, typ := range c.doc.Variables {
		c.t.variables[n] = typ
	}
	for n, s := range c.doc.Secrets {
		if _, dup := c.t.variables[n]; dup {
			return bad("%q is both a variable and a secret", n)
		}
		c.t.secrets[n] = secret{typ: s.Type}
	}
	return nil
}

func (c *compiler) secretBodies() error {
	for n, s := range c.doc.Secrets {
		sec := c.t.secrets[n]
		var err error
		if sec.from, err = c.inputIndex(s.From, "secret "+n); err != nil {
			return err
		}
		if sec.ciphertext, err = c.bind(s.Ciphertext, "", false); err != nil {
			return err
		}
		c.t.secrets[n] = sec
	}
	return nil
}

// secret opens a secret, at most once per draft, which keeps the plaintext.
func (i *Instance) secret(n string, d *draft) (asm.Value, error) {
	s, ok := i.tmpl.secrets[n]
	if !ok {
		return asm.Value{}, fmt.Errorf("%w: unknown name %q", ErrInvalidTemplate, n)
	}
	if p, ok := d.secrets[n]; ok {
		return asm.Value{Type: s.typ, Raw: p}, nil
	}
	ct, err := i.resolve(s.ciphertext, d, d.index(s.from))
	if err != nil {
		return asm.Value{}, fmt.Errorf("secret %q: %w", n, err)
	}
	p, err := i.decrypt(ct)
	if err == nil {
		err = asm.CanonicalBytes(s.typ, p)
	}
	if err != nil {
		return asm.Value{}, fmt.Errorf("%w: secret %q: %v", ErrIneligible, n, err)
	}
	if d.secrets == nil {
		d.secrets = map[string][]byte{}
	}
	d.secrets[n] = p
	return asm.Value{Type: s.typ, Raw: p}, nil
}

package v1

import (
	"fmt"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
)

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

func (i *Instance) lookup(n string, _ *draft) (asm.Value, error) {
	typ, ok := i.tmpl.variables[n]
	if !ok {
		return asm.Value{}, fmt.Errorf("%w: unknown name %q", ErrInvalidTemplate, n)
	}
	return asm.Value{Type: typ, Raw: i.vars[n]}, nil
}

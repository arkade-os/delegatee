package v1

import (
	"fmt"
	"maps"
	"slices"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
)

func (c *compiler) declarations() error {
	maps.Copy(c.t.variables, c.doc.Variables)
	if d := c.doc.Delegation; d != nil {
		for _, n := range d.Sealed {
			if _, ok := c.t.variables[n]; !ok {
				return bad("sealed %q is not a declared variable", n)
			}
			c.t.sealed[n] = true
		}
	}
	return nil
}

func (c *compiler) schedules() error {
	if c.doc.Delegation == nil {
		return nil
	}
	s := c.doc.Delegation.Schedule
	for _, n := range slices.Sorted(maps.Keys(s)) {
		slot, err := c.inputIndex(n, "schedule")
		if err != nil {
			return err
		}
		in := &c.t.inputs[slot]
		sch := s[n]
		if in.schedule, in.leadVariable, err = c.schedule(&sch, in.onchain); err != nil {
			return err
		}
	}
	return nil
}

// open: without decrypt, sealed values are plaintexts already.
func (t *Template) open(
	vars map[string][]byte, decrypt func([]byte) ([]byte, error),
) (map[string][]byte, error) {
	if decrypt == nil || len(t.sealed) == 0 {
		return vars, nil
	}
	out := maps.Clone(vars)
	for _, n := range slices.Sorted(maps.Keys(t.sealed)) {
		ct, ok := vars[n]
		if !ok {
			continue
		}
		p, err := decrypt(ct)
		if err == nil {
			err = asm.CanonicalBytes(t.variables[n], p)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: sealed %q: %v", ErrIneligible, n, err)
		}
		out[n] = p
	}
	return out, nil
}

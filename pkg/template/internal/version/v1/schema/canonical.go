package schema

import (
	"encoding/json"
	"fmt"

	"github.com/arkade-os/executor/pkg/template/internal/jcs"
)

// Normalize drops what equals its default, so documents differing only in spelling share an id.
// Empty collections and an inline definition are already canonical through the field tags.
func (t *Template) Normalize() {
	def := "offchain"
	if t.Type == "onchain" {
		def = "onchain"
	}
	for i := range t.Inputs {
		if t.Inputs[i].Type == def {
			t.Inputs[i].Type = ""
		}
	}
	for i := range t.Outputs {
		if t.Outputs[i].Type == def {
			t.Outputs[i].Type = ""
		}
	}
	if t.Packets != nil && t.Packets.Unmatched == "reject" {
		t.Packets.Unmatched = ""
	}
	if d := t.Delegation; d != nil {
		for n, s := range d.Schedule {
			if s.Immediate != nil {
				delete(d.Schedule, n)
			}
		}
		if len(d.Schedule) == 0 && len(d.Sealed) == 0 && len(d.Trigger) == 0 {
			t.Delegation = nil
		}
	}
}

func (t *Template) SpendCanonical() ([]byte, error) {
	spend := *t
	spend.Delegation = nil
	return spend.Canonical()
}

// Canonical is the RFC 8785 serialization of the document; its hash is the template id.
func (t *Template) Canonical() ([]byte, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	v, err := jcsDecode(b)
	if err != nil {
		return nil, err
	}
	b, err = jcs.Canonical(v)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return b, nil
}

// jcsDecode decodes strictly; a number the canonical form cannot carry is refused up front.
func jcsDecode(doc []byte) (any, error) {
	v, err := jcs.Decode(doc)
	if err == nil {
		err = jcs.CheckNumbers(v)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return v, nil
}

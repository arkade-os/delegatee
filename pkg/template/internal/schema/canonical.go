package schema

import (
	"encoding/json"
	"fmt"

	"github.com/arkade-os/executor/pkg/template/internal/jcs"
)

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

// Normalize drops what equals its default, so documents differing only in spelling share an id.
// Empty collections and an inline definition are already canonical through the field tags.
func (t *Template) Normalize() {
	def := "offchain"
	if t.Type == "onchain" {
		def = "onchain"
	}
	for i := range t.Inputs {
		in := &t.Inputs[i]
		if in.Type == def {
			in.Type = ""
		}
		if in.Schedule != nil && in.Schedule.Immediate != nil {
			in.Schedule = nil
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

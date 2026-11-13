// Package artifact parses and validates contract compiler artifacts independently
// of the template language. Artifact versions are interpretation profiles, not Go
// module versions or compiler build versions.
package artifact

import (
	"bytes"
	"fmt"
	"slices"

	v1 "github.com/arkade-os/executor/pkg/template/artifact/internal/v1"
	"github.com/arkade-os/executor/pkg/template/internal/failure"
	"github.com/arkade-os/executor/pkg/template/internal/jcs"
)

const Version1 = "artifact/v1"

var ErrInvalid = failure.ErrInvalidArtifact
var ErrUnsupportedVersion = failure.ErrUnsupportedArtifactVersion

type Field = v1.Field
type Struct = v1.Struct
type WitnessItem = v1.WitnessItem
type Leaf = v1.Leaf
type Covenant = v1.Covenant
type Function = v1.Function
type Definition = v1.Definition

// Artifact owns a validated, immutable definition. Inspection methods return copies.
type Artifact struct {
	version    string
	id         string
	canonical  []byte
	definition Definition
}

func (a *Artifact) Version() string   { return a.version }
func (a *Artifact) ID() string        { return a.id }
func (a *Artifact) Canonical() []byte { return bytes.Clone(a.canonical) }

func (a *Artifact) Definition() Definition {
	d := a.definition
	d.ConstructorInputs = slices.Clone(d.ConstructorInputs)
	d.Structs = slices.Clone(d.Structs)
	for i := range d.Structs {
		d.Structs[i].Fields = slices.Clone(d.Structs[i].Fields)
	}
	d.Functions = slices.Clone(d.Functions)
	for i := range d.Functions {
		f := &d.Functions[i]
		if f.Arkade != nil {
			c := *f.Arkade
			c.Inputs = slices.Clone(c.Inputs)
			c.Asm = slices.Clone(c.Asm)
			f.Arkade = &c
		}
		f.Leaves = slices.Clone(f.Leaves)
		for j := range f.Leaves {
			l := &f.Leaves[j]
			l.Asm = slices.Clone(l.Asm)
			l.Witness = slices.Clone(l.Witness)
		}
	}
	return d
}
func SupportedVersions() []string { return []string{Version1} }

// Parse explicitly selects the historical v1 interpretation. Existing artifact
// documents have no language discriminator: formatVersion and compiler.version
// are metadata in that format, and are not reinterpreted as dispatch fields.
// New consumers that negotiate a profile should use ParseVersion.
func Parse(raw []byte) (*Artifact, error) { return ParseVersion(Version1, raw) }
func ParseVersion(version string, raw []byte) (*Artifact, error) {
	if version != Version1 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedVersion, version)
	}
	a, err := v1.Parse(raw)
	if err != nil {
		return nil, err
	}
	canonical, err := jcs.Canonical(a.Definition.Canonical())
	if err != nil {
		return nil, err
	}
	return &Artifact{
		version: version, id: a.ID, canonical: canonical, definition: a.Definition,
	}, nil
}

// ParseSet verifies the supplied content IDs while constructing immutable artifacts.
func ParseSet(version string, docs map[string][]byte) (map[string]*Artifact, error) {
	if version != Version1 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedVersion, version)
	}
	out := make(map[string]*Artifact, len(docs))
	for _, id := range sortedIDs(docs) {
		a, err := ParseVersion(version, docs[id])
		if err != nil {
			return nil, err
		}
		if a.ID() != id {
			return nil, fmt.Errorf("%w: artifact %s has ID %s", ErrInvalid, id, a.ID())
		}
		out[id] = a
	}
	return out, nil
}

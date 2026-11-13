package v1

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"slices"

	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/arkade-os/executor/pkg/template/internal/version/v1/schema"
)

type Document struct {
	syntax    *schema.Template
	canonical []byte
	id        string
	spendID   string
	artifacts []string
}

func Decode(raw []byte) (*Document, error) {
	s, err := schema.Decode(raw)
	if err != nil {
		return nil, err
	}
	return document(s)
}

func DecodeValue(value any) (*Document, error) {
	s, err := schema.DecodeValue(value)
	if err != nil {
		return nil, err
	}
	return document(s)
}

func (d *Document) ID() string            { return d.id }
func (d *Document) SpendID() string       { return d.spendID }
func (d *Document) Canonical() []byte     { return bytes.Clone(d.canonical) }
func (d *Document) ArtifactIDs() []string { return slices.Clone(d.artifacts) }

func Compile(d *Document, artifacts map[string]*artifact.Artifact) (*Template, error) {
	t, err := compile(d.syntax, artifacts)
	if err != nil {
		return nil, err
	}
	t.id, t.spendID = d.id, d.spendID
	return t, nil
}

func document(s *schema.Template) (*Document, error) {
	s.Normalize()
	b, err := s.Canonical()
	if err != nil {
		return nil, err
	}
	spend, err := s.SpendCanonical()
	if err != nil {
		return nil, err
	}
	sum, spendSum := sha256.Sum256(b), sha256.Sum256(spend)
	d := &Document{
		syntax: s, canonical: b, id: hex.EncodeToString(sum[:]),
		spendID: hex.EncodeToString(spendSum[:]),
	}
	add := func(c *schema.Construction) {
		id := c.Definition.Artifact
		if c.Definition.Def == nil && !slices.Contains(d.artifacts, id) {
			d.artifacts = append(d.artifacts, id)
		}
	}
	for i := range s.Inputs {
		add(&s.Inputs[i].Contract)
	}
	for i := range s.Outputs {
		if c := s.Outputs[i].Locking.Contract; c != nil {
			add(c)
		}
	}
	return d, nil
}

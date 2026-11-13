package template

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/arkade-os/executor/pkg/template/internal/jcs"
	v1 "github.com/arkade-os/executor/pkg/template/internal/version/v1"
)

const Version1 = "template/v1"

const maxDocumentBytes = 1 << 20

// Document is decoded but not yet checked against its artifacts.
type Document struct {
	source  []byte
	version string
	v1      *v1.Document
}

func (d *Document) Version() string       { return d.version }
func (d *Document) ID() string            { return d.v1.ID() }
func (d *Document) SpendID() string       { return d.v1.SpendID() }
func (d *Document) Canonical() []byte     { return d.v1.Canonical() }
func (d *Document) ArtifactIDs() []string { return d.v1.ArtifactIDs() }
func (d *Document) Source() []byte        { return bytes.Clone(d.source) }

func SupportedVersions() []string { return []string{Version1} }

// Decode reads the format before any version-specific rule.
func Decode(raw []byte) (*Document, error) {
	if len(raw) > maxDocumentBytes {
		return nil, diagnostic("decode", ErrInvalidTemplate, "document exceeds 1 MiB")
	}
	value, err := jcs.Decode(raw)
	if err != nil {
		return nil, wrap("decode", fmt.Errorf("%w: %v", ErrInvalidTemplate, err))
	}
	obj, ok := value.(map[string]any)
	if !ok {
		return nil, diagnostic("decode", ErrInvalidTemplate, "document must be an object")
	}
	version, ok := obj["format"].(string)
	if !ok || version == "" {
		return nil, diagnostic("decode", ErrInvalidTemplate, "format must be a non-empty string")
	}
	switch version {
	case Version1:
		d, err := v1.DecodeValue(value)
		if err != nil {
			return nil, wrap("decode", err)
		}
		return &Document{version: version, v1: d, source: bytes.Clone(raw)}, nil
	default:
		return nil, wrap("decode", &UnsupportedVersionError{Version: version})
	}
}

func Compile(d *Document, artifacts map[string]*artifact.Artifact) (*Template, error) {
	if d == nil || d.v1 == nil {
		return nil, diagnostic("compile", ErrInvalidTemplate, "missing decoded document")
	}
	t, err := v1.Compile(d.v1, artifacts)
	if err != nil {
		return nil, wrap("compile", err)
	}
	return &Template{version: d.version, v1: t}, nil
}

func Parse(raw []byte, artifacts map[string][]byte) (*Template, error) {
	d, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	return CompileDocuments(d, artifacts)
}

// CompileDocuments parses the referenced entries of artifacts, by content ID, and compiles d.
func CompileDocuments(d *Document, artifacts map[string][]byte) (*Template, error) {
	referenced := make(map[string][]byte)
	for _, id := range d.ArtifactIDs() {
		raw, ok := artifacts[id]
		if !ok {
			return nil, diagnostic("compile", ErrInvalidTemplate, "artifact "+id+" not provided")
		}
		referenced[id] = raw
	}
	parsed, err := artifact.ParseSet(artifact.Version1, referenced)
	if err != nil {
		return nil, wrap("compile", fmt.Errorf("%w: %w", ErrInvalidTemplate, err))
	}
	return Compile(d, parsed)
}

func ArtifactIDs(raw []byte) ([]string, error) {
	d, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	return d.ArtifactIDs(), nil
}

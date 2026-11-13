package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/executor/pkg/template"
)

const (
	TemplateStatusActive   = "active"
	TemplateStatusDisabled = "disabled"
)

type Template struct {
	ID          string
	Document    []byte
	ArtifactIDs []string // foreign keys to artifacts
	Params      []Param
	Type        template.Type
	Status      string
	Failures    int
	CreatedAt   time.Time
}

type Param struct {
	Name string
	Type string
}

type TemplateRepository interface {
	// AddOrUpdate inserts t, filling its creation time in, or persists the status and
	// failures of the stored template with its id.
	AddOrUpdate(ctx context.Context, t *Template) error
	Get(ctx context.Context, id string) (*Template, error)
	Count(ctx context.Context) (int64, error)
	// List returns the templates with status, all of them when status is empty, newest first and
	// without documents.
	List(ctx context.Context, status string) ([]Template, error)
	// Delete fails with ErrTemplateInUse while a delegation of any status references the template.
	Delete(ctx context.Context, id string) error
}

// NewTemplate parses a document against the documents of its artifacts, keyed by id.
func NewTemplate(document []byte, maxBytes int, artifacts map[string][]byte) (*Template, error) {
	if maxBytes > 0 && len(document) > maxBytes {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrInvalidDocument, maxBytes)
	}
	decoded, err := template.Decode(document)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return NewDecodedTemplate(decoded, artifacts)
}

func NewDecodedTemplate(
	document *template.Document, artifacts map[string][]byte,
) (*Template, error) {
	parsed, err := template.CompileDocuments(document, artifacts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	if parsed.Type() == template.Onchain {
		return nil, fmt.Errorf("%w: onchain templates are not served", ErrUnsupported)
	}
	if parsed.Type() == template.Virtual && !parsed.Arkade() {
		return nil, fmt.Errorf("%w: virtual templates must carry an arkade packet", ErrUnsupported)
	}
	if len(parsed.Triggers()) > 1 {
		return nil, fmt.Errorf("%w: a trigger of several rules is not served", ErrUnsupported)
	}
	t := Template{
		ID: parsed.ID(), Document: document.Source(), ArtifactIDs: parsed.Artifacts(),
		Type: parsed.Type(), Status: TemplateStatusActive,
	}
	for _, f := range parsed.Variables() {
		t.Params = append(t.Params, Param{Name: f.Name, Type: f.Type})
	}
	return &t, nil
}

// SetStatus activates or disables t; a template that becomes active starts from zero failures.
func (t *Template) SetStatus(status string) error {
	if status != TemplateStatusActive && status != TemplateStatusDisabled {
		return fmt.Errorf("%w: %q", ErrInvalidStatus, status)
	}
	if status == TemplateStatusActive {
		t.Failures = 0
	}
	t.Status = status
	return nil
}

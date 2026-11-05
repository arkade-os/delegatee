package registry

import (
	"context"
	"fmt"
	"time"

	"github.com/arkade-os/delegatee/pkg/template"
)

// Artifact is a compiled contract definition, stored under the hash of its canonical document.
type Artifact struct {
	ID        string
	Document  []byte
	CreatedAt time.Time
}

// NewArtifact validates document and derives its id; maxBytes bounds the document size, 0 means no bound.
func NewArtifact(document []byte, maxBytes int) (*Artifact, error) {
	if maxBytes > 0 && len(document) > maxBytes {
		return nil, fmt.Errorf("%w: document exceeds %d bytes", ErrInvalidDocument, maxBytes)
	}
	parsed, err := template.ParseArtifact(document)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	return &Artifact{ID: parsed.ID, Document: document}, nil
}

type ArtifactRepository interface {
	// Add inserts a, filling its creation time in.
	Add(ctx context.Context, a *Artifact) error
	Get(ctx context.Context, id string) (*Artifact, error)
	Count(ctx context.Context) (int64, error)
	// List returns every artifact without its document, newest first.
	List(ctx context.Context) ([]Artifact, error)
	// Delete fails with ErrArtifactInUse while a template references the artifact.
	Delete(ctx context.Context, id string) error
}

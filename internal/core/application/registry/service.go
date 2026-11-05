package registry

import (
	"context"
	"errors"
	"sync"

	"github.com/arkade-os/delegatee/internal/core/domain/registry"
	"github.com/arkade-os/delegatee/pkg/template"
	log "github.com/sirupsen/logrus"
)

type Limits struct {
	MaxArtifacts     int
	MaxTemplates     int
	MaxDocumentBytes int
}

type Service struct {
	artifacts registry.ArtifactRepository
	templates registry.TemplateRepository
	limits    Limits
	mu        sync.Mutex // one write at a time, so caps hold and no change overwrites another
	parsed    sync.Map   // *template.Template by id; documents are content-addressed, so entries never go stale
}

func NewService(artifacts registry.ArtifactRepository, templates registry.TemplateRepository, limits Limits) *Service {
	return &Service{artifacts: artifacts, templates: templates, limits: limits}
}

func (s *Service) RegisterArtifact(ctx context.Context, document []byte) (*registry.Artifact, error) {
	a, err := registry.NewArtifact(document, s.limits.MaxDocumentBytes)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.artifacts.Get(ctx, a.ID)
	if !errors.Is(err, registry.ErrArtifactNotFound) {
		return stored, err
	}
	if err := s.belowCap(ctx, s.artifacts.Count, s.limits.MaxArtifacts); err != nil {
		return nil, err
	}
	if err := s.artifacts.Add(ctx, a); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Service) GetArtifact(ctx context.Context, id string) (*registry.Artifact, error) {
	return s.artifacts.Get(ctx, id)
}

func (s *Service) ListArtifacts(ctx context.Context) ([]registry.Artifact, error) {
	return s.artifacts.List(ctx)
}

func (s *Service) DeleteArtifact(ctx context.Context, id string) error {
	return s.artifacts.Delete(ctx, id)
}

func (s *Service) RegisterTemplate(ctx context.Context, document []byte) (*registry.Template, error) {
	ids, _ := template.ArtifactIDs(document) // a document it cannot read fails in NewTemplate
	artifacts, err := s.loadArtifacts(ctx, ids)
	if err != nil {
		return nil, err
	}
	t, err := registry.NewTemplate(document, s.limits.MaxDocumentBytes, artifacts)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, err := s.templates.Get(ctx, t.ID)
	if !errors.Is(err, registry.ErrTemplateNotFound) {
		return stored, err
	}
	if err := s.belowCap(ctx, s.templates.Count, s.limits.MaxTemplates); err != nil {
		return nil, err
	}
	if err := s.templates.AddOrUpdate(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

// belowCap fails with ErrCapReached when max rows exist; 0 means no cap.
func (s *Service) belowCap(ctx context.Context, count func(context.Context) (int64, error), max int) error {
	if max <= 0 {
		return nil
	}
	n, err := count(ctx)
	if err != nil {
		return err
	}
	if n >= int64(max) {
		return registry.ErrCapReached
	}
	return nil
}

func (s *Service) GetTemplate(ctx context.Context, id string) (*registry.Template, error) {
	return s.templates.Get(ctx, id)
}

// Parsed returns the stored template, read fresh for its status, and its parsed form, artifacts resolved.
func (s *Service) Parsed(ctx context.Context, id string) (*registry.Template, *template.Template, error) {
	t, err := s.templates.Get(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if cached, ok := s.parsed.Load(id); ok {
		return t, cached.(*template.Template), nil
	}
	artifacts, err := s.loadArtifacts(ctx, t.ArtifactIDs)
	if err != nil {
		return nil, nil, err
	}
	parsed, err := template.Parse(t.Document, artifacts)
	if err != nil {
		return nil, nil, err
	}
	s.parsed.Store(id, parsed)
	return t, parsed, nil
}

// Usable is Parsed for a template about to be used anew: it fails with ErrTemplateDisabled when the template is disabled.
func (s *Service) Usable(ctx context.Context, id string) (*template.Template, error) {
	t, parsed, err := s.Parsed(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.Status != registry.TemplateStatusActive {
		return nil, registry.ErrTemplateDisabled
	}
	return parsed, nil
}

func (s *Service) ListTemplates(ctx context.Context, status string) ([]registry.Template, error) {
	return s.templates.List(ctx, status)
}

func (s *Service) SetTemplateStatus(ctx context.Context, id, status string) error {
	_, err := s.updateTemplate(ctx, id, func(t *registry.Template) error { return t.SetStatus(status) })
	return err
}

// RecordOutcome tells a template how an attempt of its ended and returns its failures and status.
// A success resets the failures; the template is disabled once maxFailures failures follow one another.
func (s *Service) RecordOutcome(ctx context.Context, id string, success bool, maxFailures int) (int, string, error) {
	t, err := s.updateTemplate(ctx, id, func(t *registry.Template) error {
		if success {
			t.Failures = 0
			return nil
		}
		t.Failures++
		if t.Failures >= maxFailures {
			t.Status = registry.TemplateStatusDisabled
		}
		return nil
	})
	if err != nil {
		return 0, "", err
	}
	return t.Failures, t.Status, nil
}

func (s *Service) updateTemplate(ctx context.Context, id string, change func(*registry.Template) error) (*registry.Template, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.templates.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := change(t); err != nil {
		return nil, err
	}
	if err := s.templates.AddOrUpdate(ctx, t); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *Service) DeleteTemplate(ctx context.Context, id string) error {
	return s.templates.Delete(ctx, id)
}

// RegisterDefaults registers the daemon's own documents. An invalid document is an error; any other failure is logged.
func (s *Service) RegisterDefaults(ctx context.Context, artifacts, templates map[string][]byte) error {
	for name, doc := range artifacts {
		if _, err := s.RegisterArtifact(ctx, doc); err != nil {
			if errors.Is(err, registry.ErrInvalidDocument) {
				return err
			}
			log.WithError(err).Error("register default artifact " + name)
		}
	}
	for name, doc := range templates {
		if _, err := s.RegisterTemplate(ctx, doc); errors.Is(err, registry.ErrInvalidDocument) {
			return err
		} else if err != nil {
			log.WithError(err).Error("register default template " + name)
		}
	}
	return nil
}

func (s *Service) loadArtifacts(ctx context.Context, ids []string) (map[string][]byte, error) {
	docs := make(map[string][]byte, len(ids))
	for _, id := range ids {
		a, err := s.artifacts.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		docs[id] = a.Document
	}
	return docs, nil
}

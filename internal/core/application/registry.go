package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	log "github.com/sirupsen/logrus"
)

var (
	ErrInvalidDocument = errors.New("invalid document")
	ErrInvalidStatus   = errors.New("invalid status")
	// an outage, not a bad document
	errArtifactStore = errors.New("artifact store")
)

func (s *service) checkDocument(doc []byte) error {
	if len(doc) == 0 {
		return fmt.Errorf("%w: empty", ErrInvalidDocument)
	}
	if len(doc) > s.limits.MaxDocumentBytes {
		return fmt.Errorf("%w: larger than %d bytes", ErrInvalidDocument, s.limits.MaxDocumentBytes)
	}
	return nil
}

func (s *service) RegisterArtifact(ctx context.Context, doc []byte) (*domain.Artifact, error) {
	if err := s.checkDocument(doc); err != nil {
		return nil, err
	}
	parsed, err := template.ParseArtifact(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	id := parsed.ID
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	a, err := s.repo.CreateArtifact(ctx, id, doc, s.limits.MaxArtifacts)
	if errors.Is(err, domain.ErrCapReached) {
		return nil, fmt.Errorf("%w: artifact cap reached", ErrFull)
	}
	if err != nil {
		return nil, err
	}
	log.WithField("artifact", id).Info("artifact registered")
	return a, nil
}

func (s *service) GetArtifact(ctx context.Context, id string) (*domain.Artifact, error) {
	return s.repo.GetArtifact(ctx, id)
}

func (s *service) ListArtifacts(ctx context.Context) ([]domain.Artifact, error) {
	return s.repo.ListArtifacts(ctx)
}

// DeleteArtifact holds the registration lock: a template registered meanwhile may reference it.
func (s *service) DeleteArtifact(ctx context.Context, id string) error {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	return s.repo.DeleteArtifact(ctx, id)
}

func (s *service) resolveArtifact(ctx context.Context, id string) ([]byte, error) {
	a, err := s.repo.GetArtifact(ctx, id)
	if errors.Is(err, domain.ErrArtifactNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errArtifactStore, err)
	}
	return a.Document, nil
}

func (s *service) parse(ctx context.Context, doc []byte) (*template.Template, error) {
	t, err := template.Parse(ctx, doc, s.resolveArtifact)
	if err != nil {
		return nil, moduleError(err, nil)
	}
	return t, nil
}

func (s *service) RegisterTemplate(ctx context.Context, doc []byte) (*domain.Template, error) {
	if err := s.checkDocument(doc); err != nil {
		return nil, err
	}
	parsed, err := s.parse(ctx, doc)
	if errors.Is(err, errArtifactStore) || errors.Is(err, ErrUnsupported) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	var params []domain.Param
	for _, p := range parsed.Variables() {
		params = append(params, domain.Param{Name: p.Name, Type: p.Type})
	}
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	t, err := s.repo.CreateTemplate(ctx, domain.Template{
		ID: parsed.ID(), Document: doc, ArtifactIDs: parsed.Artifacts(), Params: params,
	}, s.limits.MaxTemplates)
	if errors.Is(err, domain.ErrCapReached) {
		return nil, fmt.Errorf("%w: template cap reached", ErrFull)
	}
	if err != nil {
		return nil, err
	}
	log.WithField("template", t.ID).Info("template registered")
	return t, nil
}

func (s *service) GetTemplate(ctx context.Context, id string) (*domain.Template, error) {
	return s.repo.GetTemplate(ctx, id)
}

func (s *service) ListTemplates(ctx context.Context, status string) ([]domain.Template, error) {
	return s.repo.ListTemplates(ctx, status)
}

func (s *service) SetTemplateStatus(ctx context.Context, id, status string) error {
	if status != domain.TemplateStatusActive && status != domain.TemplateStatusDisabled {
		return fmt.Errorf("%w: must be active or disabled", ErrInvalidStatus)
	}
	if err := s.repo.SetTemplateStatus(ctx, id, status); err != nil {
		return err
	}
	log.WithFields(log.Fields{"template": id, "status": status}).Info("template status set")
	return nil
}

func (s *service) SetTemplateTrusted(ctx context.Context, id string, trusted bool) error {
	if err := s.repo.SetTemplateTrusted(ctx, id, trusted); err != nil {
		return err
	}
	log.WithFields(log.Fields{"template": id, "trusted": trusted}).Info("template trust set")
	return nil
}

// DeleteTemplate holds the registration lock: a delegation registered meanwhile may reference it.
func (s *service) DeleteTemplate(ctx context.Context, id string) error {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	return s.repo.DeleteTemplate(ctx, id)
}

func (s *service) DelegationsByTemplate(ctx context.Context) (map[string]int64, error) {
	return s.repo.CountDelegationsByTemplate(ctx)
}

// parseTemplate refuses an inactive template, or an untrusted one with secrets: a secret could land in a public script.
func (s *service) parseTemplate(ctx context.Context, id string) (*template.Template, error) {
	t, err := s.repo.GetTemplate(ctx, id)
	if err != nil {
		return nil, err
	}
	if t.Status != domain.TemplateStatusActive {
		return nil, domain.ErrTemplateDisabled
	}
	parsed, err := s.parse(ctx, t.Document)
	if err != nil {
		return nil, fmt.Errorf("template %s: %w", id, err)
	}
	if parsed.Secrets() && (len(s.encryptionKeys) == 0 || !t.Trusted) {
		return nil, ErrSecretsRequired
	}
	return parsed, nil
}

// Bootstrap disables every stored template the engine cannot parse.
func (s *service) Bootstrap(ctx context.Context) error {
	stored, err := s.repo.ListTemplates(ctx, domain.TemplateStatusActive)
	if err != nil {
		return err
	}
	for _, t := range stored {
		full, err := s.repo.GetTemplate(ctx, t.ID)
		if err != nil {
			return err
		}
		if _, err := s.parse(ctx, full.Document); errors.Is(err, errArtifactStore) {
			return err
		} else if err != nil {
			log.WithError(err).WithField("template", t.ID).Error("stored template no longer parses: disabled")
			if err := s.repo.SetTemplateStatus(ctx, t.ID, domain.TemplateStatusDisabled); err != nil {
				return err
			}
		}
	}
	return nil
}

package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/arkade-os/delegatee/internal/core/domain/registry"
	"github.com/arkade-os/delegatee/templates"
	"github.com/stretchr/testify/require"
)

func TestParsedResolvesArtifactsOnce(t *testing.T) {
	s, artifacts, _, tpl := newService(t)

	for range 3 {
		_, parsed, err := s.Parsed(t.Context(), tpl.ID)
		require.NoError(t, err)
		require.Equal(t, tpl.ID, parsed.ID())
	}
	require.Equal(t, 1, artifacts.gets)
}

func TestParsedReadsTheStatusFresh(t *testing.T) {
	s, _, repo, tpl := newService(t)

	stored, _, err := s.Parsed(t.Context(), tpl.ID)
	require.NoError(t, err)
	require.Equal(t, registry.TemplateStatusActive, stored.Status)

	repo.t.Status = registry.TemplateStatusDisabled
	stored, _, err = s.Parsed(t.Context(), tpl.ID)
	require.NoError(t, err)
	require.Equal(t, registry.TemplateStatusDisabled, stored.Status)
}

func TestUsableRefusesADisabledTemplate(t *testing.T) {
	s, _, repo, tpl := newService(t)

	parsed, err := s.Usable(t.Context(), tpl.ID)
	require.NoError(t, err)
	require.Equal(t, tpl.ID, parsed.ID())

	repo.t.Status = registry.TemplateStatusDisabled
	_, err = s.Usable(t.Context(), tpl.ID)
	require.ErrorIs(t, err, registry.ErrTemplateDisabled)
	_, _, err = s.Parsed(t.Context(), tpl.ID)
	require.NoError(t, err)
}

func TestRecordOutcome(t *testing.T) {
	s, _, repo, tpl := newService(t)
	record := func(success bool) (int, string) {
		t.Helper()
		failures, status, err := s.RecordOutcome(t.Context(), tpl.ID, success, 3)
		require.NoError(t, err)
		return failures, status
	}

	record(false)
	failures, _ := record(false)
	require.Equal(t, 2, failures)
	failures, _ = record(true)
	require.Zero(t, failures, "a success resets the count")

	for range 2 {
		_, status := record(false)
		require.Equal(t, registry.TemplateStatusActive, status)
	}
	failures, status := record(false)
	require.Equal(t, 3, failures)
	require.Equal(t, registry.TemplateStatusDisabled, status)
	require.Equal(t, registry.TemplateStatusDisabled, repo.t.Status)
	_, status = record(true)
	require.Equal(t, registry.TemplateStatusDisabled, status, "an outcome does not enable it")
}

func TestRegisterArtifactCapUnderConcurrency(t *testing.T) {
	const limit, workers = 5, 20
	repo := &artifactRows{rows: map[string]registry.Artifact{}}
	s := NewService(repo, nil, Limits{MaxArtifacts: limit})
	doc := templates.Artifacts[slices.Sorted(maps.Keys(templates.Artifacts))[0]]
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := range workers {
		wg.Go(func() {
			var a map[string]any
			require.NoError(t, json.Unmarshal(doc, &a))
			a["contractName"] = fmt.Sprint("C", i) // a distinct contract, so a distinct id
			distinct, err := json.Marshal(a)
			require.NoError(t, err)
			_, err = s.RegisterArtifact(t.Context(), distinct)
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	var capped int
	for err := range errs {
		if err != nil {
			require.ErrorIs(t, err, registry.ErrCapReached)
			capped++
		}
	}
	require.Equal(t, workers-limit, capped)
	require.Len(t, repo.rows, limit)
}

func TestRegisterArtifactAgainAtTheCap(t *testing.T) {
	repo := &artifactRows{rows: map[string]registry.Artifact{}}
	s := NewService(repo, nil, Limits{MaxArtifacts: 1})
	doc := templates.Artifacts[slices.Sorted(maps.Keys(templates.Artifacts))[0]]
	first, err := s.RegisterArtifact(t.Context(), doc)
	require.NoError(t, err)
	again, err := s.RegisterArtifact(t.Context(), doc)
	require.NoError(t, err)
	require.Equal(t, first, again)
}

// artifactRows is the part of a registry.ArtifactRepository that RegisterArtifact uses.
type artifactRows struct {
	registry.ArtifactRepository
	mu   sync.Mutex
	rows map[string]registry.Artifact
}

func (r *artifactRows) Get(_ context.Context, id string) (*registry.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.rows[id]
	if !ok {
		return nil, registry.ErrArtifactNotFound
	}
	return &a, nil
}

func (r *artifactRows) Add(_ context.Context, a *registry.Artifact) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rows[a.ID] = *a
	return nil
}

func (r *artifactRows) Count(context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int64(len(r.rows)), nil
}

type countingArtifacts struct {
	registry.ArtifactRepository
	docs map[string]registry.Artifact
	gets int
}

func (r *countingArtifacts) Get(_ context.Context, id string) (*registry.Artifact, error) {
	r.gets++
	v := r.docs[id]
	return &v, nil
}

type storedTemplate struct {
	registry.TemplateRepository
	t registry.Template
}

func (r *storedTemplate) Get(context.Context, string) (*registry.Template, error) {
	t := r.t
	return &t, nil
}

func (r *storedTemplate) AddOrUpdate(_ context.Context, t *registry.Template) error {
	r.t = *t
	return nil
}

func newService(t *testing.T) (*Service, *countingArtifacts, *storedTemplate, registry.Template) {
	t.Helper()
	artifacts := &countingArtifacts{docs: map[string]registry.Artifact{}}
	docs := map[string][]byte{}
	for _, doc := range templates.Artifacts {
		a, err := registry.NewArtifact(doc, 0)
		require.NoError(t, err)
		artifacts.docs[a.ID] = *a
		docs[a.ID] = a.Document
	}
	tpl, err := registry.NewTemplate(templates.Templates["renew.json"], 0, docs)
	require.NoError(t, err)
	repo := &storedTemplate{t: *tpl}
	return NewService(artifacts, repo, Limits{}), artifacts, repo, *tpl
}

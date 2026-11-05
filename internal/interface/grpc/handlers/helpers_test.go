package handlers

import (
	"context"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/registry"
)

// artifacts is an in-memory registry.ArtifactRepository; Delete checks the references held by templates.
type artifacts struct {
	mu        sync.Mutex
	rows      map[string]registry.Artifact
	templates *templates
}

func newArtifacts(templates *templates) *artifacts {
	return &artifacts{rows: map[string]registry.Artifact{}, templates: templates}
}

func (r *artifacts) Add(_ context.Context, a *registry.Artifact) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	a.CreatedAt = time.Now()
	r.rows[a.ID] = *a
	return nil
}

func (r *artifacts) Count(context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int64(len(r.rows)), nil
}

func (r *artifacts) Get(_ context.Context, id string) (*registry.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.rows[id]
	if !ok {
		return nil, registry.ErrArtifactNotFound
	}
	return &a, nil
}

func (r *artifacts) List(_ context.Context) ([]registry.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]registry.Artifact, 0, len(r.rows))
	for _, a := range r.rows {
		a.Document = nil
		out = append(out, a)
	}
	slices.SortFunc(out, func(a, b registry.Artifact) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (r *artifacts) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rows[id]; !ok {
		return registry.ErrArtifactNotFound
	}
	r.templates.mu.Lock()
	defer r.templates.mu.Unlock()
	for _, t := range r.templates.rows {
		if slices.Contains(t.ArtifactIDs, id) {
			return registry.ErrArtifactInUse
		}
	}
	delete(r.rows, id)
	return nil
}

type templates struct {
	mu   sync.Mutex
	rows map[string]registry.Template
}

func newTemplates() *templates { return &templates{rows: map[string]registry.Template{}} }

func (r *templates) AddOrUpdate(_ context.Context, t *registry.Template) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	stored, ok := r.rows[t.ID]
	if !ok {
		t.CreatedAt = time.Now()
		r.rows[t.ID] = *t
		return nil
	}
	stored.Status, stored.Failures = t.Status, t.Failures
	r.rows[t.ID] = stored
	return nil
}

func (r *templates) Count(context.Context) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return int64(len(r.rows)), nil
}

func (r *templates) Get(_ context.Context, id string) (*registry.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.rows[id]
	if !ok {
		return nil, registry.ErrTemplateNotFound
	}
	return &t, nil
}

func (r *templates) List(_ context.Context, status string) ([]registry.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []registry.Template
	for _, t := range r.rows {
		if status == "" || t.Status == status {
			t.Document = nil
			out = append(out, t)
		}
	}
	slices.SortFunc(out, func(a, b registry.Template) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (r *templates) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.rows[id]; !ok {
		return registry.ErrTemplateNotFound
	}
	delete(r.rows, id)
	return nil
}

type delegations struct {
	mu   sync.Mutex
	rows []delegation.Delegation
}

func newDelegations() *delegations { return &delegations{} }

func (r *delegations) AddOrUpdate(_ context.Context, d *delegation.Delegation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if d.ID == 0 {
		d.ID = int64(len(r.rows) + 1)
		d.CreatedAt = time.Now()
		d.UpdatedAt = d.CreatedAt
		r.rows = append(r.rows, *d)
		return nil
	}
	for i := range r.rows {
		if r.rows[i].ID == d.ID {
			r.rows[i].Status, r.rows[i].UpdatedAt = d.Status, time.Now()
			return nil
		}
	}
	return delegation.ErrDelegationNotFound
}

func (r *delegations) Get(_ context.Context, id int64) (*delegation.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.rows {
		if d.ID == id {
			return &d, nil
		}
	}
	return nil, delegation.ErrDelegationNotFound
}

func (r *delegations) GetByAddress(_ context.Context, address string) (*delegation.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	found := -1
	for i, d := range r.rows {
		if d.Address != address {
			continue
		}
		if found < 0 || d.Status == delegation.StatusActive || r.rows[found].Status != delegation.StatusActive {
			found = i
		}
	}
	if found < 0 {
		return nil, delegation.ErrDelegationNotFound
	}
	v := r.rows[found]
	return &v, nil
}

func (r *delegations) GetByFingerprint(_ context.Context, fingerprint string) (*delegation.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if i := r.newest(fingerprint); i >= 0 {
		v := r.rows[i]
		return &v, nil
	}
	return nil, delegation.ErrDelegationNotFound
}

func (r *delegations) Expire(_ context.Context, before time.Time) ([]delegation.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var expired []delegation.Delegation
	for i := range r.rows {
		if d := r.rows[i]; d.Status == delegation.StatusActive && d.ExpiresAt != nil && !d.ExpiresAt.After(before) {
			r.rows[i].Status, r.rows[i].UpdatedAt = delegation.StatusExpired, time.Now()
			expired = append(expired, r.rows[i])
		}
	}
	return expired, nil
}

func (r *delegations) List(_ context.Context, f delegation.ListFilter) ([]delegation.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []delegation.Delegation{}
	for i := len(r.rows) - 1; i >= 0 && len(out) < f.Limit; i-- {
		d := r.rows[i]
		if (f.Status == "" || d.Status == f.Status) && (f.Cursor == 0 || d.ID < f.Cursor) {
			out = append(out, d)
		}
	}
	return out, nil
}

func (r *delegations) CountActive(_ context.Context) (clients, spawned int64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.rows {
		switch {
		case d.Status != delegation.StatusActive:
		case d.StreamID != 0:
			spawned++
		default:
			clients++
		}
	}
	return clients, spawned, nil
}

func (r *delegations) Prune(_ context.Context, before time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	r.rows = slices.DeleteFunc(r.rows, func(d delegation.Delegation) bool {
		gone := d.StreamID != 0 && d.Status == delegation.StatusExpired && !d.ExpiresAt.After(before)
		if gone {
			n++
		}
		return gone
	})
	return n, nil
}

func (r *delegations) newest(fingerprint string) int {
	for i := len(r.rows) - 1; i >= 0; i-- {
		if r.rows[i].Fingerprint == fingerprint {
			return i
		}
	}
	return -1
}

type streams struct {
	mu   sync.Mutex
	rows []delegation.Stream
}

func newStreams() *streams { return &streams{} }

func (r *streams) AddOrUpdate(_ context.Context, s *delegation.Stream) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if s.ID != 0 {
		for i := range r.rows {
			if r.rows[i].ID == s.ID {
				r.rows[i].Status = s.Status
				return nil
			}
		}
		return delegation.ErrStreamNotFound
	}
	for _, row := range r.rows {
		if row.TemplateID == s.TemplateID && maps.Equal(row.Variables, s.Variables) {
			*s = row
			return nil
		}
	}
	s.ID = int64(len(r.rows) + 1)
	s.CreatedAt = time.Now()
	r.rows = append(r.rows, *s)
	return nil
}

func (r *streams) Get(_ context.Context, id int64) (*delegation.Stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, row := range r.rows {
		if row.ID == id {
			return &row, nil
		}
	}
	return nil, delegation.ErrStreamNotFound
}

func (r *streams) List(_ context.Context, status string) ([]delegation.Stream, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []delegation.Stream{}
	for _, row := range r.rows {
		if status == "" || row.Status == status {
			out = append(out, row)
		}
	}
	return out, nil
}

// coins keeps the coins the handlers read; the loop's methods are left out.
type coins struct {
	delegation.CoinRepository
	mu   sync.Mutex
	rows map[string]delegation.Coin
}

func newCoins() *coins { return &coins{rows: map[string]delegation.Coin{}} }

func (r *coins) Upsert(_ context.Context, coins ...delegation.Coin) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range coins {
		r.rows[c.Outpoint] = c
	}
	return nil
}

func (r *coins) ListByDelegation(_ context.Context, id int64) ([]delegation.Coin, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []delegation.Coin
	for _, c := range r.rows {
		if c.DelegationID == id {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b delegation.Coin) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

type attempts struct {
	mu   sync.Mutex
	rows []delegation.Attempt
}

func newAttempts() *attempts { return &attempts{} }

func (r *attempts) AddOrUpdate(_ context.Context, a *delegation.Attempt) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a.ID == 0 {
		a.ID = int64(len(r.rows) + 1)
		a.CreatedAt = time.Now()
		a.UpdatedAt = a.CreatedAt
		r.rows = append(r.rows, *a)
		return nil
	}
	for i := range r.rows {
		if r.rows[i].ID == a.ID {
			r.rows[i].Txs, r.rows[i].Status, r.rows[i].Error = a.Txs, a.Status, a.Error
			r.rows[i].UpdatedAt = time.Now()
			return nil
		}
	}
	return delegation.ErrAttemptNotFound
}

func (r *attempts) ListPending(_ context.Context) ([]delegation.Attempt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []delegation.Attempt
	for _, a := range r.rows {
		if a.Pending() {
			out = append(out, a)
		}
	}
	return out, nil
}

func (r *attempts) ListByDelegation(_ context.Context, id, cursor int64, limit int) ([]delegation.Attempt, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []delegation.Attempt{}
	for i := len(r.rows) - 1; i >= 0 && len(out) < limit; i-- {
		a := r.rows[i]
		if a.DelegationID == id && (cursor == 0 || a.ID < cursor) {
			out = append(out, a)
		}
	}
	return out, nil
}

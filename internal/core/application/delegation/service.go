package delegation

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/executor/internal/core/application/registry"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	registrydomain "github.com/arkade-os/executor/internal/core/domain/registry"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/arkade-os/executor/pkg/template/ecies"
	"github.com/btcsuite/btcd/btcec/v2"
	log "github.com/sirupsen/logrus"
)

type Limits struct {
	MinDelegationExpiry time.Duration
	MaxDelegations      int
	MaxStreamChildren   int           // active delegations the streams spawned, counted apart from MaxDelegations
	ExpiryInterval      time.Duration // how often delegations past their expiry are marked
	PruneAfter          time.Duration // how long after expiry a spawned delegation is deleted; zero keeps them
}

type Info struct {
	Network       string
	CosignerKey   string
	ServerKey     string
	EmulatorKey   string
	EncryptionKey string // empty without an encryption key
}

type Service struct {
	registry    *registry.Service
	delegations delegation.DelegationRepository
	streams     delegation.StreamRepository
	indexer     ports.Indexer
	keys        template.TriggerKeys // the public keys templates and triggers run under
	encryption  *btcec.PrivateKey    // opens a template's secrets
	network     arklib.Network
	info        Info
	limits      Limits
	onChange    func(delegation.Delegation)
	addMu       sync.Mutex    // one add at a time, so the fingerprint and cap checks hold
	changed     chan struct{} // the streams changed
	stop        context.CancelFunc
	wg          sync.WaitGroup
}

func NewService(
	registry *registry.Service, delegations delegation.DelegationRepository, streams delegation.StreamRepository, indexer ports.Indexer,
	cosigner *btcec.PublicKey, encryption *btcec.PrivateKey, server, emulator *btcec.PublicKey, network arklib.Network, limits Limits,
) *Service {
	s := &Service{
		registry: registry, delegations: delegations, streams: streams, indexer: indexer,
		keys:       template.TriggerKeys{Keys: template.Keys{Server: server, Emulator: emulator, Cosigner: cosigner}},
		encryption: encryption, network: network, limits: limits, changed: make(chan struct{}, 1),
	}
	s.info = Info{
		Network:     network.Name,
		CosignerKey: hex.EncodeToString(cosigner.SerializeCompressed()),
		ServerKey:   hex.EncodeToString(server.SerializeCompressed()),
		EmulatorKey: hex.EncodeToString(emulator.SerializeCompressed()),
	}
	if encryption != nil {
		s.keys.Encryption = encryption.PubKey()
		s.info.EncryptionKey = hex.EncodeToString(s.keys.Encryption.SerializeCompressed())
	}
	return s
}

func (s *Service) RegisterDelegation(
	ctx context.Context, templateID string, variables map[string]string, expiresAt *time.Time,
) (*delegation.Delegation, error) {
	tmpl, err := s.registry.Usable(ctx, templateID)
	if err != nil {
		return nil, err
	}

	d, err := delegation.NewDelegation(delegation.DelegationParams{
		Template: tmpl, Variables: variables, ExpiresAt: expiresAt,
		Now: time.Now(), MinExpiry: s.limits.MinDelegationExpiry,
		Keys: s.keys.Keys, Decrypt: s.decryptFor(templateID), Network: s.network,
	})
	if err != nil {
		return nil, err
	}
	created, err := s.add(ctx, d, s.limits.MaxDelegations)
	if err != nil {
		return nil, err
	}
	log.WithFields(log.Fields{"id": created.ID, "address": created.Address, "template": created.TemplateID}).Info("delegation registered")
	s.notify(*created)
	return created, nil
}

// decryptFor is nil without an encryption key.
func (s *Service) decryptFor(templateID string) func([]byte) ([]byte, error) {
	if s.encryption == nil {
		return nil
	}
	return func(ciphertext []byte) ([]byte, error) {
		return ecies.Decrypt(s.encryption, ciphertext, templateID)
	}
}

// add stores d, or returns the active delegation of its fingerprint when there is one. It fails with
// ErrBlocked when the newest delegation of the fingerprint is cancelled, and with ErrCapReached when
// max active delegations of its origin exist (0: no cap): those streams spawned count apart.
func (s *Service) add(ctx context.Context, d *delegation.Delegation, max int) (*delegation.Delegation, error) {
	s.addMu.Lock()
	defer s.addMu.Unlock()
	newest, err := s.delegations.GetByFingerprint(ctx, d.Fingerprint)
	switch {
	case err == nil && newest.Status == delegation.StatusActive:
		return newest, nil
	case err == nil && newest.Status == delegation.StatusCancelled:
		return nil, delegation.ErrBlocked
	case err != nil && !errors.Is(err, delegation.ErrDelegationNotFound):
		return nil, err
	}
	if max > 0 {
		clients, spawned, err := s.delegations.CountActive(ctx)
		if err != nil {
			return nil, err
		}
		active := clients
		if d.StreamID != 0 {
			active = spawned
		}
		if active >= int64(max) {
			return nil, delegation.ErrCapReached
		}
	}
	if err := s.delegations.AddOrUpdate(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

func (s *Service) OnChange(fn func(delegation.Delegation)) { s.onChange = fn }

// Instance is a delegation's template filled with its variables and keys.
type Instance struct {
	Delegation *delegation.Delegation
	Template   *template.Instance
	Type       template.Type
	Disabled   bool // whether the template is switched off, by the operator or by its failures
}

func (s *Service) Instance(ctx context.Context, id int64) (*Instance, error) {
	d, err := s.delegations.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	stored, tmpl, err := s.registry.Parsed(ctx, d.TemplateID)
	if err != nil {
		return nil, err
	}
	inst, err := d.Instantiate(tmpl, s.keys.Keys, s.decryptFor(d.TemplateID))
	if err != nil {
		return nil, err
	}
	return &Instance{
		Delegation: d, Template: inst, Type: tmpl.Type(),
		Disabled: stored.Status != registrydomain.TemplateStatusActive,
	}, nil
}

func (s *Service) CountActive(ctx context.Context) (int64, error) {
	clients, spawned, err := s.delegations.CountActive(ctx)
	return clients + spawned, err
}

func (s *Service) GetDelegation(ctx context.Context, id int64) (*delegation.Delegation, error) {
	return s.delegations.Get(ctx, id)
}

func (s *Service) GetDelegationByAddress(ctx context.Context, address string) (*delegation.Delegation, error) {
	return s.delegations.GetByAddress(ctx, address)
}

func (s *Service) CancelDelegation(ctx context.Context, id int64) error {
	return s.transition(ctx, id, "cancelled", (*delegation.Delegation).Cancel)
}

func (s *Service) ResumeDelegation(ctx context.Context, id int64) error {
	return s.transition(ctx, id, "resumed", (*delegation.Delegation).Resume)
}

func (s *Service) transition(ctx context.Context, id int64, verb string, step func(*delegation.Delegation) error) error {
	d, err := s.delegations.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := step(d); err != nil {
		return err
	}
	if err := s.delegations.AddOrUpdate(ctx, d); err != nil {
		return err
	}
	log.WithField("id", id).Info("delegation " + verb)
	s.notify(*d)
	return nil
}

func (s *Service) ListDelegations(ctx context.Context, f delegation.ListFilter) ([]delegation.Delegation, error) {
	return s.delegations.List(ctx, f)
}

// ExpireDelegations marks the active delegations whose expiry has passed at now and deletes the spawned
// ones that expired PruneAfter ago.
func (s *Service) ExpireDelegations(ctx context.Context, now time.Time) (int, error) {
	expired, err := s.delegations.Expire(ctx, now)
	if err != nil {
		return 0, err
	}
	if len(expired) > 0 {
		log.WithField("count", len(expired)).Info("delegations expired")
	}
	for _, d := range expired {
		s.notify(d)
	}
	if s.limits.PruneAfter > 0 {
		pruned, err := s.delegations.Prune(ctx, now.Add(-s.limits.PruneAfter))
		if err != nil {
			return len(expired), err
		}
		if pruned > 0 {
			log.WithField("count", pruned).Info("spawned delegations pruned")
		}
	}
	return len(expired), nil
}

// Start runs ExpireDelegations every ExpiryInterval and follows arkd's transactions while a stream is
// active, until Stop or ctx ends.
func (s *Service) Start(ctx context.Context) {
	ctx, s.stop = context.WithCancel(ctx)
	s.wg.Go(func() {
		ticker := time.NewTicker(s.limits.ExpiryInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if _, err := s.ExpireDelegations(ctx, now); err != nil && ctx.Err() == nil {
					log.WithError(err).Error("expire delegations")
				}
			}
		}
	})
	if s.indexer != nil {
		s.wg.Go(func() {
			s.followTransactions(ctx)
		})
	}
}

func (s *Service) Stop() {
	if s.stop == nil {
		return
	}
	s.stop()
	s.wg.Wait()
}

func (s *Service) Info() Info { return s.info }

func (s *Service) notify(d delegation.Delegation) {
	if s.onChange != nil {
		s.onChange(d)
	}
}

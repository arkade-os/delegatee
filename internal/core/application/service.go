// Package application runs delegation templates: it watches their coins and spends them when due.
package application

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	ErrFull            = errors.New("this delegatee accepts no more delegations")
	ErrDelegateKeyLeaf = errors.New("delegate-key leaves require an operator-trusted template")
	ErrSecretsRequired = errors.New("template needs secrets: it requires an encryption key and an operator-trusted template")
	ErrInvalidArgs     = errors.New("invalid template arguments")
	// ErrUnsupported is a template this daemon cannot run.
	ErrUnsupported = errors.New("unsupported template")
	// ErrIneligible is an action or an instance that cannot be built from these coins.
	ErrIneligible = errors.New("ineligible coins")

	errOtherKey              = errors.New("registered under another key")
	errUnusableAdvertisement = errors.New("unusable advertisement")
)

const (
	maxSignerKeys = 16
	// the latest renewal of a delegation is always kept
	renewalsRetention     = 30 * 24 * time.Hour
	renewalsPruneInterval = time.Hour
	concurrency           = 4
)

type Info struct {
	Network          string
	DelegatePubKey   string
	ServerPubKey     string
	EmulatorPubKey   string
	EncryptionPubKey string // empty without an encryption key
}

type Holdings struct {
	Vtxos      int
	Amount     uint64
	NextExpiry time.Time // zero without vtxos
	NextDue    time.Time
	// Late counts vtxos in the last quarter between renewable and expiry.
	Late       int
	LateAmount uint64
}

// Status never depends on arkd: it must stay visible during an outage.
type Status struct {
	LastScan      time.Time // zero until the first scan completes
	RenewingVtxos int
	PollInterval  time.Duration
	// since the process started
	Renewed, Failed uint64
	Holdings        map[int64]Holdings
	// Unwatched is why an active delegation is missing from Holdings, by id.
	Unwatched map[int64]string
}

type Service interface {
	Start()
	Stop()
	Info() Info
	// RegisterDelegation watches the address of a one-input template.
	RegisterDelegation(ctx context.Context, templateID string, variables map[string]string, expiresAt *time.Time) (*domain.Delegation, error)
	// RenewableAt is when each vtxo is due; an error when d no longer instantiates.
	RenewableAt(ctx context.Context, d *domain.Delegation, vtxos []clientlib.Vtxo) ([]time.Time, error)
	// CancelDelegation and CancelDelegationByID are operator cancels: registering the fingerprint again is refused until ResumeDelegation.
	CancelDelegation(ctx context.Context, address string) error
	CancelDelegationByID(ctx context.Context, id int64) error
	ResumeDelegation(ctx context.Context, id int64) error
	GetDelegation(ctx context.Context, address string) (*domain.Delegation, error)
	GetDelegationByID(ctx context.Context, id int64) (*domain.Delegation, error)
	// ListDelegations lists up to limit delegations of a non-empty status, newest first, with ids below a non-zero cursor.
	ListDelegations(ctx context.Context, status string, cursor int64, limit int) ([]domain.Delegation, error)
	ListRenewals(ctx context.Context, d *domain.Delegation) ([]domain.Renewal, error)
	LastRenewals(ctx context.Context) (map[int64]domain.Renewal, error)
	Status() Status
	CountActive(ctx context.Context) (int64, error)
	IntentFees(ctx context.Context) (arkfee.Config, error)
	Vtxos(ctx context.Context, d *domain.Delegation) ([]clientlib.Vtxo, error)
	Health(ctx context.Context) map[string]error

	Bootstrap(ctx context.Context) error
	RegisterArtifact(ctx context.Context, document []byte) (*domain.Artifact, error)
	GetArtifact(ctx context.Context, id string) (*domain.Artifact, error)
	ListArtifacts(ctx context.Context) ([]domain.Artifact, error)
	DeleteArtifact(ctx context.Context, id string) error
	RegisterTemplate(ctx context.Context, document []byte) (*domain.Template, error)
	GetTemplate(ctx context.Context, id string) (*domain.Template, error)
	ListTemplates(ctx context.Context, status string) ([]domain.Template, error)
	SetTemplateStatus(ctx context.Context, id, status string) error
	SetTemplateTrusted(ctx context.Context, id string, trusted bool) error
	DeleteTemplate(ctx context.Context, id string) error
	DelegationsByTemplate(ctx context.Context) (map[string]int64, error)
}

// Limits exist because every active delegation costs an indexer lookup per poll.
type Limits struct {
	// MinWatchExpiry is how far ahead expires_at must be; zero only refuses the past.
	MinWatchExpiry      time.Duration
	MaxDelegations      int
	MaxTemplates        int
	MaxArtifacts        int
	MaxDocumentBytes    int
	TemplateMaxFailures int
}

func (l Limits) validate() error {
	for name, v := range map[string]int{
		"max delegations": l.MaxDelegations, "max templates": l.MaxTemplates, "max artifacts": l.MaxArtifacts,
		"max document bytes": l.MaxDocumentBytes, "template max failures": l.TemplateMaxFailures,
	} {
		if v <= 0 {
			return fmt.Errorf("%s must be positive", name)
		}
	}
	return nil
}

// Store is the database: a repository per aggregate, with health and shutdown.
type Store interface {
	domain.DelegationRepository
	domain.TemplateRepository
	domain.ArtifactRepository
	domain.SettlementRepository
	Ping(ctx context.Context) error
	Close() error
}

type service struct {
	repo                Store
	ark                 ports.Ark
	indexer             ports.Indexer
	emulator            ports.Emulator
	explorer            ports.Explorer
	encryptionKeys      []*btcec.PrivateKey
	onchainPollInterval time.Duration
	maxOnchainFeeRate   float64 // sat/vB
	dust                uint64
	cosigners           []*cosigner
	pollInterval        time.Duration
	renewalTimeout      time.Duration
	collectionWindow    time.Duration
	collectUntil        time.Time
	limits              Limits
	registerMu          sync.Mutex

	network         arklib.Network
	serverPubKey    *btcec.PublicKey
	forfeitPubKey   *btcec.PublicKey
	forfeitPkScript []byte
	emulatorPubKey  *btcec.PublicKey

	batch, direct lane
	renewed       atomic.Uint64
	failed        atomic.Uint64
	started       time.Time
	lastPrune     time.Time

	// shared guards what the scan and the lanes both touch
	shared       sync.Mutex
	consumed     map[string]time.Time // coins spent by a renewal, until the indexer says so
	unsaved      []settlement         // pending offchain txs whose record failed
	onchainCache map[string]onchainSnapshot
	onchainDrops uint64
	inFlight     map[int64]bool // delegations a lane is working on

	// the scan alone
	held         map[string]bool      // coins of the daemon's settlements that may still land, as of the scan
	refusedSince map[string]time.Time // pending txs arkd refuses, since the first refusal
	watched      map[int64]*watched   // nil for a delegation of another key
	sub          *subscription
	sampled      map[int64]bool // inFlight as the scan began

	// mu guards what the last completed scan saw
	mu        sync.Mutex
	lastScan  time.Time
	holdings  map[int64]Holdings
	unwatched map[int64]string

	wg      sync.WaitGroup
	stop    context.CancelFunc
	stopped chan struct{}
	wake    chan struct{}
}

type cosigner struct {
	key    *btcec.PrivateKey
	pubKey string
}

type watched struct {
	tmpl       *template.Template
	delegation domain.Delegation
	cosigner   *cosigner
	instance   *template.Instance
}

type renewalInput struct {
	coin    coin
	onchain bool
	watched *watched
	due     time.Time
	leaf    *psbt.TaprootTapLeafScript
	prevOut *wire.TxOut
}

func NewServiceWithKeys(
	ctx context.Context,
	repo Store,
	ark ports.Ark,
	indexerSvc ports.Indexer,
	emulator ports.Emulator,
	explorer ports.Explorer,
	onchainPollInterval time.Duration,
	maxOnchainFeeRate float64,
	encryptionKeys []*btcec.PrivateKey,
	keys []*btcec.PrivateKey,
	pollInterval, renewalTimeout, collectionWindow time.Duration,
	limits Limits,
) (Service, error) {
	if onchainPollInterval <= 0 {
		return nil, fmt.Errorf("onchain poll interval must be positive")
	}
	cosigners, err := newCosigners(keys)
	if err != nil {
		return nil, err
	}
	if collectionWindow < 0 {
		return nil, fmt.Errorf("collection window must not be negative")
	}
	if pollInterval <= 0 || renewalTimeout <= 0 {
		return nil, fmt.Errorf("poll interval and renewal timeout must be positive")
	}
	if err := limits.validate(); err != nil {
		return nil, err
	}
	arkInfo, err := ark.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("arkd info: %w", err)
	}
	emuInfo, err := emulator.GetInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("emulator info: %w", err)
	}
	serverPubKey, err := PubKeyFromHex(arkInfo.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("arkd signer pubkey: %w", err)
	}
	forfeitPubKey, err := PubKeyFromHex(arkInfo.ForfeitPubKey)
	if err != nil {
		return nil, fmt.Errorf("arkd forfeit pubkey: %w", err)
	}
	emuPubKey, err := PubKeyFromHex(emuInfo.SignerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("emulator pubkey: %w", err)
	}
	network, err := networkFromName(arkInfo.Network)
	if err != nil {
		return nil, err
	}
	forfeitAddr, err := address.DecodeAddress(arkInfo.ForfeitAddress, nil)
	if err != nil {
		return nil, fmt.Errorf("arkd forfeit address: %w", err)
	}
	forfeitPkScript, err := txscript.PayToAddrScript(forfeitAddr)
	if err != nil {
		return nil, err
	}

	// the indexer may still list a coin a renewal spent before a restart
	consumed := map[string]time.Time{}
	last, err := repo.LastRenewals(ctx)
	if err != nil {
		return nil, fmt.Errorf("last renewals: %w", err)
	}
	for _, ren := range last {
		if ren.Success {
			for _, op := range ren.Outpoints {
				consumed[op] = time.Now()
			}
		}
	}

	return &service{
		repo:                repo,
		ark:                 ark,
		indexer:             indexerSvc,
		emulator:            emulator,
		explorer:            explorer,
		encryptionKeys:      slices.Clone(encryptionKeys),
		onchainPollInterval: onchainPollInterval,
		maxOnchainFeeRate:   maxOnchainFeeRate,
		dust:                arkInfo.Dust,
		cosigners:           cosigners,
		pollInterval:        pollInterval,
		renewalTimeout:      renewalTimeout,
		collectionWindow:    collectionWindow,
		limits:              limits,
		network:             network,
		serverPubKey:        serverPubKey,
		forfeitPubKey:       forfeitPubKey,
		forfeitPkScript:     forfeitPkScript,
		emulatorPubKey:      emuPubKey,
		watched:             map[int64]*watched{},
		consumed:            consumed,
		inFlight:            map[int64]bool{},
		onchainCache:        map[string]onchainSnapshot{},
		refusedSince:        map[string]time.Time{},
		started:             time.Now(),
		wake:                make(chan struct{}, 1),
	}, nil
}

func newCosigners(keys []*btcec.PrivateKey) ([]*cosigner, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one tree cosigner key is required")
	}
	if len(keys) > maxSignerKeys {
		return nil, fmt.Errorf("at most %d tree cosigner keys are supported", maxSignerKeys)
	}
	cosigners := make([]*cosigner, len(keys))
	seen := make(map[string]struct{}, len(keys))
	for i, key := range keys {
		if key == nil {
			return nil, fmt.Errorf("tree cosigner key %d is nil", i)
		}
		pubKey := tree.NewTreeSignerSession(key).GetPublicKey()
		if _, ok := seen[pubKey]; ok {
			return nil, fmt.Errorf("tree cosigner keys contain a duplicate key")
		}
		seen[pubKey] = struct{}{}
		cosigners[i] = &cosigner{key: key, pubKey: pubKey}
	}
	return cosigners, nil
}

func (s *service) Info() Info {
	var encryptionPubKey string
	if len(s.encryptionKeys) > 0 {
		encryptionPubKey = hex.EncodeToString(s.encryptionKeys[0].PubKey().SerializeCompressed())
	}
	return Info{
		EncryptionPubKey: encryptionPubKey,
		Network:          s.network.Name,
		DelegatePubKey:   s.cosigners[0].pubKey,
		ServerPubKey:     hex.EncodeToString(s.serverPubKey.SerializeCompressed()),
		EmulatorPubKey:   hex.EncodeToString(s.emulatorPubKey.SerializeCompressed()),
	}
}

func (s *service) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	s.stopped = make(chan struct{})
	go func() {
		defer close(s.stopped)
		timer := time.NewTimer(s.pollInterval)
		defer timer.Stop()
		for {
			s.scan(ctx)
			scanned := time.Now()
			timer.Reset(s.nextScanDelay(scanned))
			select {
			case <-ctx.Done():
			case <-timer.C:
				continue
			case <-s.wake:
				select {
				case <-ctx.Done():
				case <-time.After(minScanGap - time.Since(scanned)):
					continue
				}
			}
			s.wg.Wait()
			return
		}
	}()
}

func (s *service) Stop() {
	if s.stop != nil {
		s.stop()
		<-s.stopped
	}
	if err := s.repo.Close(); err != nil {
		log.WithError(err).Error("close repository")
	}
}

func (s *service) RegisterDelegation(
	ctx context.Context, templateID string, variables map[string]string, expiresAt *time.Time,
) (*domain.Delegation, error) {
	fingerprint := domain.Fingerprint(templateID, variables, nil)
	// an active watch wins: its stored expiry is kept
	if found, err := s.existing(ctx, fingerprint); err != nil || found != nil {
		return found, err
	}
	if now := time.Now(); expiresAt != nil && (!expiresAt.After(now) || expiresAt.Before(now.Add(s.limits.MinWatchExpiry))) {
		return nil, fmt.Errorf("%w: expires_at must be at least %s ahead", ErrInvalidArgs, s.limits.MinWatchExpiry)
	}
	tmpl, inst, err := s.prepare(ctx, templateID, variables)
	if err != nil {
		return nil, err
	}
	slots, tapKeys, err := bindSlots(tmpl, inst, nil)
	if err != nil {
		return nil, err
	}
	addr, err := s.watchAddress(slots[0].Onchain, tapKeys[0])
	if err != nil {
		return nil, err
	}
	d, err := s.create(ctx, domain.Delegation{
		Fingerprint: fingerprint, Address: addr, TemplateID: templateID, Variables: variables,
		ExpiresAt: expiresAt, DelegatePubKey: s.cosigners[0].pubKey, Slots: slots,
	}, false)
	if err == nil && tmpl.Type() != template.Intent {
		s.wakeScan() // the coin may be there already
	}
	return d, err
}

func (s *service) RenewableAt(ctx context.Context, d *domain.Delegation, vtxos []clientlib.Vtxo) ([]time.Time, error) {
	_, inst, err := s.instantiate(ctx, d)
	if err != nil {
		return nil, err
	}
	tip := sync.OnceValues(s.explorer.ChainTip)
	due := make([]time.Time, len(vtxos))
	for i, v := range vtxos {
		due[i] = dueTime(inst, vtxoCoin(0, v), tip)
	}
	return due, nil
}

// CancelDelegation stops every active watch of address: templates may share one.
func (s *service) CancelDelegation(ctx context.Context, address string) error {
	for {
		d, err := s.repo.Get(ctx, address)
		if err != nil || d.Status != domain.DelegationStatusActive {
			return err
		}
		if err := s.cancel(ctx, d); err != nil {
			return err
		}
	}
}

func (s *service) CancelDelegationByID(ctx context.Context, id int64) error {
	d, err := s.repo.GetByID(ctx, id)
	if err != nil || d.Status != domain.DelegationStatusActive {
		return err
	}
	return s.cancel(ctx, d)
}

func (s *service) cancel(ctx context.Context, d *domain.Delegation) error {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	return s.repo.SetStatus(ctx, d.ID, domain.DelegationStatusCancelled)
}

func (s *service) ResumeDelegation(ctx context.Context, id int64) error {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	return s.repo.Resume(ctx, id)
}

func (s *service) GetDelegation(ctx context.Context, address string) (*domain.Delegation, error) {
	return s.repo.Get(ctx, address)
}

func (s *service) GetDelegationByID(ctx context.Context, id int64) (*domain.Delegation, error) {
	return s.repo.GetByID(ctx, id)
}

func (s *service) ListDelegations(ctx context.Context, status string, cursor int64, limit int) ([]domain.Delegation, error) {
	return s.repo.ListPage(ctx, status, cursor, limit)
}

func (s *service) CountActive(ctx context.Context) (int64, error) {
	return s.repo.CountActive(ctx)
}

func (s *service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		LastScan:      s.lastScan,
		RenewingVtxos: int(s.batch.busy.Load() + s.direct.busy.Load()),
		PollInterval:  s.pollInterval,
		Renewed:       s.renewed.Load(),
		Failed:        s.failed.Load(),
		Holdings:      maps.Clone(s.holdings),
		Unwatched:     maps.Clone(s.unwatched),
	}
}

func (s *service) IntentFees(ctx context.Context) (arkfee.Config, error) {
	info, err := s.ark.GetInfo(ctx)
	if err != nil {
		return arkfee.Config{}, fmt.Errorf("arkd info: %w", err)
	}
	return info.Fees.IntentFees, nil
}

func (s *service) LastRenewals(ctx context.Context) (map[int64]domain.Renewal, error) {
	return s.repo.LastRenewals(ctx)
}

func (s *service) ListRenewals(ctx context.Context, d *domain.Delegation) ([]domain.Renewal, error) {
	return s.repo.ListRenewals(ctx, d.ID, 50)
}

func (s *service) Vtxos(ctx context.Context, d *domain.Delegation) ([]clientlib.Vtxo, error) {
	var scripts []string
	for _, sl := range d.Slots {
		if !sl.Onchain && !slices.Contains(scripts, sl.Script) {
			scripts = append(scripts, sl.Script)
		}
	}
	byScript, err := s.spendableVtxos(ctx, scripts)
	if err != nil {
		return nil, err
	}
	var out []clientlib.Vtxo
	seen := map[string]bool{}
	for _, sl := range d.Slots {
		coins := byScript[sl.Script]
		if sl.Onchain {
			utxos, err := s.onchainUtxos(sl)
			if err != nil {
				return nil, err
			}
			for _, u := range utxos {
				coins = append(coins, clientlib.Vtxo{Outpoint: clientlib.Outpoint{Txid: u.Txid, VOut: u.Vout}, Amount: u.Amount, Script: u.Script})
			}
		}
		for _, v := range coins {
			op := v.Outpoint.String()
			if !seen[op] && !v.Spent && (sl.Outpoint == "" || sl.Outpoint == op) {
				seen[op] = true
				out = append(out, v)
			}
		}
	}
	return out, nil
}

func (s *service) Health(ctx context.Context) map[string]error {
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, arkErr := s.ark.GetInfo(healthCtx)
	_, emuErr := s.emulator.GetInfo(healthCtx)
	return map[string]error{
		"database": s.repo.Ping(healthCtx),
		"ark":      arkErr,
		"emulator": emuErr,
		"scanner":  s.scannerHealth(time.Now()),
	}
}

// scannerHealth fails when scans stopped: a wedged loop looks alive otherwise.
func (s *service) scannerHealth(now time.Time) error {
	s.mu.Lock()
	last := s.lastScan
	s.mu.Unlock()
	if last.IsZero() {
		last = s.started
	}
	if grace := max(3*s.pollInterval, time.Minute); now.Sub(last) > grace {
		return fmt.Errorf("no scan for %s", now.Sub(last).Round(time.Second))
	}
	return nil
}

// prepare instantiates a one-input template for a watch under the current cosigner key.
func (s *service) prepare(ctx context.Context, templateID string, variables map[string]string) (*template.Template, *template.Instance, error) {
	tmpl, err := s.parseTemplate(ctx, templateID)
	if err != nil {
		return nil, nil, err
	}
	if len(tmpl.Inputs()) != 1 {
		return nil, nil, fmt.Errorf("%w: a watch binds one input", ErrInvalidArgs)
	}
	inst, err := s.instanceFor(ctx, tmpl, s.cosigners[0], variables, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	return tmpl, inst, nil
}

func (s *service) instantiate(ctx context.Context, d *domain.Delegation) (*template.Template, *template.Instance, error) {
	c := s.cosignerFor(d.DelegatePubKey)
	if c == nil {
		return nil, nil, errOtherKey
	}
	tmpl, err := s.parseTemplate(ctx, d.TemplateID)
	if err != nil {
		return nil, nil, err
	}
	if len(d.Slots) != len(tmpl.Inputs()) {
		return nil, nil, fmt.Errorf("delegation has %d slots, the template %d inputs", len(d.Slots), len(tmpl.Inputs()))
	}
	var bound []*wire.OutPoint
	for _, slot := range d.Slots {
		if slot.Outpoint == "" {
			continue
		}
		op, err := wire.NewOutPointFromString(slot.Outpoint)
		if err != nil {
			return nil, nil, err
		}
		bound = append(bound, op)
	}
	inst, err := s.newInstance(ctx, tmpl, c, d.Variables, bound, nil)
	if err != nil {
		return nil, nil, err
	}
	for i, slot := range d.Slots {
		if !slices.Equal(inst.Tapscripts(i), slot.Tapscripts) {
			return nil, nil, errors.New("tree changed since registration: the server or emulator key rotated")
		}
	}
	if err := s.checkDelegatePolicy(ctx, d.TemplateID, inst, len(d.Slots), c); err != nil {
		return nil, nil, err
	}
	return tmpl, inst, nil
}

func (s *service) instanceFor(
	ctx context.Context, tmpl *template.Template, c *cosigner, variables map[string]string, bound []*wire.OutPoint, known map[string]*wire.MsgTx,
) (*template.Instance, error) {
	inst, err := s.newInstance(ctx, tmpl, c, variables, bound, known)
	if err != nil {
		return nil, err
	}
	if err := s.checkDelegatePolicy(ctx, tmpl.ID(), inst, len(tmpl.Inputs()), c); err != nil {
		return nil, err
	}
	return inst, nil
}

// newInstance fetches each bound source once, known first; a watch has no coins, so what fails comes from the request.
func (s *service) newInstance(
	ctx context.Context, tmpl *template.Template, c *cosigner, variables map[string]string, bound []*wire.OutPoint, known map[string]*wire.MsgTx,
) (*template.Instance, error) {
	vars := make(map[string][]byte, len(variables))
	for n, v := range variables {
		raw, err := hex.DecodeString(v)
		if err != nil || hex.EncodeToString(raw) != v {
			return nil, fmt.Errorf("%w: %s is not lower-case hex", ErrInvalidArgs, n)
		}
		vars[n] = raw
	}
	var sources []*template.Source
	fetched := map[string]*wire.MsgTx{}
	maps.Copy(fetched, known)
	for _, op := range bound {
		txid := op.Hash.String()
		tx := fetched[txid]
		if tx == nil {
			var err error
			if tx, err = s.sourceTx(ctx, txid); err != nil {
				return nil, fmt.Errorf("source %s: %w", op, err)
			}
			fetched[txid] = tx
		}
		if int(op.Index) >= len(tx.TxOut) {
			return nil, fmt.Errorf("%w: source %s: no such output", ErrIneligible, op)
		}
		sources = append(sources, &template.Source{Outpoint: *op, Tx: tx, Amount: uint64(tx.TxOut[op.Index].Value)})
	}
	inst, err := tmpl.Instantiate(ctx, template.Context{
		Keys: template.Keys{Server: s.serverPubKey, Emulator: s.emulatorPubKey, Delegate: c.key.PubKey()}, Variables: vars, Decrypt: s.decrypter(), Sources: sources,
	})
	if err != nil {
		if bound == nil && !errors.Is(err, template.ErrUnsupported) {
			return nil, fmt.Errorf("%w: %w", ErrInvalidArgs, err)
		}
		return nil, moduleError(err, ErrIneligible)
	}
	return inst, nil
}

// watch is nil when d was registered under another key.
func (s *service) watch(ctx context.Context, d *domain.Delegation) (*watched, error) {
	tmpl, inst, err := s.instantiate(ctx, d)
	if errors.Is(err, errOtherKey) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &watched{tmpl: tmpl, delegation: *d, cosigner: s.cosignerFor(d.DelegatePubKey), instance: inst}, nil
}

func (s *service) decrypter() func(ciphertext []byte) ([]byte, error) {
	if len(s.encryptionKeys) == 0 {
		return nil
	}
	return func(ciphertext []byte) ([]byte, error) { return ecies.DecryptAny(s.encryptionKeys, ciphertext) }
}

func (s *service) cosignerFor(pubKeyHex string) *cosigner {
	for _, c := range s.cosigners {
		if c.pubKey == pubKeyHex {
			return c
		}
	}
	return nil
}

// existing is the active delegation of fingerprint; an operator cancel refuses it until resumed.
func (s *service) existing(ctx context.Context, fingerprint string) (*domain.Delegation, error) {
	d, err := s.repo.GetByFingerprint(ctx, fingerprint)
	switch {
	case errors.Is(err, domain.ErrDelegationNotFound):
		return nil, nil
	case err != nil:
		return nil, err
	case d.Status == domain.DelegationStatusCancelled:
		return nil, domain.ErrBlocked
	case d.Status != domain.DelegationStatusActive:
		return nil, nil
	}
	return d, nil
}

// unbound fails when an active instance other than fingerprint binds outpoint.
func (s *service) unbound(ctx context.Context, fingerprint, outpoint string) error {
	if outpoint == "" {
		return nil
	}
	other, err := s.repo.GetActiveByOutpoint(ctx, outpoint)
	if errors.Is(err, domain.ErrDelegationNotFound) || (err == nil && other.Fingerprint == fingerprint) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %s is bound by delegation %d", domain.ErrDelegationAlreadyExists, outpoint, other.ID)
}

// create caps registrations, not successors of the daemon's own transactions.
func (s *service) create(ctx context.Context, d domain.Delegation, own bool) (*domain.Delegation, error) {
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	if _, err := s.existing(ctx, d.Fingerprint); err != nil {
		return nil, err
	}
	for _, slot := range d.Slots {
		if err := s.unbound(ctx, d.Fingerprint, slot.Outpoint); err != nil {
			return nil, err
		}
	}
	limit := s.limits.MaxDelegations
	if own {
		limit = 0
	}
	created, err := s.repo.Create(ctx, d, limit)
	if errors.Is(err, domain.ErrCapReached) {
		return nil, ErrFull
	}
	if err != nil {
		return nil, err
	}
	log.WithFields(log.Fields{
		"id": created.ID, "parent": created.ParentID, "address": created.Address, "template": created.TemplateID,
	}).Info("delegation registered")
	return created, nil
}

func (s *service) watchAddress(onchain bool, tapKey *btcec.PublicKey) (string, error) {
	if onchain {
		return onchainAddress(tapKey, s.network)
	}
	return (&arklib.Address{HRP: s.network.Addr, Signer: s.serverPubKey, VtxoTapKey: tapKey}).EncodeV0()
}

// spendableVtxos queries the indexer a few chunks of 100 scripts at a time.
func (s *service) spendableVtxos(ctx context.Context, scripts []string) (map[string][]clientlib.Vtxo, error) {
	const chunk = 100
	var mu sync.Mutex
	out := make(map[string][]clientlib.Vtxo)
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for start := 0; start < len(scripts); start += chunk {
		batch := scripts[start:min(start+chunk, len(scripts))]
		g.Go(func() error {
			// arkd answers an unpaged request in full
			for page := int32(0); ; {
				opts := []clientlib.GetVtxosOption{clientlib.WithScripts(batch), clientlib.WithSpendableOnly()}
				if page > 0 {
					opts = append(opts, clientlib.WithVtxosPage(&clientlib.PageRequest{Index: page}))
				}
				resp, err := s.indexer.GetVtxos(ctx, opts...)
				if err != nil {
					return err
				}
				mu.Lock()
				for _, v := range resp.Vtxos {
					out[v.Script] = append(out[v.Script], v)
				}
				mu.Unlock()
				if resp.Page == nil || resp.Page.Next <= resp.Page.Current {
					return nil
				}
				page = resp.Page.Next
			}
		})
	}
	return out, g.Wait()
}

func (s *service) scan(ctx context.Context) {
	s.collectUntil = time.Time{}
	s.sampleLanes()
	now := time.Now()
	s.prune(ctx, now)
	if err := s.finishSettlements(ctx); err != nil {
		log.WithError(err).Error("finish settlements")
		return
	}
	delegations, err := s.repo.List(ctx, domain.DelegationStatusActive)
	if err != nil {
		log.WithError(err).Error("list active delegations")
		return
	}
	active, err := s.activeTemplates(ctx)
	if err != nil {
		log.WithError(err).Error("list active templates")
		return
	}
	holdings, unwatched, inputs, err := s.discover(ctx, delegations, active, now)
	if err != nil {
		log.WithError(err).Error("discover coins")
		return
	}
	var lateVtxos int
	for _, h := range holdings {
		lateVtxos += h.Late
	}
	if lateVtxos > 0 {
		log.WithField("count", lateVtxos).Warn("late vtxos: arkd rounds may be stalled")
	}
	s.mu.Lock()
	s.lastScan, s.holdings, s.unwatched = now, holdings, unwatched
	s.mu.Unlock()
	s.syncSubscription(ctx, s.wakeScripts())
	var batch, direct []renewalInput
	for _, in := range inputs {
		if s.laneOf(in) == &s.direct {
			direct = append(direct, in)
		} else {
			batch = append(batch, in)
		}
	}
	// a transaction of its own gains nothing from waiting for others
	s.dispatch(&s.direct, direct)
	// one cosigner key means one batch session at a time
	if s.batch.wasBusy {
		return
	}
	s.collectUntil = s.collectionDeadline(batch, time.Now())
	if s.collectUntil.IsZero() {
		s.dispatch(&s.batch, batch)
	}
}

func (s *service) prune(ctx context.Context, now time.Time) {
	if s.lastPrune.IsZero() || now.Sub(s.lastPrune) >= renewalsPruneInterval {
		if err := s.repo.PruneRenewals(ctx, now.Add(-renewalsRetention)); err != nil {
			log.WithError(err).Warn("prune renewals")
		} else {
			s.lastPrune = now
		}
	}
	expired, err := s.repo.Expire(ctx, now)
	if err != nil {
		log.WithError(err).Warn("expire watches")
	}
	if expired > 0 {
		log.WithField("count", expired).Info("watches expired")
	}
}

func (s *service) activeTemplates(ctx context.Context) (map[string]struct{}, error) {
	templates, err := s.repo.ListTemplates(ctx, domain.TemplateStatusActive)
	if err != nil {
		return nil, err
	}
	active := make(map[string]struct{}, len(templates))
	for _, t := range templates {
		active[t.ID] = struct{}{}
	}
	return active, nil
}

func (s *service) renewAndRecord(ctx context.Context, inputs []renewalInput) {
	log.WithField("count", len(inputs)).Info("renewing vtxos")
	renewCtx, cancel := context.WithTimeout(ctx, s.renewalTimeout)
	defer cancel()
	results := s.renew(renewCtx, inputs)
	ctx = context.WithoutCancel(ctx)
	s.recordRenewals(ctx, inputs, results)
	s.recordTemplateOutcomes(ctx, results)
}

// recordRenewals reports a vtxo failing the same way every poll once.
func (s *service) recordRenewals(ctx context.Context, inputs []renewalInput, results []renewalResult) {
	l := &s.batch
	if len(inputs) > 0 {
		l = s.laneOf(inputs[0])
	}
	due := make(map[string]string, len(inputs))
	for _, in := range inputs {
		if msg, ok := l.lastFailure[in.coin.Outpoint.String()]; ok {
			due[in.coin.Outpoint.String()] = msg
		}
	}
	l.lastFailure = due

	type key struct {
		delegation int64
		commitment string
		err        string
	}
	byDelegation := map[key]*domain.Renewal{}
	var order []key
	for _, res := range results {
		errMsg := ""
		if res.err != nil {
			errMsg = res.err.Error()
		}
		for _, in := range res.inputs {
			outpoint := in.coin.Outpoint.String()
			if errMsg != "" && l.lastFailure[outpoint] == errMsg {
				continue
			}
			if delete(l.lastFailure, outpoint); errMsg != "" {
				l.lastFailure[outpoint] = errMsg
			}
			k := key{in.watched.delegation.ID, res.commitmentTxid, errMsg}
			ren, ok := byDelegation[k]
			if !ok {
				ren = &domain.Renewal{
					DelegationID: in.watched.delegation.ID, CommitmentTxid: res.commitmentTxid,
					Success: res.err == nil, Error: errMsg,
				}
				byDelegation[k] = ren
				order = append(order, k)
			}
			ren.Outpoints = append(ren.Outpoints, outpoint)
		}
	}
	for _, k := range order {
		ren := byDelegation[k]
		logger := log.WithFields(log.Fields{"delegation": ren.DelegationID, "vtxos": ren.Outpoints})
		if ren.Success {
			s.consume(ren.Outpoints...)
			s.renewed.Add(uint64(len(ren.Outpoints)))
			logger.WithField("commitment_txid", ren.CommitmentTxid).Info("vtxos renewed")
		} else {
			s.failed.Add(uint64(len(ren.Outpoints)))
			logger.WithField("error", ren.Error).Error("renewal failed")
		}
		if err := s.repo.RecordRenewal(ctx, *ren); err != nil {
			logger.WithError(err).Error("record renewal")
		}
	}
}

// a template whose intents keep being rejected must not spam arkd
func (s *service) recordTemplateOutcomes(ctx context.Context, results []renewalResult) {
	for id, t := range templateOutcomes(results) {
		if !t.accepted && t.rejected == 0 {
			continue
		}
		// one refused vtxo must not halt every delegation sharing a trusted template
		if tmpl, err := s.repo.GetTemplate(ctx, id); err == nil && tmpl.Trusted {
			if t.rejected > 0 {
				log.WithFields(log.Fields{"template": id, "rejected": t.rejected}).Warn("intents rejected for a trusted template")
			}
			continue
		}
		failures, status, err := s.repo.RecordTemplateOutcome(ctx, id, t.accepted, s.limits.TemplateMaxFailures)
		if err != nil {
			log.WithError(err).WithField("template", id).Error("record template outcome")
			continue
		}
		if status == domain.TemplateStatusDisabled && !t.accepted {
			log.WithFields(log.Fields{"template": id, "failures": failures}).Warn("template disabled: every intent rejected for too many cycles")
		}
	}
}

// a cycle with neither accepted intents nor refused vtxos says nothing about a template
type tally struct {
	accepted bool
	rejected int
}

func templateOutcomes(results []renewalResult) map[string]tally {
	out := map[string]tally{}
	for _, res := range results {
		for _, in := range res.inputs {
			id := in.watched.delegation.TemplateID
			t := out[id]
			switch {
			case res.err == nil || res.registered:
				t.accepted = true
			case errors.Is(res.err, errIntentRejected):
				t.rejected++
			}
			out[id] = t
		}
	}
	return out
}

// late means less than a quarter of the time between renewable and expiry is left, or none: a locktime past expiry.
func late(expiry, due, now time.Time) bool {
	room := expiry.Sub(due)
	return !expiry.IsZero() && room != 0 && (room < 0 || expiry.Sub(now) < room/4)
}

// outpoints is nil for a watch
func bindSlots(tmpl *template.Template, inst *template.Instance, outpoints []string) ([]domain.SlotBinding, []*btcec.PublicKey, error) {
	inputs := tmpl.Inputs()
	slots := make([]domain.SlotBinding, len(inputs))
	tapKeys := make([]*btcec.PublicKey, len(inputs))
	for i, in := range inputs {
		tapscripts := inst.Tapscripts(i)
		pkScript, tapKey, err := pkScriptOf(tapscripts)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: slot %s: %v", ErrInvalidArgs, in.Name, err)
		}
		slots[i] = domain.SlotBinding{
			Name: in.Name, Onchain: in.Onchain, Tapscripts: tapscripts, Script: hex.EncodeToString(pkScript),
		}
		if outpoints != nil {
			slots[i].Outpoint = outpoints[i]
		}
		tapKeys[i] = tapKey
	}
	return slots, tapKeys, nil
}

// pkScriptOf uses ark's unspendable internal key.
func pkScriptOf(tapscripts []string) ([]byte, *btcec.PublicKey, error) {
	if len(tapscripts) == 0 {
		return nil, nil, errors.New("empty tapscript tree")
	}
	leaves := make([]txscript.TapLeaf, len(tapscripts))
	for i, ts := range tapscripts {
		raw, err := hex.DecodeString(ts)
		if err != nil {
			return nil, nil, fmt.Errorf("tapscript %d: %w", i, err)
		}
		leaves[i] = txscript.NewBaseTapLeaf(raw)
	}
	root := txscript.AssembleTaprootScriptTree(leaves...).RootNode.TapHash()
	tapKey := txscript.ComputeTaprootOutputKey(script.UnspendableKey(), root[:])
	pkScript, err := script.P2TRScript(tapKey)
	return pkScript, tapKey, err
}

func onchainAddress(tapKey *btcec.PublicKey, network arklib.Network) (string, error) {
	var params *chaincfg.Params
	switch network.Name {
	case arklib.Bitcoin.Name:
		params = &chaincfg.MainNetParams
	case arklib.BitcoinTestNet.Name:
		params = &chaincfg.TestNet3Params
	case arklib.BitcoinTestNet4.Name:
		params = &chaincfg.TestNet4Params
	case arklib.BitcoinSigNet.Name:
		params = &chaincfg.SigNetParams
	case arklib.BitcoinMutinyNet.Name:
		params = &arklib.MutinyNetSigNetParams
	case arklib.BitcoinRegTest.Name:
		params = &chaincfg.RegressionNetParams
	default:
		return "", fmt.Errorf("unknown network %q", network.Name)
	}
	addr, err := address.NewAddressTaproot(schnorr.SerializePubKey(tapKey), params)
	if err != nil {
		return "", err
	}
	return addr.EncodeAddress(), nil
}

func PubKeyFromHex(pubkey string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(pubkey)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(raw)
}

func networkFromName(name string) (arklib.Network, error) {
	for _, n := range []arklib.Network{
		arklib.Bitcoin, arklib.BitcoinTestNet, arklib.BitcoinTestNet4,
		arklib.BitcoinSigNet, arklib.BitcoinMutinyNet, arklib.BitcoinRegTest,
	} {
		if n.Name == name {
			return n, nil
		}
	}
	return arklib.Network{}, fmt.Errorf("unknown network %q", name)
}

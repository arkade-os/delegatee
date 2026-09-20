// Package application renews VTXOs locked by the delegate covenant: near
// expiry it registers a self-send intent in a batch and cosigns the tree.
package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

var (
	ErrInvalidScript = errors.New("invalid vtxo script")
	// ErrInvalidSignature is a revocation the owner did not sign.
	ErrInvalidSignature = errors.New("invalid revocation")
	// ErrFull protects the delegations already registered: every active one
	// costs an indexer lookup per poll, so an unbounded table delays renewals.
	ErrFull = errors.New("this delegatee accepts no more delegations")
)

// MaxVtxosPerIntent is the emulator's current covenant-safe ceiling.
const MaxVtxosPerIntent = 16

const maxSignerKeys = 16

// a vtxo script is a handful of small leaves; anything bigger is not one
const (
	maxTapscripts   = 32
	maxTapscriptLen = 2048 // hex chars
)

// renewalsRetention bounds the history; the latest renewal of a delegation is always kept.
const renewalsRetention = 30 * 24 * time.Hour
const renewalsPruneInterval = time.Hour

// Info is what a wallet needs to build a delegate address for one set of params.
type Info struct {
	Network               string
	DelegatePubKey        string
	ServerPubKey          string
	EmulatorPubKey        string
	EmulatorTweakedPubKey string
	ArkadeScript          string
	DelegateTapscript     string
	Params                domain.Params
}

// Holdings is what the last scan saw at one delegation.
type Holdings struct {
	Vtxos      int
	Amount     uint64
	NextExpiry time.Time // zero without vtxos
	NextDue    time.Time // when the first of them becomes renewable
	// Late counts vtxos renewable for a while and still not renewed: past
	// the last quarter of the time between renewable and expiry.
	Late       int
	LateAmount uint64
}

// Status is the scanner's state, for operators. It never depends on arkd:
// it must stay visible during an outage.
type Status struct {
	LastScan      time.Time // zero until the first scan completes
	RenewingVtxos int       // vtxos in the batch session in flight, if any
	PollInterval  time.Duration
	// Renewed and Failed count vtxo renewals since the process started.
	Renewed, Failed uint64
	// Holdings by delegation id, for active delegations this keyring can renew.
	// An active delegation missing here was registered under another key.
	Holdings map[int64]Holdings
}

type Service interface {
	Start()
	Stop()
	// Info and RegisterDelegation default a zero renewal window to DefaultRenewalWindow.
	Info(params domain.Params) (Info, error)
	RegisterDelegation(ctx context.Context, tapscripts []string, params domain.Params) (*domain.Delegation, error)
	CancelDelegation(ctx context.Context, address string) error
	// RevokeDelegation is CancelDelegation for the owner, who proves it with an exit key.
	RevokeDelegation(ctx context.Context, address, pubKeyHex, signatureHex string, timestamp int64) error
	GetDelegation(ctx context.Context, address string) (*domain.Delegation, error)
	ListDelegations(ctx context.Context) ([]domain.Delegation, error)
	ListRenewals(ctx context.Context, d *domain.Delegation) ([]domain.Renewal, error)
	LastRenewals(ctx context.Context) (map[int64]domain.Renewal, error)
	Status() Status
	CountActive(ctx context.Context) (int64, error)
	// IntentFees is what arkd charges right now.
	IntentFees(ctx context.Context) (arkfee.Config, error)
	Vtxos(ctx context.Context, d *domain.Delegation) ([]types.Vtxo, error)
	// DueAt is when one of the delegation's vtxos becomes renewable.
	DueAt(d *domain.Delegation, v types.Vtxo) time.Time
	Health(ctx context.Context) map[string]error
}

type service struct {
	repo              domain.DelegationRepository
	ark               client.Client
	indexer           indexer.Indexer
	emulator          emulatorclient.TransportClient
	key               *btcec.PrivateKey
	cosigners         []*cosigner
	pollInterval      time.Duration
	renewalTimeout    time.Duration
	maxVtxosPerIntent int
	maxDelegations    int
	registerMu        sync.Mutex

	network           arklib.Network
	serverPubKey      *btcec.PublicKey
	forfeitPubKey     *btcec.PublicKey
	forfeitPkScript   []byte
	emulatorPubKey    *btcec.PublicKey
	delegatePubKeyHex string

	renewing atomic.Int64 // vtxos in the batch session in flight
	renewed  atomic.Uint64
	failed   atomic.Uint64
	started  time.Time
	// lastFailure is the last error per outpoint, only touched by the one
	// renewal goroutine. Lost on restart: the failure is then reported again.
	lastFailure map[string]string
	lastPrune   time.Time

	// watched caches what scan derives from a delegation (covenant, leaf
	// proof, script): it never changes, and deriving it is most of a scan's
	// cpu. nil for a delegation of another key. Only touched by scan.
	watched map[int64]*watched

	// mu guards what the last completed scan saw, for Status
	mu       sync.Mutex
	lastScan time.Time
	holdings map[int64]Holdings

	wg      sync.WaitGroup
	stop    context.CancelFunc
	stopped chan struct{}
}

type cosigner struct {
	key    *btcec.PrivateKey
	pubKey string
}

// watched is an active delegation this keyring can renew, ready to build intents.
type watched struct {
	delegation domain.Delegation
	cosigner   *cosigner
	pkScript   []byte
	script     string // hex pkScript, as the indexer keys vtxos
	leaf       *psbt.TaprootTapLeafScript
	covenant   *covenant
}

type renewalInput struct {
	vtxo         types.Vtxo
	delegation   *domain.Delegation
	cosigner     *cosigner
	pkScript     []byte
	leaf         *psbt.TaprootTapLeafScript
	arkadeScript []byte
	output       *wire.TxOut // set by renew once the fee is known
}

// covenant is the delegate leaf for one set of params.
type covenant struct {
	arkadeScript []byte
	tweakedKey   *btcec.PublicKey
	tapscript    []byte
}

func NewService(
	ctx context.Context,
	repo domain.DelegationRepository,
	ark client.Client,
	indexerSvc indexer.Indexer,
	emulator emulatorclient.TransportClient,
	key *btcec.PrivateKey,
	pollInterval, renewalTimeout time.Duration,
	maxVtxosPerIntent, maxDelegations int,
) (Service, error) {
	return NewServiceWithKeys(ctx, repo, ark, indexerSvc, emulator, []*btcec.PrivateKey{key}, pollInterval, renewalTimeout, maxVtxosPerIntent, maxDelegations)
}

func NewServiceWithKeys(
	ctx context.Context,
	repo domain.DelegationRepository,
	ark client.Client,
	indexerSvc indexer.Indexer,
	emulator emulatorclient.TransportClient,
	keys []*btcec.PrivateKey,
	pollInterval, renewalTimeout time.Duration,
	maxVtxosPerIntent, maxDelegations int,
) (Service, error) {
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
	if pollInterval <= 0 || renewalTimeout <= 0 {
		return nil, fmt.Errorf("poll interval and renewal timeout must be positive")
	}
	if maxVtxosPerIntent <= 0 || maxVtxosPerIntent > MaxVtxosPerIntent {
		return nil, fmt.Errorf("max vtxos per intent must be between 1 and %d", MaxVtxosPerIntent)
	}
	if maxDelegations <= 0 {
		return nil, fmt.Errorf("max delegations must be positive")
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
	forfeitAddr, err := btcutil.DecodeAddress(arkInfo.ForfeitAddress, nil)
	if err != nil {
		return nil, fmt.Errorf("arkd forfeit address: %w", err)
	}
	forfeitPkScript, err := txscript.PayToAddrScript(forfeitAddr)
	if err != nil {
		return nil, err
	}

	return &service{
		repo:              repo,
		ark:               ark,
		indexer:           indexerSvc,
		emulator:          emulator,
		key:               keys[0],
		cosigners:         cosigners,
		pollInterval:      pollInterval,
		renewalTimeout:    renewalTimeout,
		maxVtxosPerIntent: maxVtxosPerIntent,
		maxDelegations:    maxDelegations,
		network:           network,
		serverPubKey:      serverPubKey,
		forfeitPubKey:     forfeitPubKey,
		forfeitPkScript:   forfeitPkScript,
		emulatorPubKey:    emuPubKey,
		delegatePubKeyHex: cosigners[0].pubKey,
		lastFailure:       map[string]string{},
		watched:           map[int64]*watched{},
		started:           time.Now(),
	}, nil
}

func (s *service) covenantFor(params domain.Params) (*covenant, error) {
	return s.covenantForCosigner(params, s.cosigners[0])
}

func (s *service) covenantForCosigner(params domain.Params, cosigner *cosigner) (*covenant, error) {
	if err := validateParams(params); err != nil {
		return nil, err
	}
	arkadeScript, err := buildArkadeScript(cosigner.pubKey, params)
	if err != nil {
		return nil, err
	}
	tweaked := arkade.ComputeArkadeScriptPublicKey(s.emulatorPubKey, arkade.ArkadeScriptHash(arkadeScript))
	tapscript, err := (&script.MultisigClosure{
		PubKeys: []*btcec.PublicKey{s.serverPubKey, tweaked},
	}).Script()
	if err != nil {
		return nil, err
	}
	return &covenant{arkadeScript: arkadeScript, tweakedKey: tweaked, tapscript: tapscript}, nil
}

func withDefaults(params domain.Params) domain.Params {
	if params.RenewalWindow == 0 {
		params.RenewalWindow = DefaultRenewalWindow
	}
	return params
}

func (s *service) Info(params domain.Params) (Info, error) {
	params = withDefaults(params)
	c, err := s.covenantFor(params)
	if err != nil {
		return Info{}, err
	}
	return Info{
		Network:               s.network.Name,
		DelegatePubKey:        s.delegatePubKeyHex,
		ServerPubKey:          hex.EncodeToString(s.serverPubKey.SerializeCompressed()),
		EmulatorPubKey:        hex.EncodeToString(s.emulatorPubKey.SerializeCompressed()),
		EmulatorTweakedPubKey: hex.EncodeToString(c.tweakedKey.SerializeCompressed()),
		ArkadeScript:          hex.EncodeToString(c.arkadeScript),
		DelegateTapscript:     hex.EncodeToString(c.tapscript),
		Params:                params,
	}, nil
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

func (s *service) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	s.stop = cancel
	s.stopped = make(chan struct{})
	go func() {
		defer close(s.stopped)
		ticker := time.NewTicker(s.pollInterval)
		defer ticker.Stop()
		for {
			s.scan(ctx)
			select {
			case <-ctx.Done():
				s.wg.Wait()
				return
			case <-ticker.C:
			}
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
	ctx context.Context, tapscripts []string, params domain.Params,
) (*domain.Delegation, error) {
	if len(tapscripts) > maxTapscripts {
		return nil, fmt.Errorf("%w: more than %d tapscripts", ErrInvalidScript, maxTapscripts)
	}
	for _, ts := range tapscripts {
		if len(ts) > maxTapscriptLen {
			return nil, fmt.Errorf("%w: tapscript longer than %d bytes", ErrInvalidScript, maxTapscriptLen/2)
		}
	}
	params = withDefaults(params)
	c, err := s.covenantFor(params)
	if err != nil {
		return nil, err
	}
	vtxoScript, err := s.parseScript(tapscripts, c)
	if err != nil {
		return nil, err
	}
	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidScript, err)
	}
	addr, err := (&arklib.Address{
		HRP: s.network.Addr, Signer: s.serverPubKey, VtxoTapKey: tapKey,
	}).EncodeV0()
	if err != nil {
		return nil, err
	}
	s.registerMu.Lock()
	defer s.registerMu.Unlock()
	if active, err := s.repo.CountActive(ctx); err != nil {
		return nil, err
	} else if active >= int64(s.maxDelegations) {
		return nil, ErrFull
	}
	d, err := s.repo.Create(ctx, addr, tapscripts, params)
	if err != nil {
		return nil, err
	}
	log.WithField("address", addr).Info("address registered for delegation")
	return d, nil
}

func (s *service) CancelDelegation(ctx context.Context, address string) error {
	return s.repo.Cancel(ctx, address, domain.DelegationStatusCancelled)
}

func (s *service) GetDelegation(ctx context.Context, address string) (*domain.Delegation, error) {
	return s.repo.Get(ctx, address)
}

func (s *service) ListDelegations(ctx context.Context) ([]domain.Delegation, error) {
	return s.repo.List(ctx, "")
}

func (s *service) CountActive(ctx context.Context) (int64, error) {
	return s.repo.CountActive(ctx)
}

func (s *service) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		LastScan:      s.lastScan,
		RenewingVtxos: int(s.renewing.Load()),
		PollInterval:  s.pollInterval,
		Renewed:       s.renewed.Load(),
		Failed:        s.failed.Load(),
		Holdings:      maps.Clone(s.holdings),
	}
}

func (s *service) IntentFees(ctx context.Context) (arkfee.Config, error) {
	info, err := s.ark.GetInfo(ctx)
	if err != nil {
		return arkfee.Config{}, fmt.Errorf("arkd info: %w", err)
	}
	return info.Fees.IntentFees, nil
}

func (s *service) DueAt(d *domain.Delegation, v types.Vtxo) time.Time {
	return dueAt(v, d.Params)
}

func (s *service) LastRenewals(ctx context.Context) (map[int64]domain.Renewal, error) {
	return s.repo.LastRenewals(ctx)
}

func (s *service) ListRenewals(ctx context.Context, d *domain.Delegation) ([]domain.Renewal, error) {
	return s.repo.ListRenewals(ctx, d.ID, 50)
}

func (s *service) Vtxos(ctx context.Context, d *domain.Delegation) ([]types.Vtxo, error) {
	pkScript, _, err := s.scriptOf(d)
	if err != nil {
		return nil, err
	}
	script := hex.EncodeToString(pkScript)
	byScript, err := s.spendableVtxos(ctx, []string{script})
	if err != nil {
		return nil, err
	}
	return byScript[script], nil
}

// how many requests to arkd, the indexer or the emulator run at once: enough
// to hide their latency, not enough to look like a flood
const concurrency = 4

// spendableVtxos queries the indexer for many scripts, a few chunks of 100
// at a time, and groups the result by script.
func (s *service) spendableVtxos(ctx context.Context, scripts []string) (map[string][]types.Vtxo, error) {
	const chunk = 100
	var mu sync.Mutex
	out := make(map[string][]types.Vtxo)
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(concurrency)
	for start := 0; start < len(scripts); start += chunk {
		batch := scripts[start:min(start+chunk, len(scripts))]
		g.Go(func() error {
			// arkd answers an unpaged request in full; should that change, follow the pages
			for page := int32(0); ; {
				opts := []indexer.GetVtxosOption{indexer.WithScripts(batch), indexer.WithSpendableOnly()}
				if page > 0 {
					opts = append(opts, indexer.WithVtxosPage(&indexer.PageRequest{Index: page}))
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
	if s.renewing.Load() > 0 {
		return nil // scans pause during a batch, by design
	}
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

// late reports a vtxo renewable for a while and still there: less than a
// quarter of the time between renewable and expiry is left.
func late(v types.Vtxo, due, now time.Time) bool {
	room := v.ExpiresAt.Sub(due)
	return room > 0 && v.ExpiresAt.Sub(now) < room/4
}

func (s *service) parseScript(tapscripts []string, c *covenant) (script.VtxoScript, error) {
	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidScript, err)
	}
	if !hasLeaf(tapscripts, c.tapscript) {
		return nil, fmt.Errorf("%w: missing delegate leaf %x", ErrInvalidScript, c.tapscript)
	}
	if len(vtxoScript.ExitClosures()) == 0 {
		return nil, fmt.Errorf("%w: missing exit leaf", ErrInvalidScript)
	}
	return vtxoScript, nil
}

func hasLeaf(tapscripts []string, leaf []byte) bool {
	for _, ts := range tapscripts {
		if b, err := hex.DecodeString(ts); err == nil && bytes.Equal(b, leaf) {
			return true
		}
	}
	return false
}

func (s *service) scriptOf(d *domain.Delegation) ([]byte, script.VtxoScript, error) {
	vtxoScript, err := script.ParseVtxoScript(d.Tapscripts)
	if err != nil {
		return nil, nil, err
	}
	tapKey, _, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}
	pkScript, err := script.P2TRScript(tapKey)
	return pkScript, vtxoScript, err
}

func (s *service) scan(ctx context.Context) {
	if s.renewing.Load() > 0 {
		return
	}
	now := time.Now()
	if s.lastPrune.IsZero() || now.Sub(s.lastPrune) >= renewalsPruneInterval {
		if err := s.repo.PruneRenewals(ctx, now.Add(-renewalsRetention)); err != nil {
			log.WithError(err).Warn("prune renewals")
		} else {
			s.lastPrune = now
		}
	}
	delegations, err := s.repo.List(ctx, domain.DelegationStatusActive)
	if err != nil {
		log.WithError(err).Error("list active delegations")
		return
	}

	byScript := make(map[string]*watched, len(delegations))
	scripts := make([]string, 0, len(delegations))
	cache := make(map[int64]*watched, len(delegations)) // rebuilt, so cancelled ones drop out
	for i := range delegations {
		d := &delegations[i]
		w, known := s.watched[d.ID]
		if !known {
			if w, err = s.watch(d); err != nil {
				log.WithError(err).WithField("address", d.Address).Error("unusable delegation")
			}
		}
		cache[d.ID] = w
		if w != nil {
			byScript[w.script] = w
			scripts = append(scripts, w.script)
		}
	}
	s.watched = cache
	vtxosByScript, err := s.spendableVtxos(ctx, scripts)
	if err != nil {
		log.WithError(err).Error("list vtxos")
		return
	}

	holdings := make(map[int64]Holdings, len(scripts))
	var inputs []renewalInput
	for _, script := range scripts {
		w := byScript[script]
		h := Holdings{Vtxos: len(vtxosByScript[script])}
		for _, v := range vtxosByScript[script] {
			h.Amount += v.Amount
			if h.NextExpiry.IsZero() || v.ExpiresAt.Before(h.NextExpiry) {
				h.NextExpiry = v.ExpiresAt
			}
			due := dueAt(v, w.delegation.Params)
			if h.NextDue.IsZero() || due.Before(h.NextDue) {
				h.NextDue = due
			}
			if late(v, due, now) {
				h.Late++
				h.LateAmount += v.Amount
			}
			if !now.Before(due) {
				inputs = append(inputs, renewalInput{
					vtxo: v, delegation: &w.delegation, pkScript: w.pkScript,
					leaf: w.leaf, arkadeScript: w.covenant.arkadeScript, cosigner: w.cosigner,
				})
			}
		}
		holdings[w.delegation.ID] = h
	}
	var lateVtxos int
	for _, h := range holdings {
		lateVtxos += h.Late
	}
	if lateVtxos > 0 {
		log.WithField("count", lateVtxos).Warn("vtxos renewable for a while and not renewed: are arkd rounds running?")
	}
	s.mu.Lock()
	s.lastScan, s.holdings = now, holdings
	s.mu.Unlock()
	if len(inputs) == 0 {
		return
	}
	// one cosigner key means one batch session at a time: renew everything together.
	// Stop waits for it rather than cancelling: an abandoned intent stalls arkd rounds.
	s.renewing.Store(int64(len(inputs)))
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.renewing.Store(0)
		s.renewAndRecord(context.Background(), inputs)
	}()
}

func (s *service) renewAndRecord(ctx context.Context, inputs []renewalInput) {
	log.WithField("count", len(inputs)).Info("renewing vtxos")

	renewCtx, cancel := context.WithTimeout(ctx, s.renewalTimeout)
	defer cancel()
	results := s.renew(renewCtx, inputs)

	// forget outpoints that are gone, so lastFailure stays as small as the due set
	due := make(map[string]string, len(inputs))
	for _, in := range inputs {
		if msg, ok := s.lastFailure[in.vtxo.Outpoint.String()]; ok {
			due[in.vtxo.Outpoint.String()] = msg
		}
	}
	s.lastFailure = due

	// one renewal row per delegation and outcome
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
			// a vtxo failing the same way every poll is reported once
			outpoint := in.vtxo.Outpoint.String()
			if errMsg != "" && s.lastFailure[outpoint] == errMsg {
				continue
			}
			if delete(s.lastFailure, outpoint); errMsg != "" {
				s.lastFailure[outpoint] = errMsg
			}
			k := key{in.delegation.ID, res.commitmentTxid, errMsg}
			ren, ok := byDelegation[k]
			if !ok {
				ren = &domain.Renewal{
					DelegationID: in.delegation.ID, CommitmentTxid: res.commitmentTxid,
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
			s.renewed.Add(uint64(len(ren.Outpoints)))
			logger.WithField("commitment_txid", ren.CommitmentTxid).Info("vtxos renewed")
		} else {
			s.failed.Add(uint64(len(ren.Outpoints)))
			logger.WithField("error", ren.Error).Error("renewal failed")
		}
		if err := s.repo.RecordRenewal(context.WithoutCancel(ctx), *ren); err != nil {
			logger.WithError(err).Error("record renewal")
		}
	}
}

// watch derives what is needed to renew d, or nil when it was registered
// under another key.
func (s *service) watch(d *domain.Delegation) (*watched, error) {
	for _, cosigner := range s.cosigners {
		c, err := s.covenantForCosigner(d.Params, cosigner)
		if err != nil {
			return nil, err
		}
		if !hasLeaf(d.Tapscripts, c.tapscript) {
			continue
		}
		pkScript, leaf, err := s.delegateLeaf(d, c)
		if err != nil {
			return nil, err
		}
		return &watched{
			delegation: *d, cosigner: cosigner, pkScript: pkScript,
			script: hex.EncodeToString(pkScript), leaf: leaf, covenant: c,
		}, nil
	}
	return nil, nil
}

func (s *service) delegateLeaf(d *domain.Delegation, c *covenant) ([]byte, *psbt.TaprootTapLeafScript, error) {
	pkScript, vtxoScript, err := s.scriptOf(d)
	if err != nil {
		return nil, nil, err
	}
	_, tapTree, err := vtxoScript.TapTree()
	if err != nil {
		return nil, nil, err
	}
	proof, err := tapTree.GetTaprootMerkleProof(txscript.NewBaseTapLeaf(c.tapscript).TapHash())
	if err != nil {
		return nil, nil, err
	}
	return pkScript, &psbt.TaprootTapLeafScript{
		ControlBlock: proof.ControlBlock,
		Script:       proof.Script,
		LeafVersion:  txscript.BaseLeafVersion,
	}, nil
}

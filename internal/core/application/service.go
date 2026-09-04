// Package application renews VTXOs locked by the delegate covenant: near
// expiry it registers a self-send intent in a batch and cosigns the tree.
package application

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
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
	log "github.com/sirupsen/logrus"
)

var ErrInvalidScript = errors.New("invalid vtxo script")

// Info is what a wallet needs to build a delegate address for one renewal window.
type Info struct {
	Network               string
	DelegatePubKey        string
	ServerPubKey          string
	EmulatorPubKey        string
	EmulatorTweakedPubKey string
	ArkadeScript          string
	DelegateTapscript     string
	RenewalWindow         int64
}

type Service interface {
	Start()
	Stop()
	Info(renewalWindow int64) (Info, error)
	RegisterDelegation(ctx context.Context, tapscripts []string, renewalWindow int64) (*domain.Delegation, error)
	CancelDelegation(ctx context.Context, address string) error
	GetDelegation(ctx context.Context, address string) (*domain.Delegation, error)
	ListDelegations(ctx context.Context) ([]domain.Delegation, error)
	ListRenewals(ctx context.Context, d *domain.Delegation) ([]domain.Renewal, error)
	Vtxos(ctx context.Context, d *domain.Delegation) ([]types.Vtxo, error)
	Health(ctx context.Context) map[string]error
}

type service struct {
	repo              domain.DelegationRepository
	ark               client.Client
	indexer           indexer.Indexer
	emulator          emulatorclient.TransportClient
	key               *btcec.PrivateKey
	pollInterval      time.Duration
	renewalTimeout    time.Duration
	maxVtxosPerIntent int

	network           arklib.Network
	serverPubKey      *btcec.PublicKey
	forfeitPubKey     *btcec.PublicKey
	forfeitPkScript   []byte
	emulatorPubKey    *btcec.PublicKey
	delegatePubKeyHex string

	renewing atomic.Bool
	wg       sync.WaitGroup
	stop     context.CancelFunc
	stopped  chan struct{}
}

type renewalInput struct {
	vtxo         types.Vtxo
	delegation   *domain.Delegation
	pkScript     []byte
	leaf         *psbt.TaprootTapLeafScript
	arkadeScript []byte
}

// covenant is the delegate leaf for one renewal window.
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
	maxVtxosPerIntent int,
) (Service, error) {
	if maxVtxosPerIntent <= 0 {
		return nil, fmt.Errorf("max vtxos per intent must be positive")
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
		key:               key,
		pollInterval:      pollInterval,
		renewalTimeout:    renewalTimeout,
		maxVtxosPerIntent: maxVtxosPerIntent,
		network:           network,
		serverPubKey:      serverPubKey,
		forfeitPubKey:     forfeitPubKey,
		forfeitPkScript:   forfeitPkScript,
		emulatorPubKey:    emuPubKey,
		delegatePubKeyHex: tree.NewTreeSignerSession(key).GetPublicKey(),
	}, nil
}

func (s *service) covenantFor(renewalWindow int64) (*covenant, error) {
	if renewalWindow < 0 {
		return nil, fmt.Errorf("%w: renewal window must be positive", ErrInvalidScript)
	}
	arkadeScript, err := buildArkadeScript(s.delegatePubKeyHex, renewalWindow)
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

func (s *service) Info(renewalWindow int64) (Info, error) {
	if renewalWindow == 0 {
		renewalWindow = DefaultRenewalWindow
	}
	c, err := s.covenantFor(renewalWindow)
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
		RenewalWindow:         renewalWindow,
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
	ctx context.Context, tapscripts []string, renewalWindow int64,
) (*domain.Delegation, error) {
	if renewalWindow == 0 {
		renewalWindow = DefaultRenewalWindow
	}
	c, err := s.covenantFor(renewalWindow)
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
	d, err := s.repo.Create(ctx, addr, tapscripts, renewalWindow)
	if err != nil {
		return nil, err
	}
	log.WithField("address", addr).Info("address registered for delegation")
	return d, nil
}

func (s *service) CancelDelegation(ctx context.Context, address string) error {
	return s.repo.Cancel(ctx, address)
}

func (s *service) GetDelegation(ctx context.Context, address string) (*domain.Delegation, error) {
	return s.repo.Get(ctx, address)
}

func (s *service) ListDelegations(ctx context.Context) ([]domain.Delegation, error) {
	return s.repo.List(ctx, "")
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

// spendableVtxos queries the indexer for many scripts at once, in chunks
// that keep each response small, and groups the result by script.
func (s *service) spendableVtxos(ctx context.Context, scripts []string) (map[string][]types.Vtxo, error) {
	const chunk = 100
	out := make(map[string][]types.Vtxo)
	for start := 0; start < len(scripts); start += chunk {
		resp, err := s.indexer.GetVtxos(ctx,
			indexer.WithScripts(scripts[start:min(start+chunk, len(scripts))]),
			indexer.WithSpendableOnly(),
		)
		if err != nil {
			return nil, err
		}
		for _, v := range resp.Vtxos {
			out[v.Script] = append(out[v.Script], v)
		}
	}
	return out, nil
}

func (s *service) Health(ctx context.Context) map[string]error {
	_, arkErr := s.ark.GetInfo(ctx)
	_, emuErr := s.emulator.GetInfo(ctx)
	return map[string]error{
		"database": s.repo.Ping(ctx),
		"ark":      arkErr,
		"emulator": emuErr,
	}
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
	if s.renewing.Load() {
		return
	}
	delegations, err := s.repo.List(ctx, domain.DelegationStatusActive)
	if err != nil {
		log.WithError(err).Error("list active delegations")
		return
	}

	type watched struct {
		delegation *domain.Delegation
		covenant   *covenant
		leaf       *psbt.TaprootTapLeafScript
	}
	byScript := make(map[string]watched, len(delegations))
	scripts := make([]string, 0, len(delegations))
	for i := range delegations {
		d := &delegations[i]
		c, err := s.covenantFor(d.RenewalWindow)
		if err != nil {
			log.WithError(err).WithField("address", d.Address).Error("covenant")
			continue
		}
		// skip delegations registered under another key
		if !hasLeaf(d.Tapscripts, c.tapscript) {
			continue
		}
		pkScript, leaf, err := s.delegateLeaf(d, c)
		if err != nil {
			log.WithError(err).WithField("address", d.Address).Error("delegate leaf")
			continue
		}
		script := hex.EncodeToString(pkScript)
		byScript[script] = watched{delegation: d, covenant: c, leaf: leaf}
		scripts = append(scripts, script)
	}
	if len(scripts) == 0 {
		return
	}
	vtxosByScript, err := s.spendableVtxos(ctx, scripts)
	if err != nil {
		log.WithError(err).Error("list vtxos")
		return
	}

	now := time.Now().Unix()
	var inputs []renewalInput
	for _, script := range scripts {
		w := byScript[script]
		pkScript, _ := hex.DecodeString(script)
		for _, v := range vtxosByScript[script] {
			if v.ExpiresAt.Unix()-now <= w.delegation.RenewalWindow {
				inputs = append(inputs, renewalInput{
					vtxo: v, delegation: w.delegation, pkScript: pkScript,
					leaf: w.leaf, arkadeScript: w.covenant.arkadeScript,
				})
			}
		}
	}
	if len(inputs) == 0 {
		return
	}
	// one cosigner key means one batch session at a time: renew everything together.
	// Stop waits for it rather than cancelling: an abandoned intent stalls arkd rounds.
	s.renewing.Store(true)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer s.renewing.Store(false)
		s.renewAndRecord(context.Background(), inputs)
	}()
}

func (s *service) renewAndRecord(ctx context.Context, inputs []renewalInput) {
	log.WithField("count", len(inputs)).Info("renewing vtxos")

	renewCtx, cancel := context.WithTimeout(ctx, s.renewalTimeout)
	defer cancel()
	results := s.renew(renewCtx, inputs)

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
			ren.Outpoints = append(ren.Outpoints, in.vtxo.Outpoint.String())
		}
	}
	for _, k := range order {
		ren := byDelegation[k]
		logger := log.WithFields(log.Fields{"delegation": ren.DelegationID, "vtxos": ren.Outpoints})
		if ren.Success {
			logger.WithField("commitment_txid", ren.CommitmentTxid).Info("vtxos renewed")
		} else {
			logger.WithField("error", ren.Error).Error("renewal failed")
		}
		if err := s.repo.RecordRenewal(context.WithoutCancel(ctx), *ren); err != nil {
			logger.WithError(err).Error("record renewal")
		}
	}
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

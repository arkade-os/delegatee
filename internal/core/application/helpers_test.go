package application

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/intent"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var errBoom = errors.New("boom")

type fakeRepo struct {
	mu          sync.Mutex
	delegations []domain.Delegation
	renewals    []domain.Renewal
	artifacts   map[string]domain.Artifact
	templates   map[string]domain.Template
	prunedTo    time.Time
	// fingerprintMisses fakes another replica inserting between lookup and insert.
	fingerprintMisses int
	lastID            int64
	closed            bool
	err               error // returned by every call when set
	createErr         error // returned by Create when set
	saveErr           error // returned by SaveSettlement when set
	finalsSaveErr     error // returned by SaveSettlement for a row with final checkpoints
	listSettlementErr error
	getErr            error // returned by GetByID when set
	settlements       map[[2]string]domain.Settlement
	artifactErr       error // returned by GetArtifact when set
	// afterListSettlements runs once, after the next ListSettlements took its rows
	afterListSettlements func()
	// afterDeleteSettlement runs once, after the next DeleteSettlement
	afterDeleteSettlement func()
}

func (r *fakeRepo) Create(_ context.Context, d domain.Delegation, max int) (*domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := cmp.Or(r.err, r.createErr); err != nil {
		return nil, err
	}
	if d.Variables == nil {
		d.Variables = map[string]string{}
	}
	if d.Slots == nil {
		d.Slots = []domain.SlotBinding{}
	}
	active := 0
	for _, existing := range r.delegations {
		if existing.Status != domain.DelegationStatusActive {
			continue
		}
		// only active rows are unique, as the postgres partial index
		if existing.Fingerprint == d.Fingerprint {
			return &existing, nil
		}
		active++
	}
	if max > 0 && active >= max {
		return nil, domain.ErrCapReached
	}
	r.lastID++
	d.ID, d.Status = r.lastID, domain.DelegationStatusActive
	d.CreatedAt, d.UpdatedAt = time.Now(), time.Now()
	r.delegations = append(r.delegations, d)
	return &d, nil
}

func (r *fakeRepo) CountDelegationsByTemplate(context.Context) (map[string]int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int64{}
	for _, d := range r.delegations {
		out[d.TemplateID]++
	}
	return out, nil
}

func (r *fakeRepo) CreateArtifact(_ context.Context, id string, document []byte, max int) (*domain.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.artifacts == nil {
		r.artifacts = map[string]domain.Artifact{}
	}
	if a, ok := r.artifacts[id]; ok {
		return &a, nil
	}
	if max > 0 && len(r.artifacts) >= max {
		return nil, domain.ErrCapReached
	}
	a := domain.Artifact{ID: id, Document: document, CreatedAt: time.Now()}
	r.artifacts[id] = a
	return &a, nil
}

func (r *fakeRepo) GetArtifact(_ context.Context, id string) (*domain.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.artifactErr != nil {
		return nil, r.artifactErr
	}
	if a, ok := r.artifacts[id]; ok {
		return &a, nil
	}
	return nil, domain.ErrArtifactNotFound
}

func (r *fakeRepo) DeleteArtifact(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, t := range r.templates {
		if slices.Contains(t.ArtifactIDs, id) {
			return domain.ErrArtifactInUse
		}
	}
	if _, ok := r.artifacts[id]; !ok {
		return domain.ErrArtifactNotFound
	}
	delete(r.artifacts, id)
	return nil
}

func (r *fakeRepo) CreateTemplate(_ context.Context, t domain.Template, max int) (*domain.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if r.templates == nil {
		r.templates = map[string]domain.Template{}
	}
	if existing, ok := r.templates[t.ID]; ok {
		return &existing, nil
	}
	if max > 0 && len(r.templates) >= max {
		return nil, domain.ErrCapReached
	}
	if t.Params == nil {
		t.Params = []domain.Param{}
	}
	t.Status, t.CreatedAt = domain.TemplateStatusActive, time.Now()
	r.templates[t.ID] = t
	return &t, nil
}

func (r *fakeRepo) GetTemplate(_ context.Context, id string) (*domain.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if t, ok := r.templates[id]; ok {
		return &t, nil
	}
	return nil, domain.ErrTemplateNotFound
}

func (r *fakeRepo) ListTemplates(_ context.Context, status string) ([]domain.Template, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	var out []domain.Template
	for _, t := range r.templates {
		if status == "" || t.Status == status {
			t.Document = nil
			out = append(out, t)
		}
	}
	return out, nil
}

func (r *fakeRepo) SetTemplateStatus(_ context.Context, id, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.templates[id]
	if !ok {
		return domain.ErrTemplateNotFound
	}
	t.Status = status
	if status == domain.TemplateStatusActive {
		t.Failures = 0
	}
	r.templates[id] = t
	return nil
}

func (r *fakeRepo) SetTemplateTrusted(_ context.Context, id string, trusted bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.templates[id]
	if !ok {
		return domain.ErrTemplateNotFound
	}
	t.Trusted = trusted
	r.templates[id] = t
	return nil
}

func (r *fakeRepo) DeleteTemplate(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.delegations {
		if d.TemplateID == id {
			return domain.ErrTemplateInUse
		}
	}
	if _, ok := r.templates[id]; !ok {
		return domain.ErrTemplateNotFound
	}
	delete(r.templates, id)
	return nil
}

func (r *fakeRepo) RecordTemplateOutcome(_ context.Context, id string, success bool, maxFailures int) (int, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	t, ok := r.templates[id]
	if !ok {
		return 0, "", domain.ErrTemplateNotFound
	}
	if success {
		t.Failures = 0
	} else if t.Failures++; t.Failures >= maxFailures {
		t.Status = domain.TemplateStatusDisabled
	}
	r.templates[id] = t
	return t.Failures, t.Status, nil
}

func (r *fakeRepo) ListArtifacts(context.Context) ([]domain.Artifact, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.Artifact, 0, len(r.artifacts))
	for _, a := range r.artifacts {
		out = append(out, domain.Artifact{ID: a.ID, CreatedAt: a.CreatedAt})
	}
	return out, nil
}

// Get prefers an active row, then the newest, as the postgres query does.
func (r *fakeRepo) Get(_ context.Context, address string) (*domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var found *domain.Delegation
	for i := len(r.delegations) - 1; i >= 0 && address != ""; i-- {
		d := r.delegations[i]
		if d.Address != address {
			continue
		}
		if d.Status == domain.DelegationStatusActive {
			return &d, nil
		}
		if found == nil {
			found = &d
		}
	}
	if found == nil {
		return nil, domain.ErrDelegationNotFound
	}
	return found, nil
}

func (r *fakeRepo) GetByID(_ context.Context, id int64) (*domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.getErr != nil {
		return nil, r.getErr
	}
	for _, d := range r.delegations {
		if d.ID == id {
			return &d, nil
		}
	}
	return nil, domain.ErrDelegationNotFound
}

func (r *fakeRepo) List(_ context.Context, status string) ([]domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	var out []domain.Delegation
	for _, d := range r.delegations {
		if status == "" || d.Status == status {
			out = append(out, d)
		}
	}
	return out, nil
}

func (r *fakeRepo) ListPage(ctx context.Context, status string, cursor int64, limit int) ([]domain.Delegation, error) {
	all, err := r.List(ctx, status)
	all = slices.DeleteFunc(all, func(d domain.Delegation) bool { return cursor != 0 && d.ID >= cursor })
	slices.Reverse(all)
	return all[:min(limit, len(all))], err
}

func (r *fakeRepo) CountActive(context.Context) (n int64, _ error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.delegations {
		if r.delegations[i].Status == domain.DelegationStatusActive {
			n++
		}
	}
	return n, r.err
}

func (r *fakeRepo) SetStatus(_ context.Context, id int64, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	for i := range r.delegations {
		if d := &r.delegations[i]; d.ID == id {
			if d.Status == domain.DelegationStatusActive {
				d.Status = status
			}
			return nil
		}
	}
	return domain.ErrDelegationNotFound
}

func (r *fakeRepo) GetByFingerprint(_ context.Context, fingerprint string) (*domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	if r.fingerprintMisses > 0 {
		r.fingerprintMisses--
		return nil, domain.ErrDelegationNotFound
	}
	for i := len(r.delegations) - 1; i >= 0; i-- {
		if d := r.delegations[i]; d.Fingerprint == fingerprint {
			return &d, nil
		}
	}
	return nil, domain.ErrDelegationNotFound
}

func (r *fakeRepo) Resume(_ context.Context, id int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.delegations {
		if d := &r.delegations[i]; d.ID == id {
			if d.Status != domain.DelegationStatusCancelled {
				return domain.ErrNotCancelled
			}
			d.Status = domain.DelegationStatusActive
			return r.err
		}
	}
	return domain.ErrDelegationNotFound
}

func (r *fakeRepo) GetActiveByOutpoint(_ context.Context, outpoint string) (*domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, d := range r.delegations {
		if d.Status == domain.DelegationStatusActive &&
			slices.ContainsFunc(d.Slots, func(s domain.SlotBinding) bool { return s.Outpoint == outpoint }) {
			return &d, nil
		}
	}
	return nil, domain.ErrDelegationNotFound
}

func (r *fakeRepo) Expire(_ context.Context, before time.Time) (expired int64, _ error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return 0, r.err
	}
	for i := range r.delegations {
		d := &r.delegations[i]
		if d.Status == domain.DelegationStatusActive && d.ExpiresAt != nil && !d.ExpiresAt.After(before) {
			d.Status, expired = domain.DelegationStatusExpired, expired+1
		}
	}
	return expired, nil
}

func (r *fakeRepo) RecordRenewal(_ context.Context, ren domain.Renewal) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.renewals = append(r.renewals, ren)
	return nil
}

func (r *fakeRepo) recorded() []domain.Renewal {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.Renewal(nil), r.renewals...)
}

func (r *fakeRepo) ListRenewals(_ context.Context, id int64, limit int) ([]domain.Renewal, error) {
	var out []domain.Renewal
	for _, ren := range r.recorded() {
		if ren.DelegationID == id && len(out) < limit {
			out = append(out, ren)
		}
	}
	return out, nil
}

func (r *fakeRepo) LastRenewals(context.Context) (map[int64]domain.Renewal, error) {
	out := map[int64]domain.Renewal{}
	for _, ren := range r.recorded() {
		out[ren.DelegationID] = ren
	}
	return out, nil
}

func (r *fakeRepo) PruneRenewals(_ context.Context, before time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.prunedTo = before
	return nil
}

func (r *fakeRepo) SaveSettlement(_ context.Context, s domain.Settlement) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := cmp.Or(r.err, r.saveErr); err != nil {
		return err
	}
	if len(s.Finals) > 0 && r.finalsSaveErr != nil {
		return r.finalsSaveErr
	}
	if r.settlements == nil {
		r.settlements = map[[2]string]domain.Settlement{}
	}
	key := [2]string{s.Txid, s.SpentBy}
	if old, ok := r.settlements[key]; ok {
		old.Finals, old.Landed = s.Finals, s.Landed
		s = old
	}
	s.CreatedAt = cmp.Or(s.CreatedAt, time.Now())
	r.settlements[key] = s
	return nil
}

func (r *fakeRepo) ListSettlements(context.Context) ([]domain.Settlement, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := cmp.Or(r.err, r.listSettlementErr); err != nil {
		return nil, err
	}
	out := slices.Collect(maps.Values(r.settlements))
	slices.SortFunc(out, func(a, b domain.Settlement) int { return a.CreatedAt.Compare(b.CreatedAt) })
	if hook := r.afterListSettlements; hook != nil {
		r.afterListSettlements = nil
		r.mu.Unlock()
		hook()
		r.mu.Lock()
	}
	return out, nil
}

func (r *fakeRepo) DeleteSettlement(_ context.Context, txid, spentBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	delete(r.settlements, [2]string{txid, spentBy})
	if hook := r.afterDeleteSettlement; hook != nil {
		r.afterDeleteSettlement = nil
		r.mu.Unlock()
		hook()
		r.mu.Lock()
	}
	return nil
}

// age makes every settlement older by d.
func (r *fakeRepo) age(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, s := range r.settlements {
		s.CreatedAt = s.CreatedAt.Add(-d)
		r.settlements[k] = s
	}
}

func (r *fakeRepo) settled() []domain.Settlement {
	rows, _ := r.ListSettlements(context.Background())
	return rows
}

func (r *fakeRepo) Ping(context.Context) error { return r.err }
func (r *fakeRepo) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// fakeArk panics on any arkd method it does not implement.
type fakeArk struct {
	clientlib.Client
	mu           sync.Mutex
	info         *clientlib.Info
	infoErr      error
	registerErr  error
	streamErr    error
	registered   []string // proofs
	confirmed    []string
	nonces       tree.TreeNonces
	sigs         tree.TreePartialSigs
	forfeits     []string
	submitTx     func(ark string, checkpoints []string) (string, string, []string, error)
	finalized    []string // checkpoints
	finalizes    int      // FinalizeTx calls
	finalizeErrs []error  // returned by the next calls, in order
	batch        *fakeBatch
	// pending answers GetPendingTx for a proof signed for its coins
	pending       []clientlib.AcceptedOffchainTx
	pendingProofs int
}

func (a *fakeArk) GetPendingTx(_ context.Context, proof, message string) ([]clientlib.AcceptedOffchainTx, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pendingProofs++
	server, err := PubKeyFromHex(a.info.SignerPubKey)
	if err != nil {
		return nil, err
	}
	if err := intent.Verify(proof, message, []*btcec.PublicKey{server}); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return a.pending, nil
}

func (a *fakeArk) SubmitTreeNonces(_ context.Context, _, _ string, nonces tree.TreeNonces) error {
	a.nonces = nonces
	if a.batch != nil {
		a.batch.aggregate(nonces)
	}
	return nil
}
func (a *fakeArk) SubmitTreeSignatures(_ context.Context, _, _ string, sigs tree.TreePartialSigs) error {
	a.sigs = sigs
	return nil
}
func (a *fakeArk) SubmitSignedForfeitTxs(_ context.Context, forfeits []string, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.batch != nil && a.batch.crashAtForfeits {
		a.batch.finalized.Do(func() { close(a.batch.events) })
		return status.Error(codes.Unavailable, "connection lost")
	}
	a.forfeits = append(a.forfeits, forfeits...)
	if a.batch != nil {
		a.batch.finalized.Do(func() {
			if a.batch.failAfterForfeits {
				a.batch.send(clientlib.BatchFailedEvent{Id: "b1", Reason: "a peer failed"})
				return
			}
			if a.batch.closeAfterForfeits {
				close(a.batch.events)
				return
			}
			if a.batch.hangAfterForfeits {
				return
			}
			a.batch.send(clientlib.BatchFinalizedEvent{Id: "b1", Txid: a.batch.txid})
		})
	}
	return nil
}

func (a *fakeArk) GetInfo(context.Context) (*clientlib.Info, error) { return a.info, a.infoErr }
func (a *fakeArk) RegisterIntent(_ context.Context, proof, _ string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.registerErr != nil {
		return "", a.registerErr
	}
	a.registered = append(a.registered, proof)
	return "intent-" + string(rune('a'+len(a.registered)-1)), nil
}
func (a *fakeArk) ConfirmRegistration(_ context.Context, id string) error {
	a.confirmed = append(a.confirmed, id)
	if a.batch != nil && len(a.confirmed) == 1 {
		a.mu.Lock()
		proofs := slices.Clone(a.registered)
		a.mu.Unlock()
		a.batch.start(proofs)
	}
	return nil
}

// GetEventStream closes at once unless a batch is playing.
func (a *fakeArk) GetEventStream(context.Context, []string) (<-chan clientlib.BatchEventChannel, func(), error) {
	if a.streamErr != nil {
		return nil, nil, a.streamErr
	}
	if a.batch != nil {
		return a.batch.events, func() {}, nil
	}
	ch := make(chan clientlib.BatchEventChannel)
	close(ch)
	return ch, func() {}, nil
}

func (a *fakeArk) SubmitTx(_ context.Context, ark string, checkpoints []string) (string, string, []string, error) {
	return a.submitTx(ark, checkpoints)
}

func (a *fakeArk) FinalizeTx(_ context.Context, _ string, checkpoints []string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.finalizes++
	if len(a.finalizeErrs) > 0 {
		err := a.finalizeErrs[0]
		a.finalizeErrs = a.finalizeErrs[1:]
		return err
	}
	a.finalized = checkpoints
	return nil
}

type fakeIndexer struct {
	clientlib.Indexer
	mu        sync.Mutex
	vtxos     []clientlib.Vtxo
	err       error
	calls     int
	served    bool
	txs       map[string]string // txid -> b64 psbt, filled by testEnv.source
	prevMiss  bool
	txLookups int
	known     []clientlib.Vtxo // answers a lookup by outpoint alone, spent coins included

	subscribed    map[string]bool // scripts of the open subscription
	subscriptions int
	events        chan clientlib.ScriptEvent
	endEvents     func()
	subErr        error
	updateErr     error
	opened        [][]string // scripts each NewSubscription received
}

// GetVtxos serves everything to a scan's first request by scripts.
func (i *fakeIndexer) GetVtxos(_ context.Context, opts ...clientlib.GetVtxosOption) (*clientlib.VtxosResponse, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if o, err := clientlib.ApplyGetVtxosOptions(opts...); err == nil && o.Outpoints != nil {
		asked := o.FormattedOutpoints()
		return &clientlib.VtxosResponse{Vtxos: slices.DeleteFunc(slices.Clone(i.known), func(v clientlib.Vtxo) bool {
			return !slices.Contains(asked, v.Outpoint.String())
		})}, i.err
	}
	i.calls++
	if i.err != nil {
		return nil, i.err
	}
	if i.served {
		return &clientlib.VtxosResponse{}, nil
	}
	i.served = true
	return &clientlib.VtxosResponse{Vtxos: i.vtxos}, nil
}

func (i *fakeIndexer) serve(vtxos ...clientlib.Vtxo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.vtxos, i.served, i.calls = vtxos, false, 0
}

func (i *fakeIndexer) NewSubscription(_ context.Context, scripts []string) (string, <-chan clientlib.ScriptEvent, func(), error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.subErr != nil {
		return "", nil, nil, i.subErr
	}
	i.subscriptions++
	i.opened = append(i.opened, slices.Clone(scripts))
	i.subscribed = map[string]bool{}
	for _, script := range scripts {
		i.subscribed[script] = true
	}
	events := make(chan clientlib.ScriptEvent, 8)
	i.events = events
	i.endEvents = sync.OnceFunc(func() { close(events) })
	stop := i.endEvents
	return fmt.Sprintf("sub-%d", i.subscriptions), events, func() {
		stop()
		i.mu.Lock()
		defer i.mu.Unlock()
		i.subscribed = nil
	}, nil
}

func (i *fakeIndexer) UpdateSubscription(_ context.Context, _ string, add, remove []string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.updateErr != nil {
		return i.updateErr
	}
	for _, script := range add {
		i.subscribed[script] = true
	}
	for _, script := range remove {
		delete(i.subscribed, script)
	}
	return nil
}

func (i *fakeIndexer) subscribedScripts() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return slices.Sorted(maps.Keys(i.subscribed))
}

// closeSubscription ends the stream as arkd going away for good does.
func (i *fakeIndexer) closeSubscription() {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.endEvents()
}

func (i *fakeIndexer) GetVirtualTxs(_ context.Context, txids []string, _ ...clientlib.PageOption) (*clientlib.VirtualTxsResponse, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.txLookups++
	resp := &clientlib.VirtualTxsResponse{}
	for k := len(txids) - 1; k >= 0 && !i.prevMiss; k-- { // in another order than asked
		if tx, ok := i.txs[txids[k]]; ok {
			resp.Txs = append(resp.Txs, tx)
		}
	}
	return resp, nil
}

type fakeEmulator struct {
	emulatorclient.TransportClient
	mu        sync.Mutex
	info      *emulatorclient.Info
	infoErr   error
	reject    func(emulatorclient.Intent) error
	submitted []emulatorclient.Intent
	submitTx  func(tx string, checkpoints []string) (string, []string, error)
	finalized []string // commitments sent to SubmitFinalization
	// nil signs every forfeit
	forfeits func(in emulatorclient.Intent, forfeits []string) []string
}

func (e *fakeEmulator) GetInfo(context.Context) (*emulatorclient.Info, error) {
	return e.info, e.infoErr
}
func (e *fakeEmulator) SubmitFinalization(
	_ context.Context, in emulatorclient.Intent, forfeits []string, _ tree.FlatTxTree, commitment string,
) ([]string, string, error) {
	e.mu.Lock()
	e.finalized = append(e.finalized, commitment)
	e.mu.Unlock()
	if e.infoErr != nil {
		return nil, "", e.infoErr
	}
	if e.forfeits != nil {
		return e.forfeits(in, forfeits), "", nil
	}
	// the emulator returns the commitment only when it signed one of its inputs
	return forfeits, "", nil
}
func (e *fakeEmulator) SubmitIntent(_ context.Context, in emulatorclient.Intent) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.submitted = append(e.submitted, in)
	if e.reject != nil {
		if err := e.reject(in); err != nil {
			return "", err
		}
	}
	return in.Proof, nil
}

func (e *fakeEmulator) SubmitTx(_ context.Context, tx string, checkpoints []string) (string, []string, error) {
	return e.submitTx(tx, checkpoints)
}

type fakeExplorer struct {
	clientlib.Explorer
	txs       map[string]*wire.MsgTx
	utxos     []clientlib.ExplorerUtxo
	spent     bool
	spentBy   string
	depth     int
	broadcast *wire.MsgTx
	lostReply bool // Broadcast relays the transaction and fails
	feeRate   float64
	feeErr    error
	tip       ports.ChainTip
	tipErr    error
	onUtxos   func() // runs inside GetUtxos
}

func (e *fakeExplorer) GetTxHex(id string) (string, error) {
	tx := e.txs[id]
	if tx == nil {
		return "", errors.New("tx not found")
	}
	var b bytes.Buffer
	err := tx.Serialize(&b)
	return hex.EncodeToString(b.Bytes()), err
}

func (e *fakeExplorer) GetTxOutspends(id string) ([]clientlib.SpentStatus, error) {
	tx := e.txs[id]
	if tx == nil {
		return nil, errors.New("tx not found")
	}
	out := make([]clientlib.SpentStatus, len(tx.TxOut))
	for i := range out {
		out[i].Spent, out[i].SpentBy = e.spent, e.spentBy
	}
	return out, nil
}

func (e *fakeExplorer) ChainTip() (ports.ChainTip, error) { return e.tip, e.tipErr }

// noTip is a tip for due times of coins without a locktime, which never ask for it
func noTip() (ports.ChainTip, error) { return ports.ChainTip{}, errors.New("no explorer") }

func (e *fakeExplorer) GetUtxos(addresses []string) ([]clientlib.ExplorerUtxo, error) {
	if e.onUtxos != nil {
		e.onUtxos()
	}
	var out []clientlib.ExplorerUtxo
	for _, a := range addresses {
		addr, err := address.DecodeAddress(a, &chaincfg.RegressionNetParams)
		if err != nil {
			return nil, err
		}
		script, err := txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
		for _, u := range e.utxos {
			if u.Script == hex.EncodeToString(script) {
				out = append(out, u)
			}
		}
	}
	return out, nil
}

func (e *fakeExplorer) Confirmations(string) (int, error) { return e.depth, nil }
func (e *fakeExplorer) GetFeeRate() (float64, error)      { return e.feeRate, e.feeErr }

func (e *fakeExplorer) Broadcast(raw ...string) (string, error) {
	tx := wire.NewMsgTx(2)
	if err := tx.Deserialize(hex.NewDecoder(bytes.NewBufferString(raw[0]))); err != nil {
		return "", err
	}
	e.broadcast = tx
	if e.lostReply {
		e.txs[tx.TxHash().String()] = tx
		return "", errors.New("timeout")
	}
	return tx.TxHash().String(), nil
}

// testEnv is a service wired to fakes, running the fixtures of pkg/template.
type testEnv struct {
	svc      *service
	repo     *fakeRepo
	ark      *fakeArk
	indexer  *fakeIndexer
	emulator *fakeEmulator
	explorer *fakeExplorer
	userKey  *btcec.PrivateKey
	fixtures map[string]string // file -> id, once registered
	txs      uint32            // makes every transaction a helper creates unique
}

func hexKey(t testing.TB) (*btcec.PrivateKey, string) {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return k, hex.EncodeToString(k.PubKey().SerializeCompressed())
}

func newTestEnv(t testing.TB, tweak ...func(*testEnv)) *testEnv {
	t.Helper()
	_, signer := hexKey(t)
	forfeitKey, forfeit := hexKey(t)
	_, emu := hexKey(t)
	forfeitAddr, err := address.NewAddressWitnessPubKeyHash(
		address.Hash160(forfeitKey.PubKey().SerializeCompressed()), &chaincfg.RegressionNetParams)
	require.NoError(t, err)

	env := &testEnv{
		repo: &fakeRepo{},
		ark: &fakeArk{info: &clientlib.Info{
			SignerPubKey: signer, ForfeitPubKey: forfeit, Network: arklib.BitcoinRegTest.Name,
			ForfeitAddress: forfeitAddr.EncodeAddress(), Dust: 330,
		}},
		indexer:  &fakeIndexer{txs: map[string]string{}},
		emulator: &fakeEmulator{info: &emulatorclient.Info{SignerPublicKey: emu}},
		explorer: &fakeExplorer{txs: map[string]*wire.MsgTx{}, depth: 1, feeRate: 2},
		fixtures: map[string]string{},
	}
	env.userKey, _ = hexKey(t)
	for _, f := range tweak {
		f(env)
	}
	env.svc = env.newService(t)
	return env
}

// restart is the daemon started again on the same database, arkd, indexer and chain.
func (e *testEnv) restart(t testing.TB) *testEnv {
	t.Helper()
	r := *e
	r.svc = e.newService(t)
	r.svc.encryptionKeys = e.svc.encryptionKeys
	return &r
}

func (e *testEnv) newService(t testing.TB) *service {
	t.Helper()
	var scalar [32]byte
	scalar[31] = 1
	key, _ := btcec.PrivKeyFromBytes(scalar[:])
	svc, err := NewServiceWithKeys(t.Context(), e.repo, e.ark, e.indexer, e.emulator, e.explorer, 30*time.Second, 50, nil,
		[]*btcec.PrivateKey{key}, time.Hour, time.Minute, 0,
		Limits{MaxDelegations: 100, MaxTemplates: 100, MaxArtifacts: 100, MaxDocumentBytes: 16 << 10, TemplateMaxFailures: 3})
	require.NoError(t, err)
	return svc.(*service)
}

func (e *testEnv) active(t testing.TB) []domain.Delegation {
	t.Helper()
	rows, err := e.repo.List(t.Context(), domain.DelegationStatusActive)
	require.NoError(t, err)
	return rows
}

// scan runs one scan and waits for its renewal.
func (e *testEnv) scan(t testing.TB) {
	e.svc.scan(t.Context())
	e.svc.wg.Wait()
}

func (e *testEnv) setFees(offchainInput string) {
	e.ark.info.Fees = clientlib.FeeInfo{IntentFees: arkfee.Config{IntentOffchainInputProgram: offchainInput}}
}

// cosignerHex is private scalar 1, the cosigner key the fixtures bind.
const cosignerHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func document(t testing.TB, file string) []byte {
	t.Helper()
	if file == ownedRenewal {
		return []byte(ownedRenewalDoc)
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "..", "pkg", "template", "testdata", file))
	if errors.Is(err, fs.ErrNotExist) {
		doc, err = os.ReadFile(filepath.Join("..", "..", "..", "templates", file))
	}
	require.NoError(t, err)
	return doc
}

func (e *testEnv) fixture(t testing.TB, file string) string {
	t.Helper()
	if id, ok := e.fixtures[file]; ok {
		return id
	}
	paths, err := filepath.Glob(filepath.Join("..", "..", "..", "pkg", "template", "testdata", "artifacts", "*.json"))
	require.NoError(t, err)
	artifacts := map[string][]byte{}
	for _, p := range append(paths, "delegated_vtxo.json") {
		doc := document(t, filepath.Join("artifacts", filepath.Base(p)))
		if a, err := template.ParseArtifact(doc); err == nil {
			artifacts[a.ID] = doc
		}
	}
	doc := document(t, file)
	parsed, err := template.Parse(t.Context(), doc, func(_ context.Context, id string) ([]byte, error) {
		if a, ok := artifacts[id]; ok {
			return a, nil
		}
		return nil, domain.ErrArtifactNotFound
	})
	require.NoError(t, err)
	for _, id := range parsed.Artifacts() {
		_, err := e.svc.RegisterArtifact(t.Context(), artifacts[id])
		require.NoError(t, err)
	}
	tmpl, err := e.svc.RegisterTemplate(t.Context(), doc)
	require.NoError(t, err)
	e.fixtures[file] = tmpl.ID
	return tmpl.ID
}

func (e *testEnv) trust(t testing.TB, id string) string {
	t.Helper()
	require.NoError(t, e.svc.SetTemplateTrusted(t.Context(), id, true))
	return id
}

func (e *testEnv) contract(t testing.TB, file string, slot int, args map[string]string) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(document(t, file), &doc))
	in := doc["inputs"].([]any)[slot].(map[string]any)
	c := in["contract"].(map[string]any)
	if c["arguments"] == nil {
		c["arguments"] = map[string]any{}
	}
	arguments := c["arguments"].(map[string]any)
	for n, v := range args {
		arguments[n] = v
	}
	delete(doc, "variables")
	// the input alone, paid back to itself, needs no sources
	raw, err := json.Marshal(map[string]any{
		"format": doc["format"], "type": "intent", "inputs": []any{in},
		"outputs": []any{map[string]any{"name": "out", "index": 0, "value": map[string]any{"from": in["name"]}, "locking": map[string]any{"from": in["name"]}}},
		"packets": map[string]any{"output_index": 1},
	})
	require.NoError(t, err)
	tmpl, err := template.Parse(t.Context(), raw, nil)
	require.NoError(t, err)
	inst, err := tmpl.Instantiate(t.Context(), template.Context{Keys: e.keys()})
	require.NoError(t, err)
	return inst.PkScript(0)
}

func (e *testEnv) keys() template.Keys {
	return template.Keys{Server: e.svc.serverPubKey, Emulator: e.svc.emulatorPubKey, Delegate: e.svc.cosigners[0].key.PubKey()}
}

func (e *testEnv) boarding(t testing.TB, owner *btcec.PublicKey) *domain.Delegation {
	t.Helper()
	d, err := e.svc.RegisterDelegation(t.Context(), e.fixture(t, "boarding.json"), e.boardingVars(t, owner), nil)
	require.NoError(t, err)
	return d
}

func (e *testEnv) boardingVars(t testing.TB, owner *btcec.PublicKey) map[string]string {
	t.Helper()
	vars := renewalVars(owner, 0)
	vars["boarding_exit_delay"] = hex.EncodeToString(scriptNum(1<<22 | 2))
	return vars
}

// renewalVars are the default renewal's: a 512-second exit, a 1024-second window.
func renewalVars(owner *btcec.PublicKey, maxFee int64) map[string]string {
	return map[string]string{
		"owner": hex.EncodeToString(owner.SerializeCompressed()), "exit_delay": hex.EncodeToString(scriptNum(1<<22 | 1)),
		"renewal_window": hex.EncodeToString(scriptNum(1024)), "max_fee": hex.EncodeToString(scriptNum(maxFee)),
	}
}

func scriptNum(n int64) []byte {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return b
}

// renewal watches owner's renewal address.
func (e *testEnv) renewal(t testing.TB, owner *btcec.PublicKey, maxFee int64) *domain.Delegation {
	t.Helper()
	d, err := e.svc.RegisterDelegation(t.Context(), e.fixture(t, "renewal.json"), renewalVars(owner, maxFee), nil)
	require.NoError(t, err)
	return d
}

func (e *testEnv) renewalScript(t testing.TB, owner *btcec.PublicKey, maxFee int64) []byte {
	t.Helper()
	script, err := hex.DecodeString(e.renewal(t, owner, maxFee).Slots[0].Script)
	require.NoError(t, err)
	return script
}

// ownedCoin's source carries owner in packet 2 and advertises ownedRenewal for output 0.
func (e *testEnv) ownedCoin(t testing.TB, owner *btcec.PublicKey, amount uint64, expiresIn time.Duration) clientlib.Vtxo {
	t.Helper()
	r := packets.Record{Outputs: []uint16{0}}
	_, err := hex.Decode(r.Template[:], []byte(e.fixture(t, ownedRenewal)))
	require.NoError(t, err)
	ad, err := packets.EncodeAdvertisement([]packets.Record{r})
	require.NoError(t, err)
	key := owner.SerializeCompressed()
	return e.vtxoAt(t, e.contract(t, ownedRenewal, 0, map[string]string{"owner": hex.EncodeToString(key)}), amount, expiresIn,
		packets.Raw(packets.TypeState, key), packets.Raw(packets.TypeAdvertisement, ad))
}

// coin is a vtxo at owner's watched renewal address.
func (e *testEnv) coin(t testing.TB, owner *btcec.PublicKey, amount uint64, expiresIn time.Duration) clientlib.Vtxo {
	t.Helper()
	return e.vtxoAt(t, e.renewalScript(t, owner, 0), amount, expiresIn)
}

// feeCoin is a coin of a renewal that pays up to maxFee.
func (e *testEnv) feeCoin(t testing.TB, owner *btcec.PublicKey, amount uint64, maxFee int64) clientlib.Vtxo {
	t.Helper()
	return e.vtxoAt(t, e.renewalScript(t, owner, maxFee), amount, time.Minute)
}

// advertised follows the advertisement of coin's source, as for a transaction the daemon settled.
func (e *testEnv) advertised(t testing.TB, coin clientlib.Vtxo) *domain.Delegation {
	t.Helper()
	for _, d := range e.active(t) {
		if d.Slots[0].Outpoint == "" && d.Slots[0].Script == coin.Script {
			e.indexer.serve(coin)
			return &d // a watch finds its coins itself
		}
	}
	e.indexer.serve(coin)
	src, err := e.svc.virtualTx(t.Context(), coin.Txid)
	require.NoError(t, err)
	outpoints := map[int]wire.OutPoint{}
	for i := range src.TxOut {
		outpoints[i] = wire.OutPoint{Hash: src.TxHash(), Index: uint32(i)}
	}
	parent := &domain.Delegation{DelegatePubKey: e.svc.cosigners[0].pubKey}
	require.NoError(t, e.svc.successors(t.Context(), parent, src, outpoints, map[string]*wire.MsgTx{coin.Txid: src}, false))
	d, err := e.repo.GetActiveByOutpoint(t.Context(), coin.Outpoint.String())
	require.NoError(t, err)
	return d
}

// pair is a counter and a reserve of counter.json sharing a source whose packet 2 holds 5.
func (e *testEnv) pair(t testing.TB, expiresIn time.Duration) (clientlib.Vtxo, clientlib.Vtxo) {
	t.Helper()
	e.fixture(t, "counter.json")
	tx := e.source(t, []*wire.TxOut{
		wire.NewTxOut(5000, e.contract(t, "counter.json", 0, nil)), wire.NewTxOut(6000, e.contract(t, "counter.json", 1, nil)),
	}, packets.Raw(packets.TypeState, []byte{5, 0, 0, 0, 0, 0, 0, 0}))
	return vtxoOf(tx, 0, expiresIn), vtxoOf(tx, 1, expiresIn)
}

func (e *testEnv) deposit(t testing.TB, d *domain.Delegation, amount uint64) clientlib.ExplorerUtxo {
	t.Helper()
	script, err := hex.DecodeString(d.Slots[0].Script)
	require.NoError(t, err)
	e.txs++
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(&wire.TxIn{PreviousOutPoint: wire.OutPoint{Index: e.txs}, Sequence: wire.MaxTxInSequenceNum})
	tx.AddTxOut(wire.NewTxOut(int64(amount), script))
	u := clientlib.ExplorerUtxo{
		Txid: tx.TxHash().String(), Amount: amount, Script: d.Slots[0].Script,
		Status: clientlib.ConfirmedStatus{Confirmed: true, BlockTime: time.Now().Add(-time.Hour).Unix()},
	}
	e.explorer.txs[u.Txid] = tx
	e.explorer.utxos = append(e.explorer.utxos, u)
	return u
}

func (e *testEnv) vtxoAt(t testing.TB, pkScript []byte, amount uint64, expiresIn time.Duration, pkts ...extension.Packet) clientlib.Vtxo {
	t.Helper()
	return vtxoOf(e.source(t, []*wire.TxOut{wire.NewTxOut(int64(amount), pkScript)}, pkts...), 0, expiresIn)
}

func (e *testEnv) source(t testing.TB, outs []*wire.TxOut, pkts ...extension.Packet) *wire.MsgTx {
	t.Helper()
	e.txs++
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: e.txs}, nil, nil))
	for _, out := range outs {
		tx.AddTxOut(out)
	}
	if len(pkts) > 0 {
		ext, err := extension.Extension(pkts).TxOut()
		require.NoError(t, err)
		tx.AddTxOut(ext)
	}
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	e.indexer.mu.Lock()
	e.indexer.txs[tx.TxHash().String()] = b64
	e.indexer.mu.Unlock()
	return tx
}

func vtxoOf(tx *wire.MsgTx, vout uint32, expiresIn time.Duration) clientlib.Vtxo {
	out := tx.TxOut[vout]
	return clientlib.Vtxo{
		Outpoint: clientlib.Outpoint{Txid: tx.TxHash().String(), VOut: vout}, Script: hex.EncodeToString(out.PkScript),
		Amount: uint64(out.Value), CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(expiresIn),
	}
}

func asVtxo(c coin) clientlib.Vtxo {
	return clientlib.Vtxo{
		Outpoint: clientlib.Outpoint{Txid: c.Outpoint.Hash.String(), VOut: c.Outpoint.Index}, Script: hex.EncodeToString(c.Script),
		Amount: c.Amount, CreatedAt: c.CreatedAt, ExpiresAt: c.Expiry, Assets: c.Assets, Swept: c.Swept,
	}
}

// claimVars seal the vhtlc_claim.json preimage to secrets.
func claimVars(t testing.TB, secrets *btcec.PublicKey) map[string]string {
	t.Helper()
	var v struct {
		Preimage string
		Vars     map[string]string
	}
	require.NoError(t, json.Unmarshal(document(t, "vhtlc_vector.json"), &v))
	preimage, err := hex.DecodeString(v.Preimage)
	require.NoError(t, err)
	sealed, err := ecies.Encrypt(secrets, preimage)
	require.NoError(t, err)
	v.Vars["ciphertext"] = hex.EncodeToString(sealed)
	return v.Vars
}

// fakeBatch is arkd running one batch that pays every registered intent's outputs with their packets.
type fakeBatch struct {
	t                  *testing.T
	env                *testEnv
	events             chan clientlib.BatchEventChannel
	batch              testBatch
	txid               string
	finalized          sync.Once
	closeAfterForfeits bool // the stream closes before the batch is reported finalized
	hangAfterForfeits  bool // the batch is never reported finalized
	failAfterForfeits  bool // arkd reports the batch failed
	crashAtForfeits    bool // the forfeits never reach arkd and the stream closes
}

func (e *testEnv) playBatch(t *testing.T) *fakeBatch {
	t.Helper()
	b := &fakeBatch{t: t, env: e, events: make(chan clientlib.BatchEventChannel, 256)}
	var hashes []string
	for c := 'a'; c <= 'z'; c++ {
		sum := sha256.Sum256([]byte("intent-" + string(c)))
		hashes = append(hashes, hex.EncodeToString(sum[:]))
	}
	b.send(clientlib.BatchStartedEvent{Id: "b1", HashedIntentIds: hashes, BatchExpiry: int64(testExpiry.Value)})
	e.ark.batch = b
	return b
}

func (b *fakeBatch) send(event any) { b.events <- clientlib.BatchEventChannel{Event: event} }

func (b *fakeBatch) start(proofs []string) {
	var outputs []*wire.TxOut
	var boarding []wire.OutPoint
	exts := map[*wire.TxOut]*wire.TxOut{}
	connectors := 0
	for _, raw := range proofs {
		proof, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		require.NoError(b.t, err)
		for _, in := range proof.UnsignedTx.TxIn[1:] {
			if _, onchain := b.env.explorer.txs[in.PreviousOutPoint.Hash.String()]; onchain {
				boarding = append(boarding, in.PreviousOutPoint)
			}
		}
		ext := slices.IndexFunc(proof.UnsignedTx.TxOut, func(o *wire.TxOut) bool { return extension.IsExtension(o.PkScript) })
		require.GreaterOrEqual(b.t, ext, 0)
		for _, out := range proof.UnsignedTx.TxOut[:ext] {
			exts[out] = proof.UnsignedTx.TxOut[ext]
			outputs = append(outputs, out)
		}
		connectors += len(proof.UnsignedTx.TxIn) - 1
	}
	b.batch = buildBatch(b.t, b.env, outputs, connectors, boarding...)
	// arkd copies the intent's extension into the leaf paying its output
	for _, leaf := range b.batch.vtxoTree.Leaves() {
		for out, ext := range exts {
			if paid := leaf.UnsignedTx.TxOut[0]; paid.Value == out.Value && bytes.Equal(paid.PkScript, out.PkScript) {
				leaf.UnsignedTx.AddTxOut(ext)
				leaf.Outputs = append(leaf.Outputs, psbt.POutput{})
				break
			}
		}
	}
	commitment, err := psbt.NewFromRawBytes(strings.NewReader(b.batch.commitment), true)
	require.NoError(b.t, err)
	b.txid = commitment.UnsignedTx.TxHash().String()
	nodes, err := b.batch.vtxoTree.Serialize()
	require.NoError(b.t, err)
	for _, node := range nodes {
		b.send(clientlib.TreeTxEvent{Id: "b1", BatchIndex: 0, Node: node})
	}
	b.send(clientlib.TreeSigningStartedEvent{
		Id: "b1", UnsignedCommitmentTx: b.batch.commitment, CosignersPubkeys: []string{b.env.svc.cosigners[0].pubKey},
	})
}

func (b *fakeBatch) aggregate(nonces tree.TreeNonces) {
	sweepRoot, err := sweepTapTreeRoot(b.env.svc.forfeitPubKey, testExpiry)
	require.NoError(b.t, err)
	coordinator, err := tree.NewTreeCoordinatorSession(sweepRoot, b.batch.amount, b.batch.vtxoTree)
	require.NoError(b.t, err)
	coordinator.AddNonce(b.env.svc.cosigners[0].key.PubKey(), nonces)
	aggregated, err := coordinator.AggregateNonces()
	require.NoError(b.t, err)
	b.send(clientlib.TreeNoncesAggregatedEvent{Id: "b1", Nonces: aggregated})
	nodes, err := b.batch.connectors.Serialize()
	require.NoError(b.t, err)
	for _, node := range nodes {
		b.send(clientlib.TreeTxEvent{Id: "b1", BatchIndex: 1, Node: node})
	}
	b.send(clientlib.BatchFinalizationEvent{Id: "b1", Tx: b.batch.commitment})
}

// claimable is claimEnv with an emulator and an arkd that sign.
func claimable(t *testing.T) (*testEnv, clientlib.Vtxo) {
	t.Helper()
	e, server, inputs := claimEnv(t)
	e.emulator.submitTx = func(tx string, cps []string) (string, []string, error) { return tx, cps, nil }
	e.ark.submitTx = func(ark string, cps []string) (string, string, []string, error) {
		ptx, signed := signAs(t, server, ark)
		_, cp := signAs(t, server, cps[0])
		return ptx.UnsignedTx.TxHash().String(), signed, []string{cp}, nil
	}
	return e, asVtxo(inputs[0].coin)
}

// laneEndsDuringScan has the batch lane run in and end once the next scan listed the settlements.
func (e *testEnv) laneEndsDuringScan(in renewalInput, end func()) {
	e.svc.batch.busy.Store(1)
	e.svc.setInFlight([]renewalInput{in}, true)
	e.repo.afterListSettlements = func() {
		end()
		e.svc.setInFlight([]renewalInput{in}, false)
		e.svc.batch.busy.Store(0)
	}
}

// openSubscription scans once and drains the wakes of the registration and of the opening.
func (e *testEnv) openSubscription(t *testing.T) {
	t.Helper()
	e.indexer.serve()
	e.scan(t)
	require.NotNil(t, e.svc.sub)
	for len(e.svc.wake) > 0 {
		<-e.svc.wake
	}
}

// ownedRenewal reads its owner from packet 2 of the source and advertises itself: a successor chain, unlike the renewal watch.
const ownedRenewal = "owned_renewal.json"

const ownedRenewalDoc = `{
  "format": "delegateed-template/v1",
  "type": "intent",
  "inputs": [{
    "name": "funds",
    "schedule": {"before_expiry_seconds": 1024},
    "contract": {
      "definition": {
        "contractName": "OwnedVtxo",
        "constructorInputs": [{"name": "owner", "type": "pubkey"}],
        "structs": [],
        "functions": [
          {"name": "spend", "leaves": [{"name": "spend", "asm": ["<owner>", "OP_CHECKSIGVERIFY", "<SERVER_KEY>", "OP_CHECKSIG"],
            "witness": [{"name": "ownerSig", "type": "signature", "encoding": "schnorr-64"}, {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]},
          {"name": "renew", "arkade": {"inputs": [], "asm": [
            "OP_PUSHEXPIRY", "1024", "OP_SUB", "OP_CHECKTIME", "OP_VERIFY",
            "0x636f7369676e6572735f7075626c69635f6b6579732e30", "OP_INSPECTINTENTMESSAGE", "OP_VERIFY", "<DELEGATE_KEY>", "OP_EQUALVERIFY",
            "2", "OP_INSPECTPACKET", "OP_VERIFY", "<owner>", "OP_EQUALVERIFY",
            "5", "OP_INSPECTPACKET", "OP_VERIFY", "5", "OP_PUSHCURRENTINPUTINDEX", "OP_INSPECTINPUTPACKET", "OP_VERIFY", "OP_EQUALVERIFY",
            "OP_PUSHCURRENTINPUTINDEX", "OP_1SUB", "7", "0", "OP_TUNNEL"]},
            "leaves": [{"name": "renew", "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:renew>", "OP_CHECKSIG"],
              "witness": [{"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}, {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}
        ]
      },
      "arguments": {"owner": "$(2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY)"}
    },
    "spend": {"function": "renew", "leaf": "renew"}
  }],
  "outputs": [{"name": "renewed", "index": 0, "value": {"from": "funds"}, "locking": {"from": "funds"}, "assets": [{"from": "funds"}]}],
  "packets": {
    "output_index": 1,
    "rules": [{"type": 2, "action": "copy", "from": "funds"}],
    "advertise": [{"template": "self", "outputs": ["renewed"]}]
  }
}`

package application

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	"github.com/arkade-os/delegatee/internal/core/domain"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

// fakeRepo is an in-memory domain.DelegationRepository.
type fakeRepo struct {
	mu          sync.Mutex
	delegations []domain.Delegation
	renewals    []domain.Renewal
	prunedTo    time.Time
	closed      bool
	err         error // returned by every call when set
}

func (r *fakeRepo) Create(_ context.Context, address string, tapscripts []string, p domain.Params) (*domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	for i := range r.delegations {
		if d := &r.delegations[i]; d.Address == address {
			if d.Status == domain.DelegationStatusActive {
				return nil, domain.ErrDelegationAlreadyExists
			}
			d.Status = domain.DelegationStatusActive
			return d, nil
		}
	}
	r.delegations = append(r.delegations, domain.Delegation{
		ID: int64(len(r.delegations) + 1), Address: address, Tapscripts: tapscripts,
		Params: p, Status: domain.DelegationStatusActive,
	})
	return &r.delegations[len(r.delegations)-1], nil
}

func (r *fakeRepo) Get(_ context.Context, address string) (*domain.Delegation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.delegations {
		if r.delegations[i].Address == address {
			return &r.delegations[i], nil
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

func (r *fakeRepo) Cancel(_ context.Context, address, status string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.delegations {
		if r.delegations[i].Address == address {
			r.delegations[i].Status = status
			return nil
		}
	}
	return domain.ErrDelegationNotFound
}

func (r *fakeRepo) Revoke(_ context.Context, address string, timestamp int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range r.delegations {
		if r.delegations[i].Address != address {
			continue
		}
		if timestamp <= r.delegations[i].LastRevocationTimestamp {
			return domain.ErrRevocationAlreadyUsed
		}
		r.delegations[i].Status = domain.DelegationStatusRevoked
		r.delegations[i].LastRevocationTimestamp = timestamp
		return nil
	}
	return domain.ErrDelegationNotFound
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

func (r *fakeRepo) Ping(context.Context) error { return r.err }
func (r *fakeRepo) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	return nil
}

// fakeArk answers what the delegatee calls on arkd; any other method panics
// on the nil embedded interface.
type fakeArk struct {
	clientlib.Client
	mu          sync.Mutex
	info        *clientlib.Info
	infoErr     error
	registerErr error
	streamErr   error
	registered  []string // proofs
	confirmed   []string
	nonces      tree.TreeNonces
	sigs        tree.TreePartialSigs
	forfeits    []string
}

func (a *fakeArk) SubmitTreeNonces(_ context.Context, _, _ string, nonces tree.TreeNonces) error {
	a.nonces = nonces
	return nil
}
func (a *fakeArk) SubmitTreeSignatures(_ context.Context, _, _ string, sigs tree.TreePartialSigs) error {
	a.sigs = sigs
	return nil
}
func (a *fakeArk) SubmitSignedForfeitTxs(_ context.Context, forfeits []string, _ string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.forfeits = append(a.forfeits, forfeits...)
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
	return nil
}

// GetEventStream serves a stream arkd closes at once: enough to reach the batch session.
func (a *fakeArk) GetEventStream(context.Context, []string) (<-chan clientlib.BatchEventChannel, func(), error) {
	if a.streamErr != nil {
		return nil, nil, a.streamErr
	}
	ch := make(chan clientlib.BatchEventChannel)
	close(ch)
	return ch, func() {}, nil
}

type fakeIndexer struct {
	clientlib.Indexer
	mu        sync.Mutex
	vtxos     []clientlib.Vtxo
	err       error
	calls     int
	served    bool
	txs       map[string]string // txid -> b64 psbt, filled by testEnv.vtxo
	prevMiss  bool
	txLookups int
}

// GetVtxos cannot see which scripts are asked for (the options are opaque),
// so it serves everything to the first request of a scan and nothing after.
func (i *fakeIndexer) GetVtxos(context.Context, ...clientlib.GetVtxosOption) (*clientlib.VtxosResponse, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
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

// serve makes the next scan see vtxos.
func (i *fakeIndexer) serve(vtxos ...clientlib.Vtxo) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.vtxos, i.served, i.calls = vtxos, false, 0
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
}

func (e *fakeEmulator) GetInfo(context.Context) (*emulatorclient.Info, error) {
	return e.info, e.infoErr
}
func (e *fakeEmulator) SubmitFinalization(
	_ context.Context, _ emulatorclient.Intent, forfeits []string, _ tree.FlatTxTree, commitmentTx string,
) ([]string, string, error) {
	if e.infoErr != nil {
		return nil, "", e.infoErr
	}
	return forfeits, commitmentTx, nil
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

// testEnv is a service wired to fakes, with a user able to build delegate scripts.
type testEnv struct {
	svc      *service
	repo     *fakeRepo
	ark      *fakeArk
	indexer  *fakeIndexer
	emulator *fakeEmulator
	userKey  *btcec.PrivateKey
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
			ForfeitAddress: forfeitAddr.EncodeAddress(),
		}},
		indexer:  &fakeIndexer{txs: map[string]string{}},
		emulator: &fakeEmulator{info: &emulatorclient.Info{SignerPublicKey: emu}},
	}
	env.userKey, _ = hexKey(t)
	for _, f := range tweak {
		f(env)
	}
	key, _ := hexKey(t)
	svc, err := NewService(t.Context(), env.repo, env.ark, env.indexer, env.emulator,
		key, time.Hour, time.Minute, 0, 16, 100)
	require.NoError(t, err)
	env.svc = svc.(*service)
	return env
}

func (e *testEnv) setFees(offchainInput string) {
	e.ark.info.Fees = clientlib.FeeInfo{IntentFees: arkfee.Config{IntentOffchainInputProgram: offchainInput}}
}

// tapscripts builds what a wallet registers: the delegate leaf from Info plus an exit leaf.
func (e *testEnv) tapscripts(t testing.TB, p domain.Params) []string {
	t.Helper()
	info, err := e.svc.Info(p)
	require.NoError(t, err)
	server, err := PubKeyFromHex(info.ServerPubKey)
	require.NoError(t, err)
	tweaked, err := PubKeyFromHex(info.EmulatorTweakedPubKey)
	require.NoError(t, err)
	ts, err := (&script.TapscriptsVtxoScript{Closures: []script.Closure{
		&script.MultisigClosure{PubKeys: []*btcec.PublicKey{server, tweaked}},
		&script.CSVMultisigClosure{
			MultisigClosure: script.MultisigClosure{PubKeys: []*btcec.PublicKey{e.userKey.PubKey()}},
			Locktime:        arklib.RelativeLocktime{Type: arklib.LocktimeTypeSecond, Value: 512},
		},
	}}).Encode()
	require.NoError(t, err)
	require.Contains(t, ts, info.DelegateTapscript)
	return ts
}

func (e *testEnv) register(t testing.TB, p domain.Params) *domain.Delegation {
	t.Helper()
	d, err := e.svc.RegisterDelegation(t.Context(), e.tapscripts(t, p), p)
	require.NoError(t, err)
	return d
}

// vtxo sits at the delegation's script and expires in expiresIn. n makes the
// tx that created it, which the indexer can serve, unique.
func (e *testEnv) vtxo(t testing.TB, d *domain.Delegation, n int, amount uint64, expiresIn time.Duration) clientlib.Vtxo {
	t.Helper()
	pkScript, _, err := e.svc.scriptOf(d)
	require.NoError(t, err)
	funding := wire.NewMsgTx(3)
	funding.AddTxIn(wire.NewTxIn(&wire.OutPoint{Index: uint32(n)}, nil, nil))
	funding.AddTxOut(wire.NewTxOut(int64(amount), pkScript))
	ptx, err := psbt.NewFromUnsignedTx(funding)
	require.NoError(t, err)
	b64, err := ptx.B64Encode()
	require.NoError(t, err)
	txid := funding.TxHash().String()
	e.indexer.mu.Lock()
	e.indexer.txs[txid] = b64
	e.indexer.mu.Unlock()
	return clientlib.Vtxo{
		Outpoint: clientlib.Outpoint{Txid: txid, VOut: 0}, Script: hex.EncodeToString(pkScript), Amount: amount,
		CreatedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(expiresIn),
	}
}

var errBoom = errors.New("boom")

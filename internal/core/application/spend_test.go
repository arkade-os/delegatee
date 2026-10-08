package application

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestRegisterSpend(t *testing.T) {
	e := newTestEnv(t)
	req := e.spendRequest(t)
	d, err := req.register(t, e)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusActive, d.Status)
	require.Empty(t, d.Address)
	require.Zero(t, d.ParentID)
	require.True(t, d.IsSpend())
	require.Equal(t, req.expiresAt.Unix(), d.ExpiresAt.Unix())
	require.Equal(t, req.outpoints, []string{d.Slots[0].Outpoint, d.Slots[1].Outpoint})

	got, err := e.svc.GetSpend(t.Context(), d.Fingerprint)
	require.NoError(t, err)
	require.Equal(t, d.ID, got.ID)
	again, err := req.register(t, e)
	require.NoError(t, err)
	require.Equal(t, d.ID, again.ID, "registering again returns the active spend")

	watch := e.renewal(t, e.userKey.PubKey(), 0)
	_, err = e.svc.GetSpend(t.Context(), watch.Fingerprint)
	require.ErrorIs(t, err, domain.ErrDelegationNotFound, "a watch is no spend")
}

func TestRegisterSpendRefusals(t *testing.T) {
	stranger, _ := btcec.NewPrivateKey()
	for name, tc := range map[string]struct {
		edit func(t *testing.T, e *testEnv, r *spendRequest)
		err  error
	}{
		"bad signature": {edit: func(_ *testing.T, _ *testEnv, r *spendRequest) { r.signature = r.signature[64:] + r.signature[:64] }},
		"signature over another expiry": {edit: func(t *testing.T, e *testEnv, r *spendRequest) {
			r.expiresAt = r.expiresAt.Add(time.Minute)
		}},
		"key of no exit leaf": {edit: func(t *testing.T, e *testEnv, r *spendRequest) { r.sign(t, stranger) }},
		"too few outpoints":   {edit: func(t *testing.T, e *testEnv, r *spendRequest) { r.outpoints = r.outpoints[:1]; r.sign(t, e.userKey) }},
		"outpoint twice": {edit: func(t *testing.T, e *testEnv, r *spendRequest) {
			r.outpoints[1] = r.outpoints[0]
			r.sign(t, e.userKey)
		}},
		"outpoint spelling": {edit: func(t *testing.T, e *testEnv, r *spendRequest) {
			r.outpoints[0] = r.outpoints[0] + "0"
			r.sign(t, e.userKey)
		}},
		"outpoint of another script": {edit: func(t *testing.T, e *testEnv, r *spendRequest) {
			r.outpoints[1] = e.coin(t, e.userKey.PubKey(), 5000, time.Hour).Outpoint.String()
			r.sign(t, e.userKey)
		}, err: ErrIneligible},
		"expired": {edit: func(t *testing.T, e *testEnv, r *spendRequest) {
			r.expiresAt = time.Now().Add(-time.Second)
			r.sign(t, e.userKey)
		}},
		"beyond a day": {edit: func(t *testing.T, e *testEnv, r *spendRequest) {
			r.expiresAt = time.Now().Add(25 * time.Hour)
			r.sign(t, e.userKey)
		}},
		"outpoint bound by another spend": {edit: func(t *testing.T, e *testEnv, r *spendRequest) {
			other := *r
			other.variables = map[string]string{"owner": r.variables["owner"], "amount": hex.EncodeToString(scriptNum(12_000))}
			other.sign(t, e.userKey)
			_, err := other.register(t, e)
			require.NoError(t, err)
		}, err: domain.ErrDelegationAlreadyExists},
	} {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			r := e.spendRequest(t)
			tc.edit(t, e, &r)
			_, err := r.register(t, e)
			want := tc.err
			if want == nil {
				want = ErrInvalidArgs
			}
			require.ErrorIs(t, err, want)
		})
	}
}

func TestSpendGoesAtOnce(t *testing.T) {
	e := newTestEnv(t)
	r := e.spendRequest(t)
	d, err := r.register(t, e)
	require.NoError(t, err)
	e.scan(t)
	var found bool
	for _, entry := range e.svc.entries {
		if entry.delegation == d.ID {
			found = true
			require.False(t, entry.deadline.After(time.Now()), "a spend does not wait for its coins' expiry")
		}
	}
	require.True(t, found)
}

// a spend must not stall a watch's claim
func TestWatchKeepsCoinsASpendBinds(t *testing.T) {
	e := newTestEnv(t)
	watch := e.renewal(t, e.userKey.PubKey(), 0)
	coin := e.coin(t, e.userKey.PubKey(), 5000, time.Minute)
	e.indexer.serve(coin)
	r := spendRequest{
		template: watch.TemplateID, variables: renewalVars(e.userKey.PubKey(), 0),
		outpoints: []string{coin.Outpoint.String()}, expiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
	}
	r.sign(t, e.userKey)
	_, err := r.register(t, e)
	require.NoError(t, err)

	_, _, inputs, err := e.svc.discover(t.Context(), e.active(t), map[string]struct{}{watch.TemplateID: {}}, time.Now())
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Equal(t, watch.ID, inputs[0].watched.delegation.ID)
}

type spendRequest struct {
	template  string
	variables map[string]string
	outpoints []string
	expiresAt time.Time
	pubkey    string
	signature string
}

func (r *spendRequest) register(t *testing.T, e *testEnv) (*domain.Delegation, error) {
	return e.svc.RegisterSpend(t.Context(), r.template, r.variables, r.outpoints, r.expiresAt, r.pubkey, r.signature)
}

func (r *spendRequest) sign(t *testing.T, key *btcec.PrivateKey) {
	sig, err := schnorr.Sign(key, spendMessage(domain.Fingerprint(r.template, r.variables, r.outpoints), r.expiresAt))
	require.NoError(t, err)
	r.pubkey = hex.EncodeToString(schnorr.SerializePubKey(key.PubKey()))
	r.signature = hex.EncodeToString(sig.Serialize())
}

// spendRequest pays 15,000 from two coins of 10,000.
func (e *testEnv) spendRequest(t *testing.T) spendRequest {
	t.Helper()
	owner := hex.EncodeToString(e.userKey.PubKey().SerializeCompressed())
	script := e.contract(t, pooledSpend, 0, map[string]string{"owner": owner})
	a := e.vtxoAt(t, script, 10_000, 30*24*time.Hour)
	b := e.vtxoAt(t, script, 10_000, 30*24*time.Hour)
	e.indexer.serve(a, b)
	r := spendRequest{
		template:  e.fixture(t, pooledSpend),
		variables: map[string]string{"owner": owner, "amount": hex.EncodeToString(scriptNum(15_000))},
		outpoints: []string{a.Outpoint.String(), b.Outpoint.String()},
		expiresAt: time.Now().Add(time.Hour).Truncate(time.Second),
	}
	r.sign(t, e.userKey)
	return r
}

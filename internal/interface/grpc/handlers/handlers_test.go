package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/arkd/pkg/client-lib/types"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

// fakeService returns canned values, or err from every call that can fail.
type fakeService struct {
	application.Service
	err        error
	delegation domain.Delegation
	gotParams  domain.Params
	gotScripts []string
	cancelled  string
	feesErr    error
	health     map[string]error
}

var (
	t0      = time.Unix(1_700_000_000, 0)
	errBoom = errors.New("boom")
)

func (f *fakeService) Info(p domain.Params) (application.Info, error) {
	f.gotParams = p
	return application.Info{Network: "regtest", DelegatePubKey: "02aa", DelegateTapscript: "20ac", Params: p}, f.err
}
func (f *fakeService) RegisterDelegation(_ context.Context, ts []string, p domain.Params) (*domain.Delegation, error) {
	f.gotScripts, f.gotParams = ts, p
	return &f.delegation, f.err
}
func (f *fakeService) GetDelegation(context.Context, string) (*domain.Delegation, error) {
	return &f.delegation, f.err
}
func (f *fakeService) ListDelegations(context.Context) ([]domain.Delegation, error) {
	return []domain.Delegation{f.delegation, {ID: 8, Address: "tark1other", Status: "cancelled"}}, f.err
}
func (f *fakeService) RevokeDelegation(_ context.Context, address, pubkey, sig string, ts int64) error {
	f.cancelled = address + "/" + pubkey + "/" + sig
	return f.err
}
func (f *fakeService) CancelDelegation(_ context.Context, address string) error {
	f.cancelled = address
	return f.err
}
func (f *fakeService) Vtxos(context.Context, *domain.Delegation) ([]types.Vtxo, error) {
	return []types.Vtxo{{
		Outpoint: types.Outpoint{Txid: "ab", VOut: 1}, Amount: 5000, CreatedAt: t0, ExpiresAt: t0.Add(time.Hour),
		Preconfirmed: true, Assets: []types.Asset{{AssetId: "gold", Amount: 3}},
	}}, nil
}
func (f *fakeService) DueAt(_ *domain.Delegation, v types.Vtxo) time.Time {
	return v.ExpiresAt.Add(-10 * time.Minute)
}
func (f *fakeService) ListRenewals(context.Context, *domain.Delegation) ([]domain.Renewal, error) {
	return []domain.Renewal{{Outpoints: []string{"ab:1"}, Error: "nope", AttemptedAt: t0}}, nil
}
func (f *fakeService) LastRenewals(context.Context) (map[int64]domain.Renewal, error) {
	return map[int64]domain.Renewal{7: {Success: true, CommitmentTxid: "cc", AttemptedAt: t0}}, f.err
}
func (f *fakeService) Status() application.Status {
	return application.Status{
		LastScan: t0, RenewingVtxos: 2, PollInterval: time.Minute,
		Holdings: map[int64]application.Holdings{7: {Vtxos: 2, Amount: 9000, NextExpiry: t0.Add(time.Hour), NextDue: t0}},
	}
}
func (f *fakeService) IntentFees(context.Context) (arkfee.Config, error) {
	return arkfee.Config{IntentOffchainInputProgram: "200.0"}, f.feesErr
}
func (f *fakeService) Health(context.Context) map[string]error { return f.health }

func newFake() *fakeService {
	return &fakeService{delegation: domain.Delegation{
		ID: 7, Address: "tark1mine", Tapscripts: []string{"20ac"}, Status: "active",
		Params: domain.Params{RenewalWindow: 600, MaxFee: 50}, CreatedAt: t0, UpdatedAt: t0.Add(time.Second),
	}}
}

func TestPublicHandlers(t *testing.T) {
	ctx := t.Context()
	svc := newFake()
	h := New("v1.2.3", svc)

	info, err := h.GetInfo(ctx, &delegateev1.GetInfoRequest{RenewalWindow: 600, MaxFee: 50})
	require.NoError(t, err)
	require.Equal(t, domain.Params{RenewalWindow: 600, MaxFee: 50}, svc.gotParams)
	require.Equal(t, "v1.2.3", info.GetVersion())
	require.Equal(t, "regtest", info.GetNetwork())
	require.Equal(t, int64(600), info.GetRenewalWindow())
	require.Equal(t, int64(50), info.GetMaxFee())
	require.Equal(t, "20ac", info.GetDelegateTapscript())

	_, err = h.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	reg, err := h.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: []string{"20ac"}, RenewalWindow: 9, MaxFee: 1})
	require.NoError(t, err)
	require.Equal(t, []string{"20ac"}, svc.gotScripts)
	require.Equal(t, domain.Params{RenewalWindow: 9, MaxFee: 1}, svc.gotParams)
	d := reg.GetDelegation()
	require.Equal(t, "tark1mine", d.GetAddress())
	require.Equal(t, int64(600), d.GetRenewalWindow())
	require.Equal(t, int64(50), d.GetMaxFee())
	require.Equal(t, t0.Unix(), d.GetCreatedAt())
	require.Equal(t, t0.Unix()+1, d.GetUpdatedAt())

	_, err = h.GetDelegation(ctx, &delegateev1.GetDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = h.RevokeDelegation(ctx, &delegateev1.RevokeDelegationRequest{Address: "a", Pubkey: "p"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.RevokeDelegation(ctx, &delegateev1.RevokeDelegationRequest{Address: "a", Pubkey: "p", Signature: "s", Timestamp: 1})
	require.NoError(t, err)
	require.Equal(t, "a/p/s", svc.cancelled)
	detail, err := h.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: "tark1mine"})
	require.NoError(t, err)
	require.Len(t, detail.GetVtxos(), 1)
	v := detail.GetVtxos()[0]
	require.Equal(t, "ab:1", v.GetOutpoint())
	require.Equal(t, uint64(5000), v.GetAmount())
	require.True(t, v.GetPreconfirmed())
	require.Equal(t, t0.Unix(), v.GetCreatedAt())
	require.Equal(t, t0.Add(50*time.Minute).Unix(), v.GetRenewableAt())
	require.Equal(t, "gold", v.GetAssets()[0].GetAssetId())
	require.Equal(t, "nope", detail.GetRenewals()[0].GetError())
	require.False(t, detail.GetRenewals()[0].GetSuccess())
}

func TestAdminHandlers(t *testing.T) {
	ctx := t.Context()
	svc := newFake()
	h := NewAdmin(svc)

	list, err := h.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetDelegations(), 2)
	mine, other := list.GetDelegations()[0], list.GetDelegations()[1]
	require.True(t, mine.GetManaged())
	require.Empty(t, mine.GetTapscripts(), "the list stays light")
	require.Equal(t, int32(2), mine.GetVtxoCount())
	require.Equal(t, uint64(9000), mine.GetTotalAmount())
	require.Equal(t, t0.Add(time.Hour).Unix(), mine.GetNextExpiry())
	require.Equal(t, t0.Unix(), mine.GetNextRenewalAt())
	require.Equal(t, "cc", mine.GetLastRenewal().GetCommitmentTxid())
	require.False(t, other.GetManaged(), "not seen by the scanner")
	require.Nil(t, other.GetLastRenewal())
	require.Zero(t, other.GetNextExpiry())

	st, err := h.GetStatus(ctx, &delegateev1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, t0.Unix(), st.GetLastScanAt())
	require.Equal(t, int32(2), st.GetRenewingVtxos())
	require.Equal(t, int64(60), st.GetPollInterval())
	require.Equal(t, "200.0", st.GetIntentFees().GetOffchainInput())
	// arkd down: the status still answers, without fees
	svc.feesErr = errBoom
	st, err = h.GetStatus(ctx, &delegateev1.GetStatusRequest{})
	require.NoError(t, err)
	require.Nil(t, st.GetIntentFees())

	_, err = h.CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Address: "tark1mine"})
	require.NoError(t, err)
	require.Equal(t, "tark1mine", svc.cancelled)
}

func TestErrorsMapToStatusCodes(t *testing.T) {
	ctx := t.Context()
	for err, want := range map[error]codes.Code{
		domain.ErrDelegationNotFound:      codes.NotFound,
		domain.ErrDelegationAlreadyExists: codes.AlreadyExists,
		application.ErrFull:               codes.ResourceExhausted,
		application.ErrInvalidScript:      codes.InvalidArgument,
		application.ErrInvalidSignature:   codes.PermissionDenied,
		errBoom:                           codes.Internal,
	} {
		svc := newFake()
		svc.err = err
		_, got := New("v", svc).RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{Tapscripts: []string{"00"}})
		require.Equal(t, want, status.Code(got), err)
		if want == codes.Internal {
			require.NotContains(t, got.Error(), "boom", "internals stay internal")
		}
		_, got = New("v", svc).GetInfo(ctx, &delegateev1.GetInfoRequest{})
		require.Equal(t, want, status.Code(got))
		_, got = New("v", svc).GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: "a"})
		require.Equal(t, want, status.Code(got))
		_, got = New("v", svc).RevokeDelegation(ctx, &delegateev1.RevokeDelegationRequest{Address: "a", Pubkey: "p", Signature: "s"})
		require.Equal(t, want, status.Code(got))
		_, got = NewAdmin(svc).ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
		require.Equal(t, want, status.Code(got))
		_, got = NewAdmin(svc).CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Address: "a"})
		require.Equal(t, want, status.Code(got))
	}
}

func TestHealth(t *testing.T) {
	svc := newFake()
	svc.health = map[string]error{"database": nil, "ark": nil}
	h := NewHealthHandler(svc)
	resp, err := h.Check(t.Context(), &grpchealth.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpchealth.HealthCheckResponse_SERVING, resp.GetStatus())

	require.Equal(t, codes.Unimplemented, status.Code(h.Watch(nil, nil)))

	svc.health["ark"] = errBoom
	resp, err = h.Check(t.Context(), &grpchealth.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, grpchealth.HealthCheckResponse_NOT_SERVING, resp.GetStatus())
}

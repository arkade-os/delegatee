package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/arkade-os/delegatee/internal/core/application"
	"github.com/arkade-os/delegatee/internal/core/domain"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpchealth "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

func TestPublicHandlers(t *testing.T) {
	ctx := t.Context()
	svc := newFake()
	h := New("v1.2.3", svc)

	info, err := h.GetInfo(ctx, &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, "v1.2.3", info.GetVersion())
	require.Equal(t, "regtest", info.GetNetwork())
	require.Equal(t, "02aa", info.GetDelegatePubkey())
	require.Equal(t, "02bb", info.GetServerPubkey())
	require.Equal(t, "02cc", info.GetEmulatorPubkey())
	require.Equal(t, "02dd", info.GetEncryptionPubkey())

	_, err = h.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: "tmpl1", ExpiresAt: -1})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	reg, err := h.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: "tmpl1", Variables: map[string]string{"owner": "02aa"}})
	require.NoError(t, err)
	require.Equal(t, "tmpl1", svc.gotTemplate)
	require.Equal(t, map[string]string{"owner": "02aa"}, svc.gotVariables)
	require.Nil(t, svc.gotExpiresAt, "0 never expires")
	d := reg.GetDelegation()
	require.Equal(t, "tark1mine", d.GetAddress())
	require.Equal(t, "tmpl1", d.GetTemplateId())
	require.Equal(t, map[string]string{"owner": "02aa"}, d.GetVariables())
	require.EqualValues(t, 3, d.GetParentId())
	require.Equal(t, t0.Add(time.Hour).Unix(), d.GetExpiresAt())
	require.Len(t, d.GetSlots(), 1)
	require.Equal(t, "funds", d.GetSlots()[0].GetName())
	require.Equal(t, []string{"20ac"}, d.GetSlots()[0].GetTapscripts())
	require.Equal(t, t0.Unix(), d.GetCreatedAt())
	require.Equal(t, t0.Unix()+1, d.GetUpdatedAt())
	_, err = h.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: "tmpl1", ExpiresAt: t0.Unix()})
	require.NoError(t, err)
	require.Equal(t, map[string]string{}, svc.gotVariables, "no variables is an empty map")
	require.Equal(t, t0, *svc.gotExpiresAt)

	_, err = h.GetDelegation(ctx, &delegateev1.GetDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	detail, err := h.GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: "tark1mine"})
	require.NoError(t, err)
	require.Equal(t, "tmpl1", detail.GetDelegation().GetTemplateId())
	require.Equal(t, map[string]string{"owner": "02aa"}, detail.GetDelegation().GetVariables())
	require.Len(t, detail.GetVtxos(), 1)
	v := detail.GetVtxos()[0]
	require.Equal(t, "ab:1", v.GetOutpoint())
	require.Equal(t, uint64(5000), v.GetAmount())
	require.True(t, v.GetPreconfirmed())
	require.Equal(t, t0.Unix(), v.GetCreatedAt())
	require.Equal(t, t0.Add(59*time.Minute).Unix(), v.GetRenewableAt())
	require.Equal(t, "gold", v.GetAssets()[0].GetAssetId())
	require.Equal(t, "nope", detail.GetRenewals()[0].GetError())
	require.False(t, detail.GetRenewals()[0].GetSuccess())
}

func TestTemplateHandlers(t *testing.T) {
	ctx := t.Context()
	svc := newFake()
	h := New("v", svc)
	admin := NewAdmin(svc)

	_, err := h.RegisterTemplate(ctx, &delegateev1.RegisterTemplateRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	created, err := h.RegisterTemplate(ctx, &delegateev1.RegisterTemplateRequest{Document: `{"format":"x"}`})
	require.NoError(t, err)
	require.Equal(t, "tmpl1", created.GetTemplate().GetId())
	require.Equal(t, `{"format":"x"}`, created.GetTemplate().GetDocument())
	require.Equal(t, "active", created.GetTemplate().GetStatus())
	require.Equal(t, "owner", created.GetTemplate().GetParams()[0].GetName())

	got, err := h.GetTemplate(ctx, &delegateev1.GetTemplateRequest{Id: "tmpl1"})
	require.NoError(t, err)
	require.Equal(t, `{"format":"x"}`, got.GetTemplate().GetDocument())
	_, err = h.GetTemplate(ctx, &delegateev1.GetTemplateRequest{Id: "nope"})
	require.Equal(t, codes.NotFound, status.Code(err))

	list, err := h.ListTemplates(ctx, &delegateev1.ListTemplatesRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetTemplates(), 1)
	require.Empty(t, list.GetTemplates()[0].GetDocument(), "lists omit documents")
	require.Equal(t, "active", svc.listedStatus, "the public list is always the active one")

	adminList, err := admin.ListAllTemplates(ctx, &delegateev1.ListAllTemplatesRequest{Status: "disabled"})
	require.NoError(t, err)
	require.Equal(t, "disabled", svc.listedStatus)
	require.Equal(t, int64(2), adminList.GetTemplates()[0].GetDelegations())
	require.Equal(t, int32(1), adminList.GetTemplates()[0].GetFailures())
	require.False(t, adminList.GetTemplates()[0].GetTrusted())

	_, err = admin.SetTemplateTrusted(ctx, &delegateev1.SetTemplateTrustedRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.SetTemplateTrusted(ctx, &delegateev1.SetTemplateTrustedRequest{Id: "nope", Trusted: true})
	require.Equal(t, codes.NotFound, status.Code(err))
	trusted, err := admin.SetTemplateTrusted(ctx, &delegateev1.SetTemplateTrustedRequest{Id: "tmpl1", Trusted: true})
	require.NoError(t, err)
	require.True(t, trusted.GetTemplate().GetTrusted())
	require.Equal(t, int64(2), trusted.GetTemplate().GetDelegations())

	setStatus, err := admin.SetTemplateStatus(ctx, &delegateev1.SetTemplateStatusRequest{Id: "tmpl1", Status: "disabled"})
	require.NoError(t, err)
	require.Equal(t, "disabled", svc.statusSet)
	require.Equal(t, int64(2), setStatus.GetTemplate().GetDelegations())
	require.Equal(t, int32(1), setStatus.GetTemplate().GetFailures())
	_, err = admin.SetTemplateStatus(ctx, &delegateev1.SetTemplateStatusRequest{Id: "tmpl1", Status: "weird"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	svc.inUse = true
	_, err = admin.DeleteTemplate(ctx, &delegateev1.DeleteTemplateRequest{Id: "tmpl1"})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	svc.inUse = false
	_, err = admin.DeleteTemplate(ctx, &delegateev1.DeleteTemplateRequest{Id: "tmpl1"})
	require.NoError(t, err)

	_, err = h.RegisterArtifact(ctx, &delegateev1.RegisterArtifactRequest{Document: "{}"})
	require.NoError(t, err)
	a, err := h.GetArtifact(ctx, &delegateev1.GetArtifactRequest{Id: "art1"})
	require.NoError(t, err)
	require.Equal(t, "{}", a.GetArtifact().GetDocument())
	artifacts, err := admin.ListArtifacts(ctx, &delegateev1.ListArtifactsRequest{})
	require.NoError(t, err)
	require.Len(t, artifacts.GetArtifacts(), 1)
	require.Equal(t, "art1", artifacts.GetArtifacts()[0].GetId())
	require.Empty(t, artifacts.GetArtifacts()[0].GetDocument(), "lists omit documents")
	_, err = admin.DeleteArtifact(ctx, &delegateev1.DeleteArtifactRequest{Id: "art1"})
	require.NoError(t, err)
	svc.full = true
	_, err = h.RegisterArtifact(ctx, &delegateev1.RegisterArtifactRequest{Document: "{}"})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
	svc.invalid = true
	_, err = h.RegisterTemplate(ctx, &delegateev1.RegisterTemplateRequest{Document: "zz"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAdminHandlers(t *testing.T) {
	ctx := t.Context()
	svc := newFake()
	h := NewAdmin(svc)

	list, err := h.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetDelegations(), 2)
	mine, other := list.GetDelegations()[0], list.GetDelegations()[1]
	require.Equal(t, "tark1mine", mine.GetDelegation().GetAddress())
	require.True(t, mine.GetManaged())
	require.Len(t, mine.GetDelegation().GetSlots(), 1)
	require.Equal(t, "funds", mine.GetDelegation().GetSlots()[0].GetName())
	require.Empty(t, mine.GetDelegation().GetSlots()[0].GetTapscripts(), "the list stays light")
	require.EqualValues(t, 3, mine.GetDelegation().GetParentId())
	require.Equal(t, int32(2), mine.GetVtxoCount())
	require.Equal(t, uint64(9000), mine.GetTotalAmount())
	require.Equal(t, t0.Add(time.Hour).Unix(), mine.GetNextExpiry())
	require.Equal(t, t0.Unix(), mine.GetNextRenewalAt())
	require.Equal(t, "cc", mine.GetLastRenewal().GetCommitmentTxid())
	require.False(t, other.GetManaged(), "not seen by the scanner")
	require.Equal(t, "template disabled", other.GetUnmanagedReason())
	require.Empty(t, mine.GetUnmanagedReason())
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
	_, err = h.CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Id: 7, Address: "ignored"})
	require.NoError(t, err)
	require.Equal(t, int64(7), svc.cancelledID, "an id takes precedence")
	require.Equal(t, "tark1mine", svc.cancelled)

	_, err = h.ResumeDelegation(ctx, &delegateev1.ResumeDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.ResumeDelegation(ctx, &delegateev1.ResumeDelegationRequest{Id: 7})
	require.NoError(t, err)
	require.Equal(t, int64(7), svc.resumed)
}

func TestListDelegationsPages(t *testing.T) {
	ctx := t.Context()
	svc := newFake()
	h := NewAdmin(svc)
	page, err := h.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
	require.Equal(t, [3]any{"", int64(0), 101}, svc.listed, "one more than the default size tells whether a page follows")
	require.Zero(t, page.GetNextCursor(), "two rows: the last page")

	page, err = h.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{PageSize: 1, Cursor: 9, Status: "active"})
	require.NoError(t, err)
	require.Equal(t, [3]any{"active", int64(9), 2}, svc.listed)
	require.Len(t, page.GetDelegations(), 1)
	require.Equal(t, int64(7), page.GetNextCursor())

	_, err = h.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{PageSize: 5000})
	require.NoError(t, err)
	require.Equal(t, 1001, svc.listed[2], "capped")
	_, err = h.ListDelegations(ctx, &delegateev1.ListDelegationsRequest{PageSize: -1})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAdminMutationIsLogged(t *testing.T) {
	logs := logtest.NewGlobal()
	svc := newFake()
	_, err := New("v", svc).RegisterTemplate(t.Context(), &delegateev1.RegisterTemplateRequest{Document: `{}`})
	require.NoError(t, err)
	require.Empty(t, logs.AllEntries(), "a public call is not logged")

	_, err = NewAdmin(svc).SetTemplateStatus(WithAdmin(t.Context(), "op"), &delegateev1.SetTemplateStatusRequest{Id: "tmpl1", Status: "disabled"})
	require.NoError(t, err)
	require.Equal(t, log.Fields{"admin": "op", "action": "set template status", "target": "tmpl1", "before": "active", "after": "disabled"},
		logs.LastEntry().Data)
	require.Equal(t, log.InfoLevel, logs.LastEntry().Level)
}

func TestErrorsMapToStatusCodes(t *testing.T) {
	ctx := t.Context()
	for err, want := range map[error]codes.Code{
		domain.ErrDelegationNotFound:      codes.NotFound,
		domain.ErrDelegationAlreadyExists: codes.AlreadyExists,
		application.ErrFull:               codes.ResourceExhausted,
		domain.ErrTemplateNotFound:        codes.NotFound,
		domain.ErrTemplateDisabled:        codes.FailedPrecondition,
		domain.ErrBlocked:                 codes.FailedPrecondition,
		domain.ErrNotCancelled:            codes.FailedPrecondition,
		application.ErrInvalidArgs:        codes.InvalidArgument,
		application.ErrIneligible:         codes.FailedPrecondition,
		application.ErrUnsupported:        codes.FailedPrecondition,
		application.ErrSecretsRequired:    codes.FailedPrecondition,
		errBoom:                           codes.Internal,
	} {
		svc := newFake()
		svc.err = err
		_, got := New("v", svc).RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: "tmpl1", Variables: map[string]string{"owner": "00"}})
		require.Equal(t, want, status.Code(got), err)
		if want == codes.Internal {
			require.NotContains(t, got.Error(), "boom", "internals stay internal")
		}
		_, got = New("v", svc).GetDelegation(ctx, &delegateev1.GetDelegationRequest{Address: "a"})
		require.Equal(t, want, status.Code(got))
		_, got = NewAdmin(svc).ListDelegations(ctx, &delegateev1.ListDelegationsRequest{})
		require.Equal(t, want, status.Code(got))
		_, got = NewAdmin(svc).CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Address: "a"})
		require.Equal(t, want, status.Code(got))
		_, got = NewAdmin(svc).CancelDelegation(ctx, &delegateev1.CancelDelegationRequest{Id: 1})
		require.Equal(t, want, status.Code(got))
	}
}

func TestOnchainCoinHasNoExpiry(t *testing.T) {
	created := time.Unix(1_790_000_000, 0)
	out := toVtxos([]clientlib.Vtxo{{CreatedAt: created}}, []time.Time{{}})
	require.Zero(t, out[0].ExpiresAt)
	require.Zero(t, out[0].RenewableAt)
	require.Equal(t, created.Unix(), out[0].CreatedAt)
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

var (
	t0      = time.Unix(1_700_000_000, 0)
	errBoom = errors.New("boom")
)

// fakeService returns canned values, or err from every call that can fail.
type fakeService struct {
	application.Service
	err          error
	delegation   domain.Delegation
	gotTemplate  string
	gotVariables map[string]string
	gotExpiresAt *time.Time
	cancelled    string
	cancelledID  int64
	resumed      int64
	listed       [3]any
	feesErr      error
	health       map[string]error

	templates    map[string]*domain.Template
	artifacts    map[string]*domain.Artifact
	statusSet    string
	listedStatus string
	inUse        bool
	full         bool
	invalid      bool
}

func (f *fakeService) Info() application.Info {
	return application.Info{
		Network: "regtest", DelegatePubKey: "02aa", ServerPubKey: "02bb", EmulatorPubKey: "02cc",
		EncryptionPubKey: "02dd",
	}
}
func (f *fakeService) RegisterDelegation(
	_ context.Context, templateID string, variables map[string]string, expiresAt *time.Time,
) (*domain.Delegation, error) {
	f.gotTemplate, f.gotVariables, f.gotExpiresAt = templateID, variables, expiresAt
	return &f.delegation, f.err
}
func (f *fakeService) GetDelegationByID(ctx context.Context, _ int64) (*domain.Delegation, error) {
	return f.GetDelegation(ctx, "")
}
func (f *fakeService) GetDelegation(context.Context, string) (*domain.Delegation, error) {
	return &f.delegation, f.err
}
func (f *fakeService) RenewableAt(_ context.Context, _ *domain.Delegation, vtxos []clientlib.Vtxo) ([]time.Time, error) {
	due := make([]time.Time, len(vtxos))
	for i, v := range vtxos {
		due[i] = v.ExpiresAt.Add(-time.Minute)
	}
	return due, nil
}
func (f *fakeService) ListDelegations(_ context.Context, status string, cursor int64, limit int) ([]domain.Delegation, error) {
	f.listed = [3]any{status, cursor, limit}
	all := []domain.Delegation{f.delegation, {ID: 8, Fingerprint: "fp8", Address: "tark1other", Status: "cancelled"}}
	return all[:min(limit, len(all))], f.err
}
func (f *fakeService) ResumeDelegation(_ context.Context, id int64) error {
	f.resumed = id
	return f.err
}
func (f *fakeService) CancelDelegation(_ context.Context, address string) error {
	f.cancelled = address
	return f.err
}
func (f *fakeService) CancelDelegationByID(_ context.Context, id int64) error {
	f.cancelledID = id
	return f.err
}
func (f *fakeService) Vtxos(context.Context, *domain.Delegation) ([]clientlib.Vtxo, error) {
	return []clientlib.Vtxo{{
		Outpoint: clientlib.Outpoint{Txid: "ab", VOut: 1}, Amount: 5000, CreatedAt: t0, ExpiresAt: t0.Add(time.Hour),
		Preconfirmed: true, Assets: []clientlib.Asset{{AssetId: "gold", Amount: 3}},
	}}, nil
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
		Holdings:  map[int64]application.Holdings{7: {Vtxos: 2, Amount: 9000, NextExpiry: t0.Add(time.Hour), NextDue: t0}},
		Unwatched: map[int64]string{8: "template disabled"},
	}
}
func (f *fakeService) IntentFees(context.Context) (arkfee.Config, error) {
	return arkfee.Config{IntentOffchainInputProgram: "200.0"}, f.feesErr
}
func (f *fakeService) Health(context.Context) map[string]error { return f.health }

func (f *fakeService) RegisterArtifact(_ context.Context, doc []byte) (*domain.Artifact, error) {
	if f.full {
		return nil, application.ErrFull
	}
	a := &domain.Artifact{ID: "art1", Document: doc}
	f.artifacts["art1"] = a
	return a, nil
}

func (f *fakeService) GetArtifact(_ context.Context, id string) (*domain.Artifact, error) {
	a, ok := f.artifacts[id]
	if !ok {
		return nil, domain.ErrArtifactNotFound
	}
	return a, nil
}

func (f *fakeService) ListArtifacts(context.Context) ([]domain.Artifact, error) {
	out := make([]domain.Artifact, 0, len(f.artifacts))
	for _, a := range f.artifacts {
		out = append(out, domain.Artifact{ID: a.ID, CreatedAt: a.CreatedAt}) // lists omit documents
	}
	return out, nil
}

func (f *fakeService) DeleteArtifact(_ context.Context, id string) error {
	delete(f.artifacts, id)
	return nil
}

func (f *fakeService) RegisterTemplate(_ context.Context, doc []byte) (*domain.Template, error) {
	if f.invalid {
		return nil, application.ErrInvalidDocument
	}
	t := &domain.Template{
		ID: "tmpl1", Document: doc, Params: []domain.Param{{Name: "owner", Type: "pubkey"}},
		Status: "active", Failures: 1,
	}
	f.templates["tmpl1"] = t
	return t, nil
}

func (f *fakeService) GetTemplate(_ context.Context, id string) (*domain.Template, error) {
	t, ok := f.templates[id]
	if !ok {
		return nil, domain.ErrTemplateNotFound
	}
	return t, nil
}

func (f *fakeService) ListTemplates(_ context.Context, status string) ([]domain.Template, error) {
	f.listedStatus = status
	out := make([]domain.Template, 0, len(f.templates))
	for _, t := range f.templates {
		out = append(out, *t)
	}
	return out, nil
}

func (f *fakeService) SetTemplateStatus(_ context.Context, id, status string) error {
	if status != "active" && status != "disabled" {
		return application.ErrInvalidStatus
	}
	t, ok := f.templates[id]
	if !ok {
		return domain.ErrTemplateNotFound
	}
	t.Status = status
	f.statusSet = status
	return nil
}

func (f *fakeService) SetTemplateTrusted(_ context.Context, id string, trusted bool) error {
	t, ok := f.templates[id]
	if !ok {
		return domain.ErrTemplateNotFound
	}
	t.Trusted = trusted
	return nil
}

func (f *fakeService) DeleteTemplate(_ context.Context, id string) error {
	if f.inUse {
		return domain.ErrTemplateInUse
	}
	delete(f.templates, id)
	return nil
}

func (f *fakeService) DelegationsByTemplate(context.Context) (map[string]int64, error) {
	return map[string]int64{"tmpl1": 2}, nil
}

func newFake() *fakeService {
	expiry := t0.Add(time.Hour)
	return &fakeService{
		delegation: domain.Delegation{
			ID: 7, Fingerprint: "fp7", Address: "tark1mine", Status: "active", ParentID: 3, ExpiresAt: &expiry,
			Slots:      []domain.SlotBinding{{Name: "funds", Tapscripts: []string{"20ac"}, Script: "5120aa"}},
			TemplateID: "tmpl1", Variables: map[string]string{"owner": "02aa"}, CreatedAt: t0, UpdatedAt: t0.Add(time.Second),
		},
		templates: map[string]*domain.Template{},
		artifacts: map[string]*domain.Artifact{},
	}
}

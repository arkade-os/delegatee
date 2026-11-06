package handlers

import (
	"context"
	"errors"
	"testing"
	"time"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	delegationapp "github.com/arkade-os/delegatee/internal/core/application/delegation"
	executionapp "github.com/arkade-os/delegatee/internal/core/application/execution"
	"github.com/arkade-os/delegatee/internal/core/application/health"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/domain/execution"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestUpdateTemplate(t *testing.T) {
	admin, public := testAdmin(t)
	id := registerDefault(t, public)

	_, err := admin.UpdateTemplate(t.Context(), &delegateev1.UpdateTemplateRequest{Id: id, Status: "disabled"})
	require.NoError(t, err)
	active, err := public.ListTemplates(t.Context(), &delegateev1.ListTemplatesRequest{Status: "active"})
	require.NoError(t, err)
	require.Empty(t, active.GetTemplates())
	all, err := public.ListTemplates(t.Context(), &delegateev1.ListTemplatesRequest{})
	require.NoError(t, err)
	require.Len(t, all.GetTemplates(), 1)
	require.Equal(t, "disabled", all.GetTemplates()[0].GetStatus())
	require.Empty(t, all.GetTemplates()[0].GetDocument())

	_, err = admin.UpdateTemplate(t.Context(), &delegateev1.UpdateTemplateRequest{Id: id, Status: "active"})
	require.NoError(t, err)
	got, err := public.GetTemplate(t.Context(), &delegateev1.GetTemplateRequest{Id: id})
	require.NoError(t, err)
	require.Equal(t, "active", got.GetTemplate().GetStatus())
}

func TestUpdateTemplateErrors(t *testing.T) {
	admin, public := testAdmin(t)
	id := registerDefault(t, public)

	_, err := admin.UpdateTemplate(t.Context(), &delegateev1.UpdateTemplateRequest{Status: "active"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.UpdateTemplate(t.Context(), &delegateev1.UpdateTemplateRequest{Id: id})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.UpdateTemplate(t.Context(), &delegateev1.UpdateTemplateRequest{Id: id, Status: "paused"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.UpdateTemplate(t.Context(), &delegateev1.UpdateTemplateRequest{Id: "missing", Status: "active"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestDeleteArtifactRefusedWhileReferenced(t *testing.T) {
	admin, public := testAdmin(t)
	templateID := registerDefault(t, public)
	list, err := admin.ListArtifacts(t.Context(), &delegateev1.ListArtifactsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetArtifacts(), 1)
	require.Empty(t, list.GetArtifacts()[0].GetDocument())
	artifactID := list.GetArtifacts()[0].GetId()

	_, err = admin.DeleteArtifact(t.Context(), &delegateev1.DeleteArtifactRequest{Id: artifactID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = public.GetArtifact(t.Context(), &delegateev1.GetArtifactRequest{Id: artifactID})
	require.NoError(t, err)

	_, err = admin.DeleteTemplate(t.Context(), &delegateev1.DeleteTemplateRequest{Id: templateID})
	require.NoError(t, err)
	_, err = admin.DeleteArtifact(t.Context(), &delegateev1.DeleteArtifactRequest{Id: artifactID})
	require.NoError(t, err)
	_, err = public.GetArtifact(t.Context(), &delegateev1.GetArtifactRequest{Id: artifactID})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestDeleteErrors(t *testing.T) {
	admin, _ := testAdmin(t)
	_, err := admin.DeleteArtifact(t.Context(), &delegateev1.DeleteArtifactRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.DeleteArtifact(t.Context(), &delegateev1.DeleteArtifactRequest{Id: "missing"})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = admin.DeleteTemplate(t.Context(), &delegateev1.DeleteTemplateRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.DeleteTemplate(t.Context(), &delegateev1.DeleteTemplateRequest{Id: "missing"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestCancelThenResumeDelegation(t *testing.T) {
	admin, public := testAdmin(t)
	id := registerDefault(t, public)
	variables := renewalVariables(t)
	reg, err := public.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: id, Variables: variables})
	require.NoError(t, err)
	delegationID := reg.GetDelegation().GetId()

	_, err = admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{Id: delegationID})
	require.NoError(t, err)
	got, err := public.GetDelegation(t.Context(), &delegateev1.GetDelegationRequest{Id: delegationID})
	require.NoError(t, err)
	require.Equal(t, "cancelled", got.GetDelegation().GetStatus())
	_, err = public.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: id, Variables: variables})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{Id: delegationID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	_, err = admin.ResumeDelegation(t.Context(), &delegateev1.ResumeDelegationRequest{Id: delegationID})
	require.NoError(t, err)
	got, err = public.GetDelegation(t.Context(), &delegateev1.GetDelegationRequest{Id: delegationID})
	require.NoError(t, err)
	require.Equal(t, "active", got.GetDelegation().GetStatus())
	again, err := public.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: id, Variables: variables})
	require.NoError(t, err)
	require.Equal(t, delegationID, again.GetDelegation().GetId())
	_, err = admin.ResumeDelegation(t.Context(), &delegateev1.ResumeDelegationRequest{Id: delegationID})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))

	_, err = admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.CancelDelegation(t.Context(), &delegateev1.CancelDelegationRequest{Id: 404})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = admin.ResumeDelegation(t.Context(), &delegateev1.ResumeDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.ResumeDelegation(t.Context(), &delegateev1.ResumeDelegationRequest{Id: 404})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestListDelegations(t *testing.T) {
	soon := time.Unix(1_800_000_000, 0).UTC()
	rows := []ports.Summary{
		summary(3, soon, 2, 30_000, delegation.Succeeded), summary(5, soon.Add(time.Hour), 1, 10_000, ""),
		summary(1, time.Time{}, 0, 0, delegation.Failed), summary(2, time.Time{}, 0, 0, ""), summary(4, time.Time{}, 0, 0, ""),
	}
	rows[3].Status = delegation.StatusCancelled
	rows[1].StreamID, rows[4].StreamID = 9, 9
	rows[2].TemplateID = "other"
	admin := NewAdmin(nil, nil, &summaryStub{rows: rows}, nil)

	all, err := admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{})
	require.NoError(t, err)
	require.Equal(t, []int64{3, 5, 1, 2, 4}, delegationIDs(all))
	require.Empty(t, all.GetNextCursor())
	first := all.GetDelegations()[0]
	require.Equal(t, int64(2), first.GetCoins())
	require.Equal(t, uint64(30_000), first.GetAmount())
	require.Equal(t, soon.Unix(), first.GetNextDue())
	require.Equal(t, "succeeded", first.GetLastAttempt())
	require.Zero(t, all.GetDelegations()[2].GetNextDue(), "no coins, nothing due")
	require.Equal(t, "failed", all.GetDelegations()[2].GetLastAttempt())

	var paged []int64
	var cursor string
	for {
		page, err := admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{Cursor: cursor, Limit: 2})
		require.NoError(t, err)
		paged = append(paged, delegationIDs(page)...)
		if cursor = page.GetNextCursor(); cursor == "" {
			break
		}
	}
	require.Equal(t, []int64{3, 5, 1, 2, 4}, paged)

	cancelled, err := admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{Status: "cancelled"})
	require.NoError(t, err)
	require.Equal(t, []int64{2}, delegationIDs(cancelled))
	spawned, err := admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{StreamId: 9})
	require.NoError(t, err)
	require.Equal(t, []int64{5, 4}, delegationIDs(spawned))
	other, err := admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{TemplateId: "other"})
	require.NoError(t, err)
	require.Equal(t, []int64{1}, delegationIDs(other))

	_, err = admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{Cursor: "not a cursor"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{Limit: 1001})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.ListDelegations(t.Context(), &delegateev1.ListDelegationsRequest{Limit: -1})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestGetHealth(t *testing.T) {
	checks := &healthStub{entries: []health.Entry{{Name: "db"}, {Name: "arkd", Err: errors.New("connection refused")}, {Name: "loop"}}}
	admin := NewAdmin(nil, nil, nil, checks)

	resp, err := admin.GetHealth(t.Context(), &delegateev1.GetHealthRequest{})
	require.NoError(t, err)
	require.False(t, resp.GetHealthy())
	require.Len(t, resp.GetEntries(), 3)
	require.Equal(t, "db", resp.GetEntries()[0].GetName())
	require.True(t, resp.GetEntries()[0].GetHealthy())
	require.Empty(t, resp.GetEntries()[0].GetError())
	require.Equal(t, "arkd", resp.GetEntries()[1].GetName())
	require.False(t, resp.GetEntries()[1].GetHealthy())
	require.Equal(t, "connection refused", resp.GetEntries()[1].GetError())

	checks.entries[1].Err = nil
	resp, err = admin.GetHealth(t.Context(), &delegateev1.GetHealthRequest{})
	require.NoError(t, err)
	require.True(t, resp.GetHealthy())
}

func TestListAttempts(t *testing.T) {
	admin, public, store := testAdminAndAttempts(t)
	id := registerDefault(t, public)
	reg, err := public.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t)})
	require.NoError(t, err)
	delegationID := reg.GetDelegation().GetId()
	var ids []int64
	for i := range 3 {
		a := delegation.Attempt{DelegationID: delegationID, Txs: []delegation.Tx{{Txid: "tx" + string(rune('0'+i)), Spends: true}}, Coins: []string{"a:0"}, Status: delegation.Submitted}
		require.NoError(t, store.AddOrUpdate(t.Context(), &a))
		ids = append(ids, a.ID)
	}
	first, err := store.ListPending(t.Context())
	require.NoError(t, err)
	require.NoError(t, first[0].Fail(errors.New("emulator: refused")))
	require.NoError(t, store.AddOrUpdate(t.Context(), &first[0]))

	list, err := admin.ListAttempts(t.Context(), &delegateev1.ListAttemptsRequest{Id: delegationID})
	require.NoError(t, err)
	require.Len(t, list.GetAttempts(), 3)
	require.Equal(t, ids[2], list.GetAttempts()[0].GetId())
	require.Equal(t, "tx2", list.GetAttempts()[0].GetTxid())
	require.Equal(t, "submitted", list.GetAttempts()[0].GetStatus())
	require.Equal(t, "intent", list.GetAttempts()[0].GetKind())
	require.Equal(t, []string{"a:0"}, list.GetAttempts()[0].GetCoins())
	require.Equal(t, delegationID, list.GetAttempts()[0].GetDelegationId())
	require.NotZero(t, list.GetAttempts()[0].GetCreatedAt())
	require.Equal(t, "failed", list.GetAttempts()[2].GetStatus())
	require.Equal(t, "emulator: refused", list.GetAttempts()[2].GetError())
	require.Zero(t, list.GetNextCursor(), "the last page")

	page, err := admin.ListAttempts(t.Context(), &delegateev1.ListAttemptsRequest{Id: delegationID, Cursor: ids[2], Limit: 1})
	require.NoError(t, err)
	require.Len(t, page.GetAttempts(), 1)
	require.Equal(t, ids[1], page.GetAttempts()[0].GetId())
	require.Equal(t, ids[1], page.GetNextCursor())

	_, err = admin.ListAttempts(t.Context(), &delegateev1.ListAttemptsRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.ListAttempts(t.Context(), &delegateev1.ListAttemptsRequest{Id: delegationID, Limit: 1001})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.ListAttempts(t.Context(), &delegateev1.ListAttemptsRequest{Id: 404})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestExpireDelegations(t *testing.T) {
	admin, public := testAdmin(t)
	id := registerDefault(t, public)
	soon := time.Now().Add(48 * time.Hour)
	reg, err := public.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{
		TemplateId: id, Variables: renewalVariables(t), ExpiresAt: soon.Unix(),
	})
	require.NoError(t, err)
	forever, err := public.RegisterDelegation(t.Context(), &delegateev1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t, 2)})
	require.NoError(t, err)

	n, err := admin.delegations.ExpireDelegations(t.Context(), soon.Add(-time.Second))
	require.NoError(t, err)
	require.Zero(t, n)
	n, err = admin.delegations.ExpireDelegations(t.Context(), soon)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	gone, err := public.GetDelegation(t.Context(), &delegateev1.GetDelegationRequest{Id: reg.GetDelegation().GetId()})
	require.NoError(t, err)
	require.Equal(t, "expired", gone.GetDelegation().GetStatus())
	got, err := public.GetDelegation(t.Context(), &delegateev1.GetDelegationRequest{Id: forever.GetDelegation().GetId()})
	require.NoError(t, err)
	require.Equal(t, "active", got.GetDelegation().GetStatus())
}

func TestGetStatus(t *testing.T) {
	soon := time.Unix(1_800_000_100, 0)
	stub := &statusStub{status: executionapp.Status{
		Active: 5, Queued: 3, Registered: 2, Late: 1, NextDue: soon, Tip: delegation.Tip{Height: 812}, Coins: 7, Amount: 70_000,
		Succeeded: 11, Failed: 4, TemplateFailures: 2, Reserve: 15 * time.Minute,
		Session: execution.Session{Duration: time.Minute, MaxIntents: 64},
		Batches: []executionapp.BatchForecast{
			{At: soon, Intents: 2, Coins: 3, Amount: 30_000, Entries: []executionapp.ForecastEntry{{DelegationID: 4, Coins: 3, Amount: 30_000, Due: soon, Deadline: soon.Add(time.Hour)}}}, {At: soon.Add(time.Minute), Intents: 1, Coins: 1, Amount: 10_000},
		},
	}}
	admin := NewAdmin(nil, nil, stub, nil)
	resp, err := admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{})
	require.NoError(t, err)
	require.Equal(t, int64(5), resp.GetActive())
	require.Equal(t, int64(3), resp.GetQueued())
	require.Equal(t, int64(2), resp.GetRegistered())
	require.Equal(t, int64(1), resp.GetLate())
	require.Equal(t, soon.Unix(), resp.GetNextDue())
	require.Equal(t, int64(812), resp.GetTipHeight())
	require.Equal(t, int64(7), resp.GetCoins())
	require.Equal(t, uint64(70_000), resp.GetAmount())
	require.Equal(t, uint64(11), resp.GetSucceeded())
	require.Equal(t, uint64(4), resp.GetFailed())
	require.Equal(t, uint64(2), resp.GetTemplateFailures())
	require.Equal(t, int64(900), resp.GetReserveSeconds())
	require.Equal(t, int64(60), resp.GetSessionSeconds())
	require.Equal(t, int64(64), resp.GetMaxIntents())
	require.Len(t, resp.GetBatches(), 2)
	require.Equal(t, soon.Unix(), resp.GetBatches()[0].GetAt())
	require.Equal(t, int64(2), resp.GetBatches()[0].GetIntents())
	require.Equal(t, int64(3), resp.GetBatches()[0].GetCoins())
	require.Equal(t, uint64(30_000), resp.GetBatches()[0].GetAmount())
	require.Len(t, resp.GetBatches()[0].GetEntries(), 1)
	require.Equal(t, int64(4), resp.GetBatches()[0].GetEntries()[0].GetDelegationId())
	require.Equal(t, soon.Add(time.Hour).Unix(), resp.GetBatches()[0].GetEntries()[0].GetDeadline())
	require.Equal(t, 24*time.Hour, stub.horizon, "the default horizon")

	_, err = admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{HorizonSeconds: 3600})
	require.NoError(t, err)
	require.Equal(t, time.Hour, stub.horizon)
	_, err = admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{HorizonSeconds: 365 * 86400})
	require.NoError(t, err)
	require.Equal(t, 7*24*time.Hour, stub.horizon, "clamped")

	stub.status = executionapp.Status{}
	resp, err = admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{})
	require.NoError(t, err)
	require.Zero(t, resp.GetNextDue(), "nothing is due")
	require.Empty(t, resp.GetBatches())

	stub.err = errors.New("database down")
	_, err = admin.GetStatus(t.Context(), &delegateev1.GetStatusRequest{})
	require.Equal(t, codes.Internal, status.Code(err))
}

func TestCursorRoundTrip(t *testing.T) {
	due := time.Now().UTC().Truncate(time.Microsecond)
	for _, c := range []ports.Cursor{{NextDue: due, ID: 7}, {ID: 9}} {
		parsed, err := parseCursor(encodeCursor(c))
		require.NoError(t, err)
		require.Equal(t, c.ID, parsed.ID)
		require.True(t, c.NextDue.Equal(parsed.NextDue))
	}
	require.Empty(t, encodeCursor(ports.Cursor{}))
	parsed, err := parseCursor("")
	require.NoError(t, err)
	require.Zero(t, parsed)
}

func TestParseCursorRefusesWhatItDidNotWrite(t *testing.T) {
	for _, bad := range []string{"%%%", "bm90LWEtY3Vyc29y", "MDow", "LTE6MQ"} {
		_, err := parseCursor(bad)
		require.True(t, errors.Is(err, delegation.ErrInvalidArgs), bad)
	}
}

type statusStub struct {
	Executor
	status  executionapp.Status
	err     error
	horizon time.Duration
}

func (s *statusStub) Status(_ context.Context, horizon time.Duration) (executionapp.Status, error) {
	s.horizon = horizon
	return s.status, s.err
}

// summaryStub lists the summaries it was given, in that order.
type summaryStub struct {
	Executor
	rows []ports.Summary
}

func (s *summaryStub) Summaries(_ context.Context, f ports.SummaryFilter) ([]ports.Summary, error) {
	var out []ports.Summary
	after := f.After.ID == 0
	for _, row := range s.rows {
		matches := (f.Status == "" || row.Status == f.Status) && (f.StreamID == 0 || row.StreamID == f.StreamID) &&
			(f.TemplateID == "" || row.TemplateID == f.TemplateID)
		if after && matches && len(out) < f.Limit {
			out = append(out, row)
		}
		after = after || row.ID == f.After.ID
	}
	return out, nil
}

type healthStub struct{ entries []health.Entry }

func (s *healthStub) Check(context.Context) []health.Entry { return s.entries }

func testAdmin(t *testing.T) (*Admin, *Delegatee) {
	t.Helper()
	admin, h, _ := testAdminAndAttempts(t)
	return admin, h
}

func testAdminAndAttempts(t *testing.T) (*Admin, *Delegatee, *attempts) {
	t.Helper()
	h, _, attempts := testHandlerAndStores(t, 10, delegationapp.Limits{MinDelegationExpiry: 24 * time.Hour})
	return NewAdmin(h.registry, h.delegations, h.execution, nil), h, attempts
}

func summary(id int64, nextDue time.Time, coins int, amount uint64, last delegation.AttemptStatus) ports.Summary {
	return ports.Summary{
		Delegation: delegation.Delegation{ID: id, Status: delegation.StatusActive},
		Coins:      coins, Amount: amount, NextDue: nextDue, LastAttempt: last,
	}
}

func delegationIDs(resp *delegateev1.ListDelegationsResponse) []int64 {
	ids := make([]int64, 0, len(resp.GetDelegations()))
	for _, d := range resp.GetDelegations() {
		ids = append(ids, d.GetDelegation().GetId())
	}
	return ids
}

// registerDefault registers the default artifact and the renewal template, returning the template id.
func registerDefault(t *testing.T, public *Delegatee) string {
	t.Helper()
	_, err := public.RegisterArtifact(t.Context(), &delegateev1.RegisterArtifactRequest{Document: testDocument(t)})
	require.NoError(t, err)
	reg, err := public.RegisterTemplate(t.Context(), &delegateev1.RegisterTemplateRequest{
		Document: testTemplateDocument(t, "renewal.json"),
	})
	require.NoError(t, err)
	return reg.GetTemplate().GetId()
}

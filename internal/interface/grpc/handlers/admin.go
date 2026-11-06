package handlers

import (
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	delegationapp "github.com/arkade-os/delegatee/internal/core/application/delegation"
	executionapp "github.com/arkade-os/delegatee/internal/core/application/execution"
	"github.com/arkade-os/delegatee/internal/core/application/health"
	app "github.com/arkade-os/delegatee/internal/core/application/registry"
	"github.com/arkade-os/delegatee/internal/core/domain/delegation"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/arkade-os/delegatee/pkg/template"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	defaultListLimit = 100
	maxListLimit     = 1000

	defaultHorizon = 24 * time.Hour
	maxHorizon     = 7 * 24 * time.Hour
)

type Executor interface {
	Attempts(ctx context.Context, delegationID, cursor int64, limit int) ([]delegation.Attempt, error)
	Coins(ctx context.Context, delegationID int64) ([]delegation.Coin, error)
	Summaries(ctx context.Context, f ports.SummaryFilter) ([]ports.Summary, error)
	Status(ctx context.Context, horizon time.Duration) (executionapp.Status, error)
}

type Health interface {
	Check(ctx context.Context) []health.Entry
}

type Admin struct {
	registry    *app.Service
	delegations *delegationapp.Service
	execution   Executor
	health      Health
}

func NewAdmin(registry *app.Service, delegations *delegationapp.Service, execution Executor, health Health) *Admin {
	return &Admin{registry: registry, delegations: delegations, execution: execution, health: health}
}

func (h *Admin) UpdateTemplate(
	ctx context.Context, req *delegateev1.UpdateTemplateRequest,
) (*delegateev1.UpdateTemplateResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if req.GetStatus() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing status")
	}
	if err := h.registry.SetTemplateStatus(ctx, req.GetId(), req.GetStatus()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.UpdateTemplateResponse{}, nil
}

func (h *Admin) DeleteTemplate(
	ctx context.Context, req *delegateev1.DeleteTemplateRequest,
) (*delegateev1.DeleteTemplateResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.registry.DeleteTemplate(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.DeleteTemplateResponse{}, nil
}

func (h *Admin) ListArtifacts(
	ctx context.Context, _ *delegateev1.ListArtifactsRequest,
) (*delegateev1.ListArtifactsResponse, error) {
	list, err := h.registry.ListArtifacts(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &delegateev1.ListArtifactsResponse{Artifacts: make([]*delegateev1.Artifact, 0, len(list))}
	for _, a := range list {
		resp.Artifacts = append(resp.Artifacts, toArtifact(&a))
	}
	return resp, nil
}

func (h *Admin) DeleteArtifact(
	ctx context.Context, req *delegateev1.DeleteArtifactRequest,
) (*delegateev1.DeleteArtifactResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.registry.DeleteArtifact(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.DeleteArtifactResponse{}, nil
}

func (h *Admin) ListDelegations(
	ctx context.Context, req *delegateev1.ListDelegationsRequest,
) (*delegateev1.ListDelegationsResponse, error) {
	limit, err := listLimit(req.GetLimit())
	if err != nil {
		return nil, err
	}
	after, err := parseCursor(req.GetCursor())
	if err != nil {
		return nil, toStatus(err)
	}
	list, err := h.execution.Summaries(ctx, ports.SummaryFilter{Status: req.GetStatus(), After: after, Limit: limit})
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &delegateev1.ListDelegationsResponse{Delegations: make([]*delegateev1.DelegationSummary, 0, len(list))}
	for _, s := range list {
		sum := &delegateev1.DelegationSummary{
			Delegation: toDelegation(&s.Delegation), Coins: int64(s.Coins), Amount: s.Amount, LastAttempt: string(s.LastAttempt),
		}
		if !s.NextDue.IsZero() {
			sum.NextDue = s.NextDue.Unix()
		}
		resp.Delegations = append(resp.Delegations, sum)
	}
	if len(list) == limit {
		resp.NextCursor = encodeCursor(ports.Cursor{NextDue: list[len(list)-1].NextDue, ID: list[len(list)-1].ID})
	}
	return resp, nil
}

func (h *Admin) CancelDelegation(
	ctx context.Context, req *delegateev1.CancelDelegationRequest,
) (*delegateev1.CancelDelegationResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.delegations.CancelDelegation(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.CancelDelegationResponse{}, nil
}

func (h *Admin) ResumeDelegation(
	ctx context.Context, req *delegateev1.ResumeDelegationRequest,
) (*delegateev1.ResumeDelegationResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.delegations.ResumeDelegation(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.ResumeDelegationResponse{}, nil
}

func (h *Admin) RegisterStream(
	ctx context.Context, req *delegateev1.RegisterStreamRequest,
) (*delegateev1.RegisterStreamResponse, error) {
	if req.GetTemplateId() == "" {
		return nil, status.Error(codes.InvalidArgument, "missing template id")
	}
	st, err := h.delegations.RegisterStream(ctx, req.GetTemplateId(), req.GetVariables())
	if err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.RegisterStreamResponse{Stream: toStream(st)}, nil
}

func (h *Admin) ListStreams(ctx context.Context, _ *delegateev1.ListStreamsRequest) (*delegateev1.ListStreamsResponse, error) {
	list, err := h.delegations.ListStreams(ctx)
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &delegateev1.ListStreamsResponse{Streams: make([]*delegateev1.Stream, 0, len(list))}
	for _, st := range list {
		resp.Streams = append(resp.Streams, toStream(&st))
	}
	return resp, nil
}

func (h *Admin) CancelStream(
	ctx context.Context, req *delegateev1.CancelStreamRequest,
) (*delegateev1.CancelStreamResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	if err := h.delegations.CancelStream(ctx, req.GetId()); err != nil {
		return nil, toStatus(err)
	}
	return &delegateev1.CancelStreamResponse{}, nil
}

func (h *Admin) ListAttempts(
	ctx context.Context, req *delegateev1.ListAttemptsRequest,
) (*delegateev1.ListAttemptsResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "missing id")
	}
	limit, err := listLimit(req.GetLimit())
	if err != nil {
		return nil, err
	}
	d, err := h.delegations.GetDelegation(ctx, req.GetId())
	if err != nil {
		return nil, toStatus(err)
	}
	tmpl, err := h.registry.GetTemplate(ctx, d.TemplateID)
	if err != nil {
		return nil, toStatus(err)
	}
	list, err := h.execution.Attempts(ctx, req.GetId(), req.GetCursor(), limit)
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &delegateev1.ListAttemptsResponse{Attempts: make([]*delegateev1.Attempt, 0, len(list))}
	for _, a := range list {
		resp.Attempts = append(resp.Attempts, toAttempt(a, tmpl.Type))
	}
	if len(list) == limit {
		resp.NextCursor = list[len(list)-1].ID
	}
	return resp, nil
}

func (h *Admin) GetHealth(ctx context.Context, _ *delegateev1.GetHealthRequest) (*delegateev1.GetHealthResponse, error) {
	entries := h.health.Check(ctx)
	resp := &delegateev1.GetHealthResponse{Healthy: health.Healthy(entries), Entries: make([]*delegateev1.HealthEntry, 0, len(entries))}
	for _, e := range entries {
		entry := &delegateev1.HealthEntry{Name: e.Name, Healthy: e.Err == nil}
		if e.Err != nil {
			entry.Error = e.Err.Error()
		}
		resp.Entries = append(resp.Entries, entry)
	}
	return resp, nil
}

func (h *Admin) GetStatus(ctx context.Context, req *delegateev1.GetStatusRequest) (*delegateev1.GetStatusResponse, error) {
	horizon := defaultHorizon
	if secs := req.GetHorizonSeconds(); secs > 0 {
		horizon = time.Duration(min(secs, int64(maxHorizon/time.Second))) * time.Second
	}
	st, err := h.execution.Status(ctx, horizon)
	if err != nil {
		return nil, toStatus(err)
	}
	resp := &delegateev1.GetStatusResponse{
		Active: st.Active, Queued: int64(st.Queued), Registered: int64(st.Registered), Late: int64(st.Late), TipHeight: st.Tip.Height,
		Coins: int64(st.Coins), Amount: st.Amount,
		Batches: make([]*delegateev1.BatchForecast, 0, len(st.Batches)),
	}
	if !st.NextDue.IsZero() {
		resp.NextDue = st.NextDue.Unix()
	}
	for _, r := range st.Batches {
		b := &delegateev1.BatchForecast{At: r.At.Unix(), Intents: int64(r.Intents), Coins: int64(r.Coins), Amount: r.Amount}
		for _, e := range r.Entries {
			b.Entries = append(b.Entries, &delegateev1.ForecastEntry{
				DelegationId: e.DelegationID, Coins: int64(e.Coins), Amount: e.Amount, Due: e.Due.Unix(), Deadline: e.Deadline.Unix(),
			})
		}
		resp.Batches = append(resp.Batches, b)
	}
	return resp, nil
}

func listLimit(limit int32) (int, error) {
	switch {
	case limit == 0:
		return defaultListLimit, nil
	case limit < 0 || limit > maxListLimit:
		return 0, status.Errorf(codes.InvalidArgument, "limit must be between 1 and %d", maxListLimit)
	}
	return int(limit), nil
}

func toStream(s *delegation.Stream) *delegateev1.Stream {
	return &delegateev1.Stream{
		Id: s.ID, TemplateId: s.TemplateID, Variables: s.Variables, Status: s.Status,
		CreatedAt: s.CreatedAt.Unix(),
	}
}

func toAttempt(a delegation.Attempt, kind template.Type) *delegateev1.Attempt {
	return &delegateev1.Attempt{
		Id: a.ID, DelegationId: a.DelegationID, Kind: string(kind), Coins: a.Coins, Txid: cmp.Or(a.Spenders()...),
		Status: string(a.Status), Error: a.Error, CreatedAt: a.CreatedAt.Unix(), UpdatedAt: a.UpdatedAt.Unix(),
	}
}

// encodeCursor is the opaque cursor of c, empty at the top of the order.
func encodeCursor(c ports.Cursor) string {
	if c.ID == 0 {
		return ""
	}
	var micros int64
	if !c.NextDue.IsZero() {
		micros = c.NextDue.UnixMicro()
	}
	return base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%d:%d", micros, c.ID)))
}

func parseCursor(s string) (ports.Cursor, error) {
	if s == "" {
		return ports.Cursor{}, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return ports.Cursor{}, fmt.Errorf("%w: cursor", delegation.ErrInvalidArgs)
	}
	micros, id, ok := strings.Cut(string(raw), ":")
	m, errM := strconv.ParseInt(micros, 10, 64)
	i, errI := strconv.ParseInt(id, 10, 64)
	if !ok || errM != nil || errI != nil || m < 0 || i <= 0 {
		return ports.Cursor{}, fmt.Errorf("%w: cursor", delegation.ErrInvalidArgs)
	}
	c := ports.Cursor{ID: i}
	if m > 0 {
		c.NextDue = time.UnixMicro(m).UTC()
	}
	return c, nil
}

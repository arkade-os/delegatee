package indexer

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type subscriptions interface {
	clientlib.Indexer
	NewTransactionSubscription(context.Context, []string) (string, <-chan clientlib.TransactionEvent, func(), error)
	UpdateTransactionSubscription(context.Context, string, []string) error
}

type subscriptionServer struct {
	arkv1.UnimplementedIndexerServiceServer
	subscribe func(*arkv1.GetSubscriptionRequest, arkv1.IndexerService_GetSubscriptionServer) error
	update    func(*arkv1.UpdateSubscriptionRequest) error
	calls     atomic.Int32
}

func (s *subscriptionServer) GetSubscription(req *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
	s.calls.Add(1)
	return s.subscribe(req, stream)
}
func (s *subscriptionServer) UpdateSubscription(_ context.Context, req *arkv1.UpdateSubscriptionRequest) (*arkv1.UpdateSubscriptionResponse, error) {
	return &arkv1.UpdateSubscriptionResponse{}, s.update(req)
}
func testClient(t *testing.T, s *subscriptionServer) subscriptions {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	server := grpc.NewServer()
	arkv1.RegisterIndexerServiceServer(server, s)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client, err := NewClient(listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(client.Close)
	require.Implements(t, (*subscriptions)(nil), client)
	return client
}
func started(stream arkv1.IndexerService_GetSubscriptionServer, id string) error {
	return stream.Send(&arkv1.GetSubscriptionResponse{Data: &arkv1.GetSubscriptionResponse_SubscriptionStarted{SubscriptionStarted: &arkv1.SubscriptionStartedEvent{SubscriptionId: id}}})
}
func txEvent(txid, tx string) *arkv1.GetSubscriptionResponse {
	return &arkv1.GetSubscriptionResponse{Data: &arkv1.GetSubscriptionResponse_Event{Event: &arkv1.IndexerSubscriptionEvent{Txid: txid, Tx: tx}}}
}
func TestTransactionFilterAndServerFailure(t *testing.T) {
	requests := make(chan *arkv1.GetSubscriptionRequest, 1)
	server := &subscriptionServer{subscribe: func(req *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
		requests <- req
		if err := started(stream, "transaction-id"); err != nil {
			return err
		}
		if err := stream.Send(&arkv1.GetSubscriptionResponse{Data: &arkv1.GetSubscriptionResponse_Heartbeat{Heartbeat: &arkv1.IndexerHeartbeat{}}}); err != nil {
			return err
		}
		if err := stream.Send(txEvent("matched", "full-psbt")); err != nil {
			return err
		}
		return status.Error(codes.Unavailable, "lost server")
	}}
	client := testClient(t, server)
	expressions := []string{"tx.extensions.exists(e, e.type == 4)"}
	_, events, stop, err := client.NewTransactionSubscription(t.Context(), expressions)
	require.NoError(t, err)
	defer stop()
	req := <-requests
	require.Empty(t, req.SubscriptionId)
	require.Equal(t, expressions, req.Filter.Expressions)
	require.Nil(t, req.Filter.Scripts)
	first := <-events
	require.NoError(t, first.Err)
	require.Equal(t, "full-psbt", first.ArkTx.Tx)
	require.Equal(t, "matched", first.ArkTx.Txid)
	next := <-events
	require.Equal(t, codes.Unavailable, status.Code(next.Err))
	_, ok := <-events
	require.False(t, ok)
	require.EqualValues(t, 1, server.calls.Load())
}
func TestStartupRejection(t *testing.T) {
	for _, code := range []codes.Code{codes.Unimplemented, codes.InvalidArgument} {
		t.Run(code.String(), func(t *testing.T) {
			server := &subscriptionServer{subscribe: func(*arkv1.GetSubscriptionRequest, arkv1.IndexerService_GetSubscriptionServer) error {
				return status.Error(code, "filter rejected")
			}}
			client := testClient(t, server)
			_, events, stop, err := client.NewTransactionSubscription(t.Context(), []string{"filter"})
			require.Equal(t, code, status.Code(err))
			require.Nil(t, events)
			require.Nil(t, stop)
			require.EqualValues(t, 1, server.calls.Load())
		})
	}
}
func TestRequiresSubscriptionAcknowledgement(t *testing.T) {
	server := &subscriptionServer{subscribe: func(_ *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
		return stream.Send(txEvent("unfiltered", "psbt"))
	}}
	client := testClient(t, server)
	_, events, stop, err := client.NewTransactionSubscription(t.Context(), []string{"filter"})
	require.ErrorContains(t, err, "acknowledgement")
	require.Nil(t, events)
	require.Nil(t, stop)
}
func TestCancellationUnblocksBackpressure(t *testing.T) {
	for _, closeClient := range []bool{false, true} {
		t.Run(map[bool]string{false: "subscription", true: "client"}[closeClient], func(t *testing.T) {
			sent := make(chan struct{})
			ended := make(chan struct{})
			server := &subscriptionServer{subscribe: func(_ *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
				defer close(ended)
				if err := started(stream, "backpressure"); err != nil {
					return err
				}
				for range 20 {
					if err := stream.Send(txEvent("match", "psbt")); err != nil {
						return err
					}
				}
				close(sent)
				<-stream.Context().Done()
				return stream.Context().Err()
			}}
			client := testClient(t, server)
			_, events, stop, err := client.NewTransactionSubscription(t.Context(), []string{"filter"})
			require.NoError(t, err)
			<-sent
			require.LessOrEqual(t, cap(events), 16)
			if closeClient {
				client.Close()
			} else {
				stop()
			}
			drained := make(chan struct{})
			go func() {
				for range events {
				}
				close(drained)
			}()
			select {
			case <-drained:
			case <-time.After(time.Second):
				t.Fatal("event reader leaked")
			}
			select {
			case <-ended:
			case <-time.After(time.Second):
				t.Fatal("server stream leaked")
			}
			stop()
			client.Close()
		})
	}
}
func TestScriptSubscriptionUsesAcknowledgedID(t *testing.T) {
	requests := make(chan *arkv1.GetSubscriptionRequest, 1)
	updates := make(chan *arkv1.UpdateSubscriptionRequest, 1)
	server := &subscriptionServer{
		subscribe: func(req *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
			requests <- req
			if err := started(stream, "scripts-id"); err != nil {
				return err
			}
			ev := txEvent("funding", "psbt")
			ev.GetEvent().Scripts = []string{"5120aa"}
			ev.GetEvent().NewVtxos = []*arkv1.IndexerVtxo{{Amount: 42, Script: "5120aa"}}
			if err := stream.Send(ev); err != nil {
				return err
			}
			<-stream.Context().Done()
			return stream.Context().Err()
		}, update: func(req *arkv1.UpdateSubscriptionRequest) error { updates <- req; return nil }}
	client := testClient(t, server)
	id, events, stop, err := client.NewSubscription(t.Context(), []string{"5120aa"})
	require.NoError(t, err)
	defer stop()
	require.Equal(t, "scripts-id", id)
	req := <-requests
	require.Equal(t, []string{"5120aa"}, req.Filter.Scripts.Add)
	require.Empty(t, req.Filter.Expressions)
	ev := <-events
	require.NoError(t, ev.Err)
	require.Equal(t, "psbt", ev.Data.Tx)
	require.EqualValues(t, 42, ev.Data.NewVtxos[0].Amount)
	require.NoError(t, client.UpdateSubscription(t.Context(), id, []string{"5120bb"}, []string{"5120aa"}))
	update := <-updates
	require.Equal(t, id, update.SubscriptionId)
	require.Equal(t, []string{"5120bb"}, update.Filter.Scripts.Add)
	require.Equal(t, []string{"5120aa"}, update.Filter.Scripts.Remove)
	stop()
	_, ok := <-events
	require.False(t, ok)
	require.EqualValues(t, 1, server.calls.Load())
}

func TestEmptyFiltersNeverOpenASubscription(t *testing.T) {
	server := &subscriptionServer{subscribe: func(*arkv1.GetSubscriptionRequest, arkv1.IndexerService_GetSubscriptionServer) error {
		return status.Error(codes.Internal, "unfiltered stream opened")
	}}
	client := testClient(t, server)
	_, events, stop, err := client.NewTransactionSubscription(t.Context(), nil)
	require.ErrorContains(t, err, "expressions")
	require.Nil(t, events)
	require.Nil(t, stop)
	id, scripts, stop, err := client.NewSubscription(t.Context(), nil)
	require.ErrorContains(t, err, "scripts")
	require.Empty(t, id)
	require.Nil(t, scripts)
	require.Nil(t, stop)
	require.Zero(t, server.calls.Load())
}

func TestParentCancellationDuringStartup(t *testing.T) {
	opened := make(chan struct{})
	ended := make(chan struct{})
	server := &subscriptionServer{subscribe: func(_ *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
		close(opened)
		defer close(ended)
		<-stream.Context().Done()
		return stream.Context().Err()
	}}
	client := testClient(t, server)
	ctx, cancel := context.WithCancel(t.Context())
	failed := make(chan error, 1)
	go func() { _, _, _, err := client.NewTransactionSubscription(ctx, []string{"filter"}); failed <- err }()
	<-opened
	cancel()
	select {
	case err := <-failed:
		require.Equal(t, codes.Canceled, status.Code(err))
	case <-time.After(time.Second):
		t.Fatal("startup ignores cancellation")
	}
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("startup stream leaked")
	}
}

func TestScriptFailureClosesWithoutReplacingID(t *testing.T) {
	server := &subscriptionServer{subscribe: func(_ *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
		if err := started(stream, "original-id"); err != nil {
			return err
		}
		return status.Error(codes.Unavailable, "disconnected")
	}, update: func(*arkv1.UpdateSubscriptionRequest) error { return status.Error(codes.NotFound, "expired id") }}
	client := testClient(t, server)
	id, events, stop, err := client.NewSubscription(t.Context(), []string{"script"})
	require.NoError(t, err)
	defer stop()
	require.Equal(t, "original-id", id)
	event := <-events
	require.Equal(t, codes.Unavailable, status.Code(event.Err))
	_, ok := <-events
	require.False(t, ok)
	require.Equal(t, codes.NotFound, status.Code(client.UpdateSubscription(t.Context(), id, []string{"other"}, nil)))
	require.EqualValues(t, 1, server.calls.Load())
}

func TestGRPCTarget(t *testing.T) {
	for _, tc := range []struct{ url, target, security string }{
		{"localhost:7070", "localhost:7070", "insecure"}, {"http://localhost/", "localhost:80", "insecure"}, {"https://ark.example/", "ark.example:443", "tls"}, {"https://ark.example:7070", "ark.example:7070", "tls"},
	} {
		target, creds := grpcTarget(tc.url)
		require.Equal(t, tc.target, target)
		require.Equal(t, tc.security, creds.Info().SecurityProtocol)
	}
}
func TestTransactionFilterUpdateKeepsStream(t *testing.T) {
	emitted := make(chan string, 2)
	updates := make(chan *arkv1.UpdateSubscriptionRequest, 2)
	server := &subscriptionServer{
		subscribe: func(_ *arkv1.GetSubscriptionRequest, stream arkv1.IndexerService_GetSubscriptionServer) error {
			if err := started(stream, "stable-id"); err != nil {
				return err
			}
			for {
				select {
				case <-stream.Context().Done():
					return stream.Context().Err()
				case tx := <-emitted:
					if err := stream.Send(txEvent(tx, "psbt")); err != nil {
						return err
					}
				}
			}
		},
		update: func(req *arkv1.UpdateSubscriptionRequest) error {
			updates <- req
			if req.Filter.Expressions[0] == "invalid" {
				return status.Error(codes.InvalidArgument, "invalid expression")
			}
			return nil
		},
	}
	client := testClient(t, server)
	id, events, stop, err := client.NewTransactionSubscription(t.Context(), []string{"initial"})
	require.NoError(t, err)
	defer stop()
	require.Equal(t, "stable-id", id)
	require.NoError(t, client.UpdateTransactionSubscription(t.Context(), id, []string{"replacement"}))
	req := <-updates
	require.Equal(t, id, req.SubscriptionId)
	require.Equal(t, []string{"replacement"}, req.Filter.Expressions)
	require.Nil(t, req.Filter.Scripts)
	emitted <- "after update"
	require.Equal(t, "after update", (<-events).ArkTx.Txid)
	require.Equal(t, codes.InvalidArgument, status.Code(client.UpdateTransactionSubscription(t.Context(), id, []string{"invalid"})))
	req = <-updates
	require.Equal(t, id, req.SubscriptionId)
	require.Nil(t, req.Filter.Scripts)
	emitted <- "after rejection"
	require.Equal(t, "after rejection", (<-events).ArkTx.Txid)
	require.EqualValues(t, 1, server.calls.Load())
	require.ErrorContains(t, client.UpdateTransactionSubscription(t.Context(), "", []string{"replacement"}), "id")
	require.ErrorContains(t, client.UpdateTransactionSubscription(t.Context(), id, nil), "expressions")
	require.Empty(t, updates)
}

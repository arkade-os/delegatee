package indexer

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	arkv1 "github.com/arkade-os/arkd/api-spec/protobuf/gen/ark/v1"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	upstream "github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Client leaves reconnects to the application, which owns the current subscription IDs.
type Client struct {
	clientlib.Indexer
	conn      *grpc.ClientConn
	svc       arkv1.IndexerServiceClient
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
}

func NewClient(url string) (*Client, error) {
	sdk, err := upstream.NewClient(strings.TrimSuffix(url, "/"))
	if err != nil {
		return nil, err
	}
	target, creds := grpcTarget(url)
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds), grpc.WithDisableServiceConfig(), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(20<<20)))
	if err != nil {
		sdk.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Client{Indexer: sdk, conn: conn, svc: arkv1.NewIndexerServiceClient(conn), ctx: ctx, cancel: cancel}, nil
}

func (c *Client) Close() {
	c.closeOnce.Do(func() { c.cancel(); c.Indexer.Close(); _ = c.conn.Close() })
}

func (c *Client) NewTransactionSubscription(ctx context.Context, expressions []string) (string, <-chan clientlib.TransactionEvent, func(), error) {
	if len(expressions) == 0 {
		return "", nil, nil, fmt.Errorf("missing transaction filter expressions")
	}
	stream, id, readCtx, stop, err := c.open(ctx, &arkv1.SubscriptionFilter{Expressions: slices.Clone(expressions)})
	if err != nil {
		return "", nil, nil, err
	}
	events := readEvents(readCtx, stream, stop, func(event *arkv1.IndexerSubscriptionEvent) clientlib.TransactionEvent {
		return clientlib.TransactionEvent{ArkTx: &clientlib.TxNotification{TxData: clientlib.TxData{Txid: event.GetTxid(), Tx: event.GetTx()}}}
	}, func(err error) clientlib.TransactionEvent { return clientlib.TransactionEvent{Err: err} })
	return id, events, stop, nil
}

func (c *Client) UpdateTransactionSubscription(ctx context.Context, id string, expressions []string) error {
	if id == "" {
		return fmt.Errorf("missing subscription id to update")
	}
	if len(expressions) == 0 {
		return fmt.Errorf("missing transaction filter expressions")
	}
	_, err := c.svc.UpdateSubscription(ctx, &arkv1.UpdateSubscriptionRequest{SubscriptionId: id, Filter: &arkv1.SubscriptionFilter{Expressions: slices.Clone(expressions)}})
	return err
}

func (c *Client) NewSubscription(ctx context.Context, scripts []string) (string, <-chan clientlib.ScriptEvent, func(), error) {
	if len(scripts) == 0 {
		return "", nil, nil, fmt.Errorf("missing subscription scripts")
	}
	stream, id, readCtx, stop, err := c.open(ctx, &arkv1.SubscriptionFilter{Scripts: &arkv1.ScriptFilter{Add: slices.Clone(scripts)}})
	if err != nil {
		return "", nil, nil, err
	}
	events := readEvents(readCtx, stream, stop, func(event *arkv1.IndexerSubscriptionEvent) clientlib.ScriptEvent {
		checkpoints := map[string]clientlib.TxData{}
		for key, tx := range event.GetCheckpointTxs() {
			checkpoints[key] = clientlib.TxData{Txid: tx.GetTxid(), Tx: tx.GetTx()}
		}
		return clientlib.ScriptEvent{Data: &clientlib.ScriptEventData{Txid: event.GetTxid(), Tx: event.GetTx(), Scripts: event.GetScripts(), NewVtxos: vtxos(event.GetNewVtxos()), SpentVtxos: vtxos(event.GetSpentVtxos()), CheckpointTxs: checkpoints}}
	}, func(err error) clientlib.ScriptEvent { return clientlib.ScriptEvent{Err: err} })
	return id, events, stop, nil
}

func (c *Client) UpdateSubscription(ctx context.Context, id string, add, remove []string) error {
	if id == "" {
		return fmt.Errorf("missing subscription id to update")
	}
	if len(add)+len(remove) == 0 {
		return fmt.Errorf("missing scripts to add or remove")
	}
	_, err := c.svc.UpdateSubscription(ctx, &arkv1.UpdateSubscriptionRequest{SubscriptionId: id, Filter: &arkv1.SubscriptionFilter{Scripts: &arkv1.ScriptFilter{Add: slices.Clone(add), Remove: slices.Clone(remove)}}})
	return err
}

func (c *Client) open(ctx context.Context, filter *arkv1.SubscriptionFilter) (arkv1.IndexerService_GetSubscriptionClient, string, context.Context, func(), error) {
	readCtx, cancel := context.WithCancel(ctx)
	detach := context.AfterFunc(c.ctx, cancel)
	stop := func() { cancel(); detach() }
	timer := time.AfterFunc(10*time.Second, cancel)
	defer timer.Stop()
	stream, err := c.svc.GetSubscription(readCtx, &arkv1.GetSubscriptionRequest{Filter: filter})
	if err != nil {
		stop()
		return nil, "", nil, nil, err
	}
	for {
		response, err := stream.Recv()
		if err != nil {
			stop()
			return nil, "", nil, nil, err
		}
		if response.GetHeartbeat() != nil {
			continue
		}
		ack := response.GetSubscriptionStarted()
		if ack == nil || ack.GetSubscriptionId() == "" {
			stop()
			return nil, "", nil, nil, fmt.Errorf("missing subscription acknowledgement")
		}
		return stream, ack.GetSubscriptionId(), readCtx, stop, nil
	}
}

func readEvents[T any](ctx context.Context, stream arkv1.IndexerService_GetSubscriptionClient, stop func(), convert func(*arkv1.IndexerSubscriptionEvent) T, failure func(error) T) <-chan T {
	events := make(chan T, 1)
	go func() {
		defer close(events)
		defer stop()
		for {
			response, err := stream.Recv()
			if ctx.Err() != nil {
				return
			}
			var event T
			if err != nil {
				event = failure(err)
			} else if data := response.GetEvent(); data != nil {
				event = convert(data)
			} else {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case events <- event:
			}
			if err != nil {
				return
			}
		}
	}()
	return events
}

func vtxos(items []*arkv1.IndexerVtxo) []clientlib.Vtxo {
	out := make([]clientlib.Vtxo, 0, len(items))
	for _, v := range items {
		var assets []clientlib.Asset
		for _, a := range v.GetAssets() {
			if a != nil {
				assets = append(assets, clientlib.Asset{AssetId: a.GetAssetId(), Amount: a.GetAmount()})
			}
		}
		out = append(out, clientlib.Vtxo{
			Outpoint: clientlib.Outpoint{Txid: v.GetOutpoint().GetTxid(), VOut: v.GetOutpoint().GetVout()},
			Script:   v.GetScript(), CommitmentTxids: v.GetCommitmentTxids(), Amount: v.GetAmount(),
			CreatedAt: time.Unix(v.GetCreatedAt(), 0), ExpiresAt: time.Unix(v.GetExpiresAt(), 0),
			Preconfirmed: v.GetIsPreconfirmed(), Swept: v.GetIsSwept(), Spent: v.GetIsSpent(),
			Unrolled: v.GetIsUnrolled(), SpentBy: v.GetSpentBy(), SettledBy: v.GetSettledBy(),
			ArkTxid: v.GetArkTxid(), Assets: assets,
		})
	}
	return out
}

func grpcTarget(url string) (string, credentials.TransportCredentials) {
	creds := insecure.NewCredentials()
	port := "80"
	if strings.HasPrefix(url, "https://") {
		creds = credentials.NewTLS(nil)
		port = "443"
	}
	target := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"), "/")
	if !strings.Contains(target, ":") {
		target += ":" + port
	}
	return target, creds
}

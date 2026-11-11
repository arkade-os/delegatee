package arkd

import (
	"context"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/executor/internal/core/ports"
	log "github.com/sirupsen/logrus"
)

// blockExpiryLimit is the first batch expiry arkd gives in seconds rather than blocks.
const blockExpiryLimit = 512

func (c *Client) BatchEvents(ctx context.Context) (<-chan ports.BatchEvent, func(), error) {
	events, stop, err := c.ark.GetEventStream(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	out := make(chan ports.BatchEvent, 64)
	go func() {
		defer close(out)
		r := trees{intents: &c.intents}
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-events:
				if !ok {
					return
				}
				converted := r.convert(ev)
				if converted == nil {
					continue
				}
				select {
				case out <- converted:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, stop, nil
}

func (c *Client) UpdateTopics(ctx context.Context, add, remove []string) error {
	_, _, _, err := c.ark.ModifyStreamTopics(ctx, add, remove)
	return err
}

// trees collects the transactions of the trees, which arkd streams one by one.
type trees struct {
	intents                 *intents
	batch                   string   // the batch our intents are in
	ours                    []intent // the ones it selected
	vtxoTree, connectorTree []tree.TxTreeNode
}

// convert turns a client-lib event into the domain's, nil when the daemon has no use for it.
func (r *trees) convert(ev clientlib.BatchEventChannel) ports.BatchEvent {
	if ev.Err != nil {
		log.WithError(ev.Err).Warn("batch event stream")
		return nil
	}
	if ev.Connection != nil {
		if ev.Connection.State == clientlib.StreamConnectionStateReconnected {
			return ports.StreamReconnected{}
		}
		return nil
	}
	switch e := ev.Event.(type) {
	case clientlib.BatchStartedEvent:
		r.vtxoTree, r.connectorTree = nil, nil
		r.intents.settle(time.Second)
		r.batch, r.ours = e.Id, r.intents.selected(e.HashedIntentIds)
		expiry := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: uint32(e.BatchExpiry)}
		if e.BatchExpiry >= blockExpiryLimit {
			expiry.Type = arklib.LocktimeTypeSecond
		}
		return ports.BatchStarted{ID: e.Id, Selected: proofTxids(r.ours), BatchExpiry: expiry}
	case clientlib.TreeTxEvent:
		if e.BatchIndex == 0 {
			r.vtxoTree = append(r.vtxoTree, e.Node)
		} else {
			r.connectorTree = append(r.connectorTree, e.Node)
		}
	case clientlib.TreeSigningStartedEvent:
		if len(r.vtxoTree) == 0 {
			return nil
		}
		vtxoTree, err := tree.NewTxTree(r.vtxoTree)
		if err != nil {
			log.WithError(err).WithField("batch", e.Id).Warn("vtxo tree of a batch")
			return nil
		}
		return ports.TreeSigningStarted{
			ID: e.Id, UnsignedCommitmentTx: e.UnsignedCommitmentTx, CosignersPubkeys: e.CosignersPubkeys, VtxoTree: vtxoTree,
		}
	case clientlib.TreeNoncesAggregatedEvent:
		return ports.TreeNoncesAggregated{ID: e.Id, TreeNonces: e.Nonces}
	case clientlib.BatchFinalizationEvent:
		var connectors *tree.TxTree
		if len(r.connectorTree) > 0 {
			var err error
			if connectors, err = tree.NewTxTree(r.connectorTree); err != nil {
				log.WithError(err).WithField("batch", e.Id).Warn("connector tree of a batch")
				return nil
			}
		}
		return ports.BatchFinalization{ID: e.Id, CommitmentTx: e.Tx, ConnectorTree: connectors}
	case clientlib.BatchFinalizedEvent:
		r.end(e.Id)
		return ports.BatchFinalized{ID: e.Id, CommitmentTxid: e.Txid}
	case clientlib.BatchFailedEvent:
		var blame []string
		if e.Id == r.batch {
			blame = blamed(e.Reason, r.ours)
		}
		r.end(e.Id)
		return ports.BatchFailed{ID: e.Id, Reason: e.Reason, Blamed: blame}
	}
	return nil
}

func (r *trees) end(batch string) {
	if batch == r.batch {
		r.intents.forget(r.ours)
		r.ours = nil
	}
}

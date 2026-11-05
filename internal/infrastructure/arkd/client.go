// Package arkd adapts arkd's client-lib to the core ports.
package arkd

import (
	"cmp"
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// Client is arkd and its indexer, both served at one URL.
type Client struct {
	*Indexer
	ark     clientlib.Client
	intents intents
}

type TransactionStream interface {
	GetTransactionsStream(ctx context.Context) (<-chan clientlib.TransactionEvent, func(), error)
}

type Indexer struct {
	indexer clientlib.Indexer
	stream  TransactionStream
}

func NewIndexer(indexer clientlib.Indexer, stream TransactionStream) *Indexer {
	return &Indexer{indexer: indexer, stream: stream}
}

func NewClient(url string) (*Client, error) {
	url = strings.TrimSuffix(url, "/")
	ark, err := client.NewClient(url, "delegateed")
	if err != nil {
		return nil, fmt.Errorf("connect to arkd: %w", err)
	}
	idx, err := indexer.NewClient(url)
	if err != nil {
		ark.Close()
		return nil, fmt.Errorf("connect to the indexer: %w", err)
	}
	return &Client{Indexer: NewIndexer(idx, ark), ark: ark}, nil
}

func (c *Client) Info(ctx context.Context) (ports.ArkInfo, error) {
	info, err := c.ark.GetInfo(ctx)
	if err != nil {
		return ports.ArkInfo{}, err
	}
	signer, err := parseKey(info.SignerPubKey)
	if err != nil {
		return ports.ArkInfo{}, fmt.Errorf("arkd signer key: %w", err)
	}
	forfeit, err := parseKey(info.ForfeitPubKey)
	if err != nil {
		return ports.ArkInfo{}, fmt.Errorf("arkd forfeit key: %w", err)
	}
	addr, err := address.DecodeAddress(info.ForfeitAddress, nil)
	if err != nil {
		return ports.ArkInfo{}, fmt.Errorf("arkd forfeit address: %w", err)
	}
	forfeitScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return ports.ArkInfo{}, err
	}
	unroll, err := hex.DecodeString(info.CheckpointTapscript)
	if err != nil {
		return ports.ArkInfo{}, fmt.Errorf("arkd checkpoint tapscript: %w", err)
	}
	return ports.ArkInfo{
		Network: clientlib.NetworkFromString(info.Network), SignerPubkey: signer, ForfeitPubkey: forfeit, ForfeitOutputScript: forfeitScript, Dust: info.Dust,
		IntentFees: info.Fees.IntentFees, CheckpointTapscript: unroll,
		SessionDuration: time.Duration(info.SessionDuration) * time.Second,
	}, nil
}

func (c *Client) RegisterIntent(ctx context.Context, proof, message string) error {
	txid, err := proofTxid(proof)
	if err != nil {
		return err
	}
	c.intents.begin()
	id, err := c.ark.RegisterIntent(ctx, proof, message)
	c.intents.end(txid, id)
	return err
}

func (c *Client) ConfirmRegistration(ctx context.Context, proofTxid string) error {
	id, ok := c.intents.id(proofTxid)
	if !ok {
		return fmt.Errorf("intent %s is not registered", proofTxid)
	}
	return c.ark.ConfirmRegistration(ctx, id)
}

func (c *Client) SubmitTreeNonces(ctx context.Context, batchID, cosigner string, nonces tree.TreeNonces) error {
	return c.ark.SubmitTreeNonces(ctx, batchID, cosigner, nonces)
}

func (c *Client) SubmitTreeSignatures(ctx context.Context, batchID, cosigner string, signatures tree.TreePartialSigs) error {
	return c.ark.SubmitTreeSignatures(ctx, batchID, cosigner, signatures)
}

func (c *Client) SubmitSignedForfeitTxs(ctx context.Context, signedForfeits []string, signedCommitmentTx string) error {
	return c.ark.SubmitSignedForfeitTxs(ctx, signedForfeits, signedCommitmentTx)
}

func (c *Client) SubmitTx(ctx context.Context, signedArkTx string, checkpoints []string) (string, string, []string, error) {
	return c.ark.SubmitTx(ctx, signedArkTx, checkpoints)
}

func (w *Indexer) Vtxos(ctx context.Context, scripts []string) ([]ports.Output, error) {
	var out []ports.Output
	for start := 0; start < len(scripts); start += ports.MaxScripts {
		chunk := scripts[start:min(start+ports.MaxScripts, len(scripts))]
		for page := int32(0); ; {
			opts := []clientlib.GetVtxosOption{clientlib.WithScripts(chunk)}
			if page > 0 {
				opts = append(opts, clientlib.WithVtxosPage(&clientlib.PageRequest{Index: page}))
			}
			resp, err := w.indexer.GetVtxos(ctx, opts...)
			if err != nil {
				return nil, err
			}
			for _, v := range resp.Vtxos {
				out = append(out, toOutput(v))
			}
			if resp.Page == nil || resp.Page.Next <= resp.Page.Current {
				break
			}
			page = resp.Page.Next
		}
	}
	return out, nil
}

func (w *Indexer) Subscribe(ctx context.Context, scripts []string) (ports.Subscription, error) {
	return subscribe(ctx, w.indexer, scripts)
}

// VirtualTxs matches by txid: the indexer owes no order.
func (w *Indexer) VirtualTxs(ctx context.Context, txids []string) (map[string]*wire.MsgTx, error) {
	resp, err := w.indexer.GetVirtualTxs(ctx, txids)
	if err != nil {
		return nil, fmt.Errorf("get virtual txs: %w", err)
	}
	txs := make(map[string]*wire.MsgTx, len(txids))
	for _, raw := range resp.Txs {
		ptx, err := psbt.NewFromRawBytes(strings.NewReader(raw), true)
		if err != nil {
			return nil, fmt.Errorf("virtual tx: %w", err)
		}
		txs[ptx.UnsignedTx.TxHash().String()] = ptx.UnsignedTx
	}
	for _, txid := range txids {
		if txs[txid] == nil {
			return nil, fmt.Errorf("virtual tx %s not found", txid)
		}
	}
	return txs, nil
}

func (w *Indexer) Transactions(ctx context.Context) (<-chan string, func(), error) {
	events, stop, err := w.stream.GetTransactionsStream(ctx)
	if err != nil {
		return nil, nil, err
	}
	txs := make(chan string, 64)
	go func() {
		defer close(txs)
		for ev := range events {
			if ev.ArkTx == nil {
				continue
			}
			select {
			case txs <- ev.ArkTx.Tx:
			case <-ctx.Done():
				return
			}
		}
	}()
	return txs, stop, nil
}

func (c *Client) Close() {
	c.indexer.Close()
	c.ark.Close()
}

// toOutput reads a vtxo as an output: a swept or unrolled one is gone too, and what spent it is the
// batch's commitment, else the ark transaction, else what arkd names.
func toOutput(v clientlib.Vtxo) ports.Output {
	o := ports.Output{
		Outpoint: v.Outpoint.String(), Script: v.Script, Amount: v.Amount, ExpiresAt: v.ExpiresAt, CreatedAt: v.CreatedAt,
		Spent: v.Spent || v.Swept || v.Unrolled,
	}
	if o.Spent {
		o.SpentBy = cmp.Or(v.SettledBy, v.ArkTxid, v.SpentBy)
	}
	return o
}

func parseKey(s string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return btcec.ParsePubKey(raw)
}

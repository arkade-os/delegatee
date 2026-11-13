// Package emulator adapts the emulator's gRPC client to the core ports.
package emulator

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/tree"
	emulatorclient "github.com/arkade-os/emulator/pkg/client"
	"github.com/arkade-os/executor/internal/core/domain/execution"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/btcsuite/btcd/btcec/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type Client struct {
	conn     *grpc.ClientConn
	emulator emulatorclient.TransportClient
}

// NewClient dials url; https:// enables TLS.
func NewClient(url string) (*Client, error) {
	target, creds := grpcTarget(url)
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connect to emulator: %w", err)
	}
	return &Client{conn: conn, emulator: emulatorclient.NewGRPCClient(conn)}, nil
}

func (c *Client) Info(ctx context.Context) (ports.EmulatorInfo, error) {
	info, err := c.emulator.GetInfo(ctx)
	if err != nil {
		return ports.EmulatorInfo{}, err
	}
	raw, err := hex.DecodeString(info.SignerPublicKey)
	if err != nil {
		return ports.EmulatorInfo{}, fmt.Errorf("emulator signer key: %w", err)
	}
	key, err := btcec.ParsePubKey(raw)
	if err != nil {
		return ports.EmulatorInfo{}, fmt.Errorf("emulator signer key: %w", err)
	}
	return ports.EmulatorInfo{SignerPubkey: key}, nil
}

func (c *Client) SubmitTx(
	ctx context.Context, tx string, checkpoints []string,
) (string, []string, error) {
	return c.emulator.SubmitTx(ctx, tx, checkpoints)
}

func (c *Client) SubmitIntent(ctx context.Context, in execution.Intent) (string, error) {
	return c.emulator.SubmitIntent(ctx, emulatorclient.Intent{Proof: in.Proof, Message: in.Message})
}

func (c *Client) SubmitFinalization(
	ctx context.Context, in execution.Intent, forfeits []string, connectorTree tree.FlatTxTree,
	commitmentTx string,
) ([]string, string, error) {
	return c.emulator.SubmitFinalization(
		ctx, emulatorclient.Intent{Proof: in.Proof, Message: in.Message}, forfeits, connectorTree,
		commitmentTx,
	)
}

func (c *Client) Close() error { return c.conn.Close() }

func grpcTarget(url string) (string, credentials.TransportCredentials) {
	creds := insecure.NewCredentials()
	port := "80"
	if strings.HasPrefix(url, "https://") {
		creds = credentials.NewTLS(nil)
		port = "443"
	}
	target := strings.TrimSuffix(
		strings.TrimPrefix(strings.TrimPrefix(url, "https://"), "http://"),
		"/",
	)
	if !strings.Contains(target, ":") {
		target += ":" + port
	}
	return target, creds
}

package explorer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/arkd/pkg/client-lib/explorer"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"golang.org/x/time/rate"
)

// service adds the block depth of a transaction to client-lib's explorer, and paces every request.
type service struct {
	clientlib.Explorer
	http    *http.Client
	limiter *rate.Limiter
}

// New paces requests at perSecond, one at a time: a shared explorer rate limits a burst by source address.
func New(url string, network arklib.Network, perSecond float64) (ports.Explorer, error) {
	e, err := explorer.NewExplorer(url, network, explorer.WithTracker(false))
	if err != nil {
		return nil, err
	}
	if perSecond <= 0 {
		return nil, fmt.Errorf("explorer rate limit must be positive")
	}
	return &service{Explorer: e, http: &http.Client{Timeout: 10 * time.Second}, limiter: rate.NewLimiter(rate.Limit(perSecond), 1)}, nil
}

func (e *service) wait() { _ = e.limiter.Wait(context.Background()) }

// paced is one request, in turn
func paced[T any](e *service, call func() (T, error)) (T, error) {
	e.wait()
	out, err := call()
	return out, throttledError(err)
}

func (e *service) GetUtxos(addresses []string) ([]clientlib.ExplorerUtxo, error) {
	for i := 1; i < len(addresses); i++ { // one request each
		e.wait()
	}
	return paced(e, func() ([]clientlib.ExplorerUtxo, error) { return e.Explorer.GetUtxos(addresses) })
}

func (e *service) GetTxHex(txid string) (string, error) {
	return paced(e, func() (string, error) { return e.Explorer.GetTxHex(txid) })
}

func (e *service) GetTxOutspends(txid string) ([]clientlib.SpentStatus, error) {
	return paced(e, func() ([]clientlib.SpentStatus, error) { return e.Explorer.GetTxOutspends(txid) })
}

func (e *service) GetFeeRate() (float64, error) {
	return paced(e, func() (float64, error) { return e.Explorer.GetFeeRate() })
}

func (e *service) Broadcast(txs ...string) (string, error) {
	return paced(e, func() (string, error) { return e.Explorer.Broadcast(txs...) })
}

func (e *service) Confirmations(txid string) (int, error) {
	raw, err := e.read("/tx/" + txid + "/status")
	if err != nil {
		return 0, err
	}
	var status struct {
		Confirmed bool  `json:"confirmed"`
		Height    int64 `json:"block_height"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return 0, err
	}
	if !status.Confirmed {
		return 0, nil
	}
	tip, err := paced(e, e.GetBlockHeight)
	if err != nil {
		return 0, err
	}
	if status.Height <= 0 || tip < status.Height {
		return 0, fmt.Errorf("inconsistent explorer block heights")
	}
	return int(tip - status.Height + 1), nil
}

func (e *service) ChainTip() (ports.ChainTip, error) {
	raw, err := e.read("/blocks") // the latest blocks, tip first
	if err != nil {
		return ports.ChainTip{}, err
	}
	var blocks []struct {
		Height     int64 `json:"height"`
		MedianTime int64 `json:"mediantime"`
	}
	if err := json.Unmarshal(raw, &blocks); err != nil {
		return ports.ChainTip{}, err
	}
	if len(blocks) == 0 || blocks[0].Height <= 0 || blocks[0].MedianTime <= 0 {
		return ports.ChainTip{}, fmt.Errorf("explorer: tip block without height or median time")
	}
	return ports.ChainTip{Height: blocks[0].Height, MedianTime: blocks[0].MedianTime}, nil
}

func (e *service) read(path string) ([]byte, error) {
	e.wait()
	resp, err := e.http.Get(strings.TrimRight(e.BaseUrl(), "/") + path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusOK:
		return io.ReadAll(io.LimitReader(resp.Body, 65536))
	case http.StatusTooManyRequests, http.StatusServiceUnavailable:
		return nil, fmt.Errorf("explorer: HTTP %d: %w", resp.StatusCode, ports.ErrThrottled)
	}
	return nil, fmt.Errorf("explorer: HTTP %d", resp.StatusCode)
}

// throttledError marks a rate limited answer client-lib reports by its body alone: Cloudflare's is "error code: 1015".
func throttledError(err error) error {
	if err == nil {
		return nil
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "error code: 1015") || strings.Contains(msg, "too many requests") || strings.Contains(msg, "status 429") {
		return fmt.Errorf("%w: %w", ports.ErrThrottled, err)
	}
	return err
}

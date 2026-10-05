package explorer

import (
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
)

// service adds the block depth of a transaction to client-lib's explorer.
type service struct {
	clientlib.Explorer
	http *http.Client
}

func New(url string, network arklib.Network) (ports.Explorer, error) {
	e, err := explorer.NewExplorer(url, network, explorer.WithTracker(false))
	if err != nil {
		return nil, err
	}
	return &service{Explorer: e, http: &http.Client{Timeout: 10 * time.Second}}, nil
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
	tip, err := e.GetBlockHeight()
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
	resp, err := e.http.Get(strings.TrimRight(e.BaseUrl(), "/") + path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("explorer: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65536))
}

package execution

import (
	"context"
	"errors"
	"testing"

	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/stretchr/testify/require"
)

type vtxosIndexer struct {
	ports.Indexer
	vtxos   []ports.Output
	err     error
	queried []string
}

func (f *vtxosIndexer) Vtxos(_ context.Context, scripts []string) ([]ports.Output, error) {
	f.queried = scripts
	return f.vtxos, f.err
}

func TestSweptAsksArkdForTheOffchainCoins(t *testing.T) {
	f := &vtxosIndexer{vtxos: []ports.Output{{Outpoint: "a:0", Swept: true}, {Outpoint: "b:0"}}}
	s := &Service{indexer: f}
	coins := []delegation.Coin{
		{Outpoint: "a:0", Script: "aa"}, {Outpoint: "b:0", Script: "aa"}, {Outpoint: "c:0", Script: "cc", Onchain: true},
	}
	swept, err := s.swept(context.Background(), coins)
	require.NoError(t, err)
	require.Equal(t, []bool{true, false, false}, swept)
	require.Equal(t, []string{"aa"}, f.queried, "each script once, onchain coins are never swept")

	f.queried = nil
	swept, err = s.swept(context.Background(), coins[2:])
	require.NoError(t, err)
	require.Equal(t, []bool{false}, swept)
	require.Nil(t, f.queried, "nothing to ask for boarding inputs")

	f.err = errors.New("down")
	_, err = s.swept(context.Background(), coins)
	require.ErrorContains(t, err, "down")
}

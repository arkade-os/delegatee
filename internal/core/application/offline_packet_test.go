package application

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestOfflineReceivePacketStartsWithoutClientRegistration(t *testing.T) {
	e := newTestEnv(t)
	key, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{key}
	id := e.trust(t, e.fixture(t, "offline_receive.json"))
	stream, err := e.svc.RegisterStreamDelegation(t.Context(), id, nil)
	require.NoError(t, err)
	require.True(t, stream.IsStream())
}

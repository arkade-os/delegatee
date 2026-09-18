package application

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/client-lib/types"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/stretchr/testify/require"
)

const testDelegatePubKey = "02" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func TestRenewalCovenant(t *testing.T) {
	require.ErrorIs(t, validateParams(domain.Params{RenewalWindow: 0}), ErrInvalidScript)
	require.Error(t, validateParams(domain.Params{RenewalWindow: 10, MaxFee: -1}))
	require.NoError(t, validateParams(domain.Params{RenewalWindow: 10}))
	require.Error(t, validateParams(domain.Params{RenewalWindow: 1 << 62}), "overflows time.Duration")
	require.Error(t, validateParams(domain.Params{RenewalWindow: 10, MaxFee: 1 << 62}))

	// changing the zero-fee script moves every existing delegate address
	noFee, err := buildArkadeScript(testDelegatePubKey, domain.Params{RenewalWindow: 1024})
	require.NoError(t, err)
	require.Equal(t, goldenNoFeeScript, hex.EncodeToString(noFee))
	withFee, err := buildArkadeScript(testDelegatePubKey, domain.Params{RenewalWindow: 1024, MaxFee: 150})
	require.NoError(t, err)
	require.Equal(t, goldenMaxFeeScript, hex.EncodeToString(withFee))

	now := time.Unix(1_000_000, 0)
	params := domain.Params{RenewalWindow: 100, MaxFee: 150}
	require.Equal(t, now, dueAt(types.Vtxo{ExpiresAt: now.Add(100 * time.Second)}, params))
	// may pay fees and the window covers the whole life: wait for half of it
	short := types.Vtxo{CreatedAt: now, ExpiresAt: now.Add(60 * time.Second)}
	require.Equal(t, now.Add(30*time.Second), dueAt(short, params))
	require.Equal(t, now.Add(-40*time.Second), dueAt(short, domain.Params{RenewalWindow: 100}))

	v := types.Vtxo{Amount: 1000}
	out, err := renewalOutput(v, []byte{0x51}, params, 150)
	require.NoError(t, err)
	require.Equal(t, int64(850), out.Value)
	_, err = renewalOutput(v, nil, params, 151)
	require.ErrorContains(t, err, "exceeds the delegation max fee")
	_, err = renewalOutput(v, nil, params, -1)
	require.ErrorContains(t, err, "negative intent fee")
	_, err = renewalOutput(types.Vtxo{Amount: 1 << 63}, nil, params, 0)
	require.ErrorContains(t, err, "not a valid amount")
	_, err = renewalOutput(types.Vtxo{Amount: 100}, nil, params, 100)
	require.ErrorContains(t, err, "not covered")
}

// goldenPrefix is everything before the value rules; the zero-fee script is
// byte for byte the covenant of the first release.
const (
	goldenPrefix       = "db02000494dc0474797065f86908726567697374657288166f6e636861696e5f6f75747075745f696e6465786573f869025b5d8817636f7369676e6572735f7075626c69635f6b6579732e30f869423032373962653636376566396463626261633535613036323935636538373062303730323962666364623264636532386439353966323831356231366638313739388817636f7369676e6572735f7075626c69635f6b6579732e31f8916975"
	goldenNoFeeScript  = goldenPrefix + "cd8c5700f7"
	goldenMaxFeeScript = goldenPrefix + "cd8ccf02960093cdc9a269cd8c5500f7"
)

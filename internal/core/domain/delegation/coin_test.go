package delegation

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWatchedScriptOwnerPrefersStreamSpawnedThenOldestDelegation(t *testing.T) {
	for name, tc := range map[string]struct {
		claims []Claim
		want   int64
	}{
		"one":                    {[]Claim{{DelegationID: 4}}, 4},
		"oldest public":          {[]Claim{{DelegationID: 9}, {DelegationID: 3}, {DelegationID: 5}}, 3},
		"spawned over public":    {[]Claim{{DelegationID: 1}, {DelegationID: 8, Spawned: true}}, 8},
		"oldest spawned":         {[]Claim{{DelegationID: 7, Spawned: true}, {DelegationID: 6, Spawned: true}, {DelegationID: 1}}, 6},
		"order does not matter":  {[]Claim{{DelegationID: 8, Spawned: true}, {DelegationID: 1}}, 8},
		"spawned younger public": {[]Claim{{DelegationID: 2}, {DelegationID: 3, Spawned: true}, {DelegationID: 1}}, 3},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, Watched{Claims: tc.claims}.Owner().DelegationID)
		})
	}
}

func TestConfirmationsAreZeroInMempoolAndCountInclusiveFromTipHeight(t *testing.T) {
	tip := Tip{Height: 110}
	require.Equal(t, 0, tip.Confirmations(0), "mempool")
	require.Equal(t, 1, tip.Confirmations(110))
	require.Equal(t, 11, tip.Confirmations(100))
	require.Equal(t, 0, tip.Confirmations(111), "a height above the tip")
}

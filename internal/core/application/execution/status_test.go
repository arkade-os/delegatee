package execution

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestAliveFailsWhenWorkIsDueAndTheLoopIsSilent(t *testing.T) {
	s := NewService(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, Limits{LoopStall: time.Minute})
	now := time.Unix(1_800_000_000, 0)

	require.NoError(t, s.Alive(now), "nothing is armed")

	s.wake.Store(now.Add(time.Hour).UnixNano())
	require.NoError(t, s.Alive(now.Add(time.Hour)), "work is not due before the timer fires")
	require.NoError(t, s.Alive(now.Add(time.Hour+30*time.Second)), "within the bound")
	require.Error(t, s.Alive(now.Add(time.Hour+2*time.Minute)))

	s.beat.Store(now.Add(time.Hour + 90*time.Second).UnixNano())
	require.NoError(t, s.Alive(now.Add(time.Hour+2*time.Minute)), "the loop handled something since")
}

package arkd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShardsPlaceFillsThenOpens(t *testing.T) {
	s := &shards{size: 3}
	added := s.place([]string{"a", "b", "c", "d"})
	require.Len(t, added, 2)
	require.ElementsMatch(t, []string{"a", "b", "c"}, added[0])
	require.Equal(t, []string{"d"}, added[1])

	added = s.place([]string{"d", "e"})
	require.Len(t, added, 2)
	require.Empty(t, added[0])
	require.Equal(t, []string{"e"}, added[1])
	require.ElementsMatch(t, []string{"d", "e"}, s.scripts(1))
}

func TestShardsDropFreesRoom(t *testing.T) {
	s := &shards{size: 2}
	s.place([]string{"a", "b", "c"})
	removed := s.drop([]string{"a", "zz"})
	require.Equal(t, [][]string{{"a"}, nil}, removed)
	require.False(t, s.has("a"))

	added := s.place([]string{"d"})
	require.Equal(t, [][]string{{"d"}, nil}, added)
}

func TestShardsNeverExceedSize(t *testing.T) {
	s := &shards{size: 1000}
	scripts := make([]string, 2500)
	for i := range scripts {
		scripts[i] = fmt.Sprint(i)
	}
	added := s.place(scripts)
	require.Len(t, added, 3)
	for i, set := range s.sets {
		require.LessOrEqual(t, len(set), 1000)
		require.Len(t, added[i], len(set))
	}
}

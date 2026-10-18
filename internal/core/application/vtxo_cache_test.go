package application

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/ports"
	"github.com/stretchr/testify/require"
)

type cacheIndexer struct {
	ports.Indexer
	mu        sync.Mutex
	coins     map[string][]clientlib.Vtxo
	requests  [][]string
	err       error
	onRequest func()
}

func (i *cacheIndexer) GetVtxos(_ context.Context, opts ...clientlib.GetVtxosOption) (*clientlib.VtxosResponse, error) {
	o, err := clientlib.ApplyGetVtxosOptions(opts...)
	if err != nil {
		return nil, err
	}
	i.mu.Lock()
	i.requests = append(i.requests, append([]string(nil), o.Scripts...))
	result := &clientlib.VtxosResponse{}
	for _, script := range o.Scripts {
		result.Vtxos = append(result.Vtxos, i.coins[script]...)
	}
	err, hook := i.err, i.onRequest
	i.mu.Unlock()
	if hook != nil {
		hook()
	}
	return result, err
}

func TestVtxoCacheRefresh(t *testing.T) {
	i := &cacheIndexer{coins: map[string][]clientlib.Vtxo{"a": {{Script: "a", Amount: 1}}}}
	s := &service{indexer: i, wake: make(chan struct{}, 1), incrementalRefresh: true}
	got, err := s.scanVtxos(t.Context(), []string{"a", "b"})
	require.NoError(t, err)
	require.Equal(t, uint64(1), got["a"][0].Amount)
	require.Contains(t, got, "b")
	i.coins["a"] = []clientlib.Vtxo{{Script: "a", Amount: 2}}
	got, err = s.scanVtxos(t.Context(), []string{"a", "b"})
	require.NoError(t, err)
	require.Len(t, i.requests, 1)
	require.Equal(t, uint64(1), got["a"][0].Amount)
	for range 100 {
		s.invalidateScripts("a")
	}
	require.Len(t, s.wake, 1)
	got, err = s.scanVtxos(t.Context(), []string{"a", "b"})
	require.NoError(t, err)
	require.Equal(t, uint64(2), got["a"][0].Amount)
	require.Equal(t, []string{"a"}, i.requests[1])
	i.coins["a"] = nil
	s.invalidateAllScripts()
	got, err = s.scanVtxos(t.Context(), []string{"a", "c"})
	require.NoError(t, err)
	require.Empty(t, got["a"])
	require.NotContains(t, got, "b")
	require.Contains(t, got, "c")
}

func TestVtxoCacheInvalidationDuringRequest(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			i := &cacheIndexer{coins: map[string][]clientlib.Vtxo{}}
			s := &service{indexer: i, wake: make(chan struct{}, 1), incrementalRefresh: true}
			_, err := s.scanVtxos(t.Context(), []string{"a", "b"})
			require.NoError(t, err)
			s.invalidateScripts("a")
			i.onRequest = func() { s.invalidateScripts("b") }
			if fail {
				i.err = errors.New("offline")
			}
			_, err = s.scanVtxos(t.Context(), []string{"a", "b"})
			if fail {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			i.onRequest, i.err = nil, nil
			_, err = s.scanVtxos(t.Context(), []string{"a", "b"})
			require.NoError(t, err)
			if fail {
				require.ElementsMatch(t, []string{"a", "b"}, i.requests[2])
			} else {
				require.Equal(t, []string{"b"}, i.requests[2])
			}
		})
	}
}

func TestVtxoCachePeriodicRefresh(t *testing.T) {
	i := &cacheIndexer{coins: map[string][]clientlib.Vtxo{}}
	s := &service{indexer: i, wake: make(chan struct{}, 1), incrementalRefresh: true, pollInterval: time.Minute}
	_, err := s.scanVtxos(t.Context(), []string{"a"})
	require.NoError(t, err)
	i.coins["a"] = []clientlib.Vtxo{{Script: "a", Amount: 3}}
	s.lastFullRefresh = time.Now().Add(-2 * time.Minute)
	got, err := s.scanVtxos(t.Context(), []string{"a"})
	require.NoError(t, err)
	require.Equal(t, uint64(3), got["a"][0].Amount)
	require.WithinDuration(t, time.Now(), s.lastFullRefresh, time.Second)
}

func TestVtxoCacheFullInvalidationAndFailedRefresh(t *testing.T) {
	i := &cacheIndexer{coins: map[string][]clientlib.Vtxo{"a": {{Script: "a", Amount: 1}}}}
	s := &service{indexer: i, wake: make(chan struct{}, 1), incrementalRefresh: true}
	scripts := []string{"a", "b"}
	_, err := s.scanVtxos(t.Context(), scripts)
	require.NoError(t, err)
	last := s.lastFullRefresh
	i.coins["a"] = []clientlib.Vtxo{{Script: "a", Amount: 2}}
	i.err = errors.New("offline")
	s.markScriptsStale()
	got, err := s.scanVtxos(t.Context(), scripts)
	require.Error(t, err)
	require.Nil(t, got)
	require.Equal(t, last, s.lastFullRefresh)
	require.Equal(t, uint64(1), s.vtxoCache["a"][0].Amount)
	i.err = nil
	i.onRequest = s.markScriptsStale
	got, err = s.scanVtxos(t.Context(), scripts)
	require.NoError(t, err)
	require.Equal(t, uint64(2), got["a"][0].Amount)
	i.onRequest = nil
	_, err = s.scanVtxos(t.Context(), scripts)
	require.NoError(t, err)
	require.Len(t, i.requests, 4)
	for _, request := range i.requests {
		require.ElementsMatch(t, scripts, request)
	}
}

func TestVtxoCache50000Scripts(t *testing.T) {
	i := &cacheIndexer{coins: map[string][]clientlib.Vtxo{}}
	s := &service{indexer: i, wake: make(chan struct{}, 1), incrementalRefresh: true}
	scripts := make([]string, 50000)
	for n := range scripts {
		scripts[n] = fmt.Sprintf("5120%064x", n)
	}
	_, err := s.scanVtxos(t.Context(), scripts)
	require.NoError(t, err)
	require.Len(t, i.requests, 500)
	s.invalidateScripts(scripts[0], scripts[49999])
	_, err = s.scanVtxos(t.Context(), scripts)
	require.NoError(t, err)
	require.Len(t, i.requests, 501)
	require.ElementsMatch(t, []string{scripts[0], scripts[49999]}, i.requests[500])
}

func TestWakeScansCannotPostponeFullReconciliation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newTestEnv(t)
		manyDelegations(t, e, 2)
		i := &cacheIndexer{Indexer: e.indexer, coins: map[string][]clientlib.Vtxo{}}
		for _, v := range e.indexer.vtxos {
			i.coins[v.Script] = []clientlib.Vtxo{v}
		}
		e.svc.indexer = i
		e.svc.pollInterval = 5 * time.Second
		e.svc.Start()
		synctest.Wait()
		require.Len(t, i.requests, 1)
		first := e.svc.lastFullRefresh
		i.mu.Lock()
		i.coins = map[string][]clientlib.Vtxo{}
		i.mu.Unlock()
		for range 6 {
			time.Sleep(time.Second)
			e.svc.wakeScan()
			synctest.Wait()
		}
		require.Len(t, i.requests, 2)
		require.Equal(t, 5*time.Second, e.svc.lastFullRefresh.Sub(first))
		require.Equal(t, e.svc.lastFullRefresh.Add(e.svc.pollInterval), e.svc.Status().NextScan)
		for _, holding := range e.svc.Status().Holdings {
			require.Zero(t, holding.Vtxos)
		}
		e.svc.Stop()
	})
}

func TestCacheInvalidationsRespectScanBackoff(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		e := newTestEnv(t)
		manyDelegations(t, e, 1)
		i := &cacheIndexer{Indexer: e.indexer, coins: map[string][]clientlib.Vtxo{}}
		script := e.indexer.vtxos[0].Script
		i.coins[script] = e.indexer.vtxos
		e.svc.indexer = i
		e.svc.pollInterval = 5 * time.Second
		e.svc.Start()
		synctest.Wait()
		first := e.svc.lastFullRefresh
		i.mu.Lock()
		i.err = ports.ErrThrottled
		i.mu.Unlock()
		wake := func() {
			time.Sleep(time.Second)
			e.svc.invalidateScripts(script)
			synctest.Wait()
		}
		wake()
		require.Len(t, i.requests, 2)
		require.Equal(t, first.Add(6*time.Second), e.svc.Status().NextScan)
		for range 4 {
			wake()
		}
		require.Len(t, i.requests, 2)
		wake()
		require.Len(t, i.requests, 3)
		require.Equal(t, first.Add(16*time.Second), e.svc.Status().NextScan)
		require.True(t, e.svc.Status().Throttled)
		require.Equal(t, first, e.svc.lastFullRefresh)
		i.mu.Lock()
		i.err = nil
		i.mu.Unlock()
		for range 9 {
			wake()
		}
		require.Len(t, i.requests, 3)
		wake()
		require.Len(t, i.requests, 4)
		require.False(t, e.svc.Status().Throttled)
		require.Equal(t, first.Add(16*time.Second), e.svc.lastFullRefresh)
		e.svc.Stop()
	})
}

func TestFailedDiscoveryDoesNotAdvanceFullReconciliation(t *testing.T) {
	e := newTestEnv(t)
	board := e.boarding(t, e.userKey.PubKey())
	e.deposit(t, board, 3000)
	e.explorer.utxoErr = ports.ErrThrottled
	previous := time.Now().Add(-time.Hour)
	e.svc.lastFullRefresh = previous
	require.ErrorIs(t, e.svc.scan(t.Context()), ports.ErrThrottled)
	require.Equal(t, previous, e.svc.lastFullRefresh)
	require.True(t, e.svc.vtxoDirtyAll)
}

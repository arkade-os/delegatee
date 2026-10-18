package application

import (
	"context"
	"maps"
	"time"

	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
)

func (s *service) invalidateScripts(scripts ...string) {
	s.markScriptsDirty(scripts...)
	s.wakeScan()
}

func (s *service) markScriptsDirty(scripts ...string) {
	s.vtxoDirtyMu.Lock()
	if s.vtxoDirty == nil {
		s.vtxoDirty = make(map[string]struct{})
	}
	for _, script := range scripts {
		if script != "" {
			s.vtxoDirty[script] = struct{}{}
		}
	}
	s.vtxoDirtyMu.Unlock()
}

func (s *service) invalidateAllScripts() {
	s.markScriptsStale()
	s.wakeScan()
}

func (s *service) markScriptsStale() {
	s.vtxoDirtyMu.Lock()
	s.vtxoDirtyAll = true
	s.vtxoDirtyMu.Unlock()
}

func (s *service) scanVtxos(ctx context.Context, scripts []string) (map[string][]clientlib.Vtxo, error) {
	s.vtxoDirtyMu.Lock()
	dirty, full := s.vtxoDirty, s.vtxoDirtyAll
	s.vtxoDirty, s.vtxoDirtyAll = nil, false
	s.vtxoDirtyMu.Unlock()
	full = full || !s.incrementalRefresh || s.lastFullRefresh.IsZero() ||
		(s.pollInterval > 0 && time.Since(s.lastFullRefresh) >= s.pollInterval)
	wanted := make(map[string]struct{}, len(scripts))
	var refresh []string
	for _, script := range scripts {
		if _, duplicate := wanted[script]; duplicate {
			continue
		}
		wanted[script] = struct{}{}
		_, cached := s.vtxoCache[script]
		_, changed := dirty[script]
		if full || !cached || changed {
			refresh = append(refresh, script)
		}
	}
	coins, err := s.spendableVtxos(ctx, refresh)
	if err != nil {
		s.vtxoDirtyMu.Lock()
		if s.vtxoDirty == nil {
			s.vtxoDirty = make(map[string]struct{})
		}
		maps.Copy(s.vtxoDirty, dirty)
		s.vtxoDirtyAll = s.vtxoDirtyAll || full
		s.vtxoDirtyMu.Unlock()
		return nil, err
	}
	if s.vtxoCache == nil {
		s.vtxoCache = make(map[string][]clientlib.Vtxo, len(scripts))
	}
	for _, script := range refresh {
		s.vtxoCache[script] = coins[script]
	}
	for script := range s.vtxoCache {
		if _, ok := wanted[script]; !ok {
			delete(s.vtxoCache, script)
		}
	}
	if full {
		s.lastFullRefresh = time.Now()
	}
	return s.vtxoCache, nil
}

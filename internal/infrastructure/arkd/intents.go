package arkd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/psbt/v2"
)

// ourFaults are what a failed batch says when we did not send in time, or refused its batch.
var ourFaults = []string{"nonce", "signature", "forfeit", "refus"}

// intents maps the proof txids that name our intents in the core to arkd's intent ids.
type intents struct {
	mu      sync.Mutex
	ids     map[string]string
	pending int // registrations whose id arkd has not returned yet
}

// intent is one of ours: its proof txid and arkd's id.
type intent struct{ proofTxid, id string }

func (m *intents) begin() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending++
}

// end closes a registration begun, recording arkd's id unless it failed.
func (m *intents) end(proofTxid, id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pending--
	if id == "" {
		return
	}
	if m.ids == nil {
		m.ids = map[string]string{}
	}
	m.ids[proofTxid] = id
}

// settle waits at most d for the registrations in flight: arkd may select an intent before its id
// reaches us.
func (m *intents) settle(d time.Duration) {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		m.mu.Lock()
		pending := m.pending
		m.mu.Unlock()
		if pending == 0 {
			return
		}
	}
}

func (m *intents) id(proofTxid string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.ids[proofTxid]
	return id, ok
}

// selected returns the intents of ours whose hashed id a batch lists.
func (m *intents) selected(hashes []string) []intent {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []intent
	for proofTxid, id := range m.ids {
		sum := sha256.Sum256([]byte(id))
		if slices.Contains(hashes, hex.EncodeToString(sum[:])) {
			out = append(out, intent{proofTxid, id})
		}
	}
	return out
}

func (m *intents) forget(ours []intent) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, in := range ours {
		delete(m.ids, in.proofTxid)
	}
}

func proofTxids(ours []intent) []string {
	var out []string
	for _, in := range ours {
		out = append(out, in.proofTxid)
	}
	return out
}

// blamed lists the proof txids of the intents a failed batch is held against: the ones its reason
// names, else all of ours when it says our nonces, signatures or forfeits were wrong or late, or we
// refused.
func blamed(reason string, ours []intent) []string {
	var named []string
	for _, in := range ours {
		if in.id != "" && strings.Contains(reason, in.id) {
			named = append(named, in.proofTxid)
		}
	}
	if len(named) > 0 {
		return named
	}
	reason = strings.ToLower(reason)
	for _, fault := range ourFaults {
		if strings.Contains(reason, fault) {
			return proofTxids(ours)
		}
	}
	return nil
}

func proofTxid(proof string) (string, error) {
	p, err := psbt.NewFromRawBytes(strings.NewReader(proof), true)
	if err != nil {
		return "", fmt.Errorf("intent proof: %w", err)
	}
	return p.UnsignedTx.TxHash().String(), nil
}

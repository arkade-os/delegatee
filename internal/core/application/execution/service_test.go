package execution

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/arkade-os/executor/templates"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestTrack(t *testing.T) {
	for _, busy := range []bool{false, true} {
		name := "idle"
		if busy {
			name = "busy"
		}
		t.Run(name, func(t *testing.T) {
			s := &Service{pending: map[int64]*pending{}}
			a := delegation.Attempt{ID: 1, Coins: []string{"coin:0"}, Status: delegation.Submitted}
			p := s.track(a)
			require.Same(t, p, s.pending[a.ID])
			require.Equal(t, a, p.attempt)
			require.True(t, p.busy)
			require.NotNil(t, p.spent)
			require.Empty(t, p.spent)
			require.Zero(t, p.landBy)

			spent := p.spent
			spent["coin:0"] = "commitment"
			landBy := time.Unix(1_800_000_000, 0)
			p.busy, p.landBy = busy, landBy
			a.AddTx(delegation.Tx{Txid: "commitment", Onchain: true, Spends: true})

			updated := s.track(a)
			require.Same(t, p, updated)
			require.Equal(t, a, updated.attempt)
			require.Equal(t, busy, updated.busy)
			require.Equal(t, landBy, updated.landBy)
			require.Equal(t, map[string]string{"coin:0": "commitment"}, updated.spent)
			spent["coin:1"] = "commitment"
			require.Equal(t, "commitment", updated.spent["coin:1"])
			require.Len(t, s.pending, 1)
		})
	}
}

func TestDueAt(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	inst := instance(t, templates.Templates["renew.json"], map[string]string{
		"owner": hex.EncodeToString(
			owner.PubKey().SerializeCompressed(),
		),
		"exit_delay":     scriptNum(1<<22 | 1),
		"renewal_window": scriptNum(1024),
		"max_fee":        scriptNum(1000),
	})
	c := delegation.Coin{
		Outpoint: strings.Repeat("ab", 32) + ":1", Amount: 1000, CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}
	require.Equal(t, c.ExpiresAt.Add(-1024*time.Second), dueAt(inst, c, now))

	// a short life halves the lead
	c.ExpiresAt = now.Add(10 * time.Minute)
	require.Equal(t, now.Add(5*time.Minute), dueAt(inst, c, now))

	// without an expiry the schedule cannot be placed: an hour from now
	c.ExpiresAt = time.Time{}
	require.Equal(t, now.Add(time.Hour), dueAt(inst, c, now))

	// no schedule: due at creation, or now when unknown
	plain := instance(t, fixture(t, "minimal.json"), nil)
	c = delegation.Coin{Outpoint: "bad outpoint", Amount: 1, CreatedAt: now.Add(-time.Minute)}
	require.Equal(t, c.CreatedAt, dueAt(plain, c, now))
	c.CreatedAt = time.Time{}
	require.Equal(t, now, dueAt(plain, c, now))
}

func TestDueAtOnchainWaitsForConfirmations(t *testing.T) {
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	inst := instance(t, templates.Templates["board.json"], map[string]string{
		"owner": hex.EncodeToString(
			owner.PubKey().SerializeCompressed(),
		),
		"boarding_exit_delay": scriptNum(1<<22 | 2),
		"exit_delay": scriptNum(
			1<<22 | 1,
		),
		"renewal_window": scriptNum(1024),
		"max_fee":        scriptNum(1000),
	})
	c := delegation.Coin{
		Outpoint: strings.Repeat("ab", 32) + ":0", Amount: 1000, CreatedAt: now.Add(-time.Minute),
		Onchain: true,
	}
	require.Equal(t, now.Add(time.Hour), dueAt(inst, c, now), "unconfirmed")
	c.Confirmations = 1
	require.Equal(t, c.CreatedAt, dueAt(inst, c, now))
}

// instance instantiates doc with variables, hex-encoded, under fresh keys.
func instance(t *testing.T, doc []byte, variables map[string]string) *template.Instance {
	t.Helper()
	docs := map[string][]byte{}
	for _, a := range templates.Artifacts {
		if parsed, err := template.ParseArtifact(a); err == nil {
			docs[parsed.ID] = a
		}
	}
	tmpl, err := template.Parse(doc, docs)
	require.NoError(t, err)
	decoded := map[string][]byte{}
	for name, value := range variables {
		raw, err := hex.DecodeString(value)
		require.NoError(t, err)
		decoded[name] = raw
	}
	keys := make([]*btcec.PublicKey, 3)
	for i := range keys {
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		keys[i] = k.PubKey()
	}
	inst, err := tmpl.Instantiate(template.Context{
		Keys:      template.Keys{Server: keys[0], Emulator: keys[1], Cosigner: keys[2]},
		Variables: decoded,
	})
	require.NoError(t, err)
	return inst
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../../../pkg/template/testdata/" + name)
	require.NoError(t, err)
	return doc
}

func scriptNum(n int64) string {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return hex.EncodeToString(b)
}

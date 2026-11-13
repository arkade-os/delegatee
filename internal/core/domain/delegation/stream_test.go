package delegation

import (
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/arkade-os/executor/templates"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestNewStreamIsActiveForATriggerTemplate(t *testing.T) {
	p := streamParams(t)
	s, err := NewStream(p)
	require.NoError(t, err)
	require.Equal(
		t,
		&Stream{TemplateID: p.Template.ID(), Variables: map[string]string{}, Status: StatusActive},
		s,
	)
}

func TestNewStreamRefusesInvalidTemplateKeyTTLOrVariables(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*StreamParams)
		want error
	}{
		"no trigger": {func(p *StreamParams) { p.Template = parseDoc(t, templates.Templates["renew.json"]) }, ErrNotStream},
		"no key":     {func(p *StreamParams) { p.Encryption = false }, ErrNoEncryptionKey},
		"short ttl":  {func(p *StreamParams) { p.MinExpiry = 48 * time.Hour }, ErrInvalidArgs},
		"given and captured": {func(p *StreamParams) {
			p.Variables = map[string]string{"preimage": "00"}
		}, ErrInvalidArgs},
		"undeclared": {func(p *StreamParams) { p.Variables = map[string]string{"other": "00"} }, ErrInvalidArgs},
		"neither given nor captured": {func(p *StreamParams) {
			p.Template = unboundTrigger(t)
		}, ErrInvalidArgs},
		"upper-case hex": {func(p *StreamParams) {
			p.Template = unboundTrigger(t)
			p.Variables = map[string]string{"receiver_program": "AB"}
		}, ErrInvalidArgs},
		"odd hex": {func(p *StreamParams) {
			p.Template = unboundTrigger(t)
			p.Variables = map[string]string{"receiver_program": "abc"}
		}, ErrInvalidArgs},
	} {
		t.Run(name, func(t *testing.T) {
			p := streamParams(t)
			tc.edit(&p)
			_, err := NewStream(p)
			require.ErrorIs(t, err, tc.want)
		})
	}

	p := streamParams(t)
	p.Template = unboundTrigger(t)
	p.Variables = map[string]string{"receiver_program": "ab"}
	s, err := NewStream(p)
	require.NoError(t, err, "a variable the trigger does not capture is given")
	require.Equal(t, p.Variables, s.Variables)
}

func TestActiveStreamCanBeCancelledOnlyOnce(t *testing.T) {
	s := Stream{Status: StatusActive}
	require.NoError(t, s.Cancel())
	require.Equal(t, StatusCancelled, s.Status)
	require.ErrorIs(t, s.Cancel(), ErrNotActive)
}

func TestSpawnCreatesActiveDelegationOverTheCapturedFundingOutput(t *testing.T) {
	p := spawnParams(t)
	d, err := Spawn(p)
	require.NoError(t, err)
	require.Equal(t, int64(7), d.StreamID)
	require.Equal(t, p.Captured, d.Variables)
	require.Equal(t, p.Now.Add(24*time.Hour), *d.ExpiresAt, "the trigger's lifetime")
	require.Equal(t, hex.EncodeToString(p.Output), d.Inputs[0].Script)
	require.Equal(t, fingerprint(p.Template.ID(), p.Captured), d.Fingerprint)
	require.Equal(t, StatusActive, d.Status)
}

func TestSpawnRefusesWrongOutputMissingKeyOrBadCapturedValue(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(*SpawnParams)
		want error
	}{
		"another output": {func(p *SpawnParams) { p.Output = append([]byte{0x51, 0x20}, make([]byte, 32)...) }, ErrIneligible},
		"no key":         {func(p *SpawnParams) { p.Decrypt = nil }, ErrNoEncryptionKey},
		"bad value":      {func(p *SpawnParams) { p.Captured["receiver_program"] = "zz" }, ErrInvalidArgs},
	} {
		t.Run(name, func(t *testing.T) {
			p := spawnParams(t)
			tc.edit(&p)
			_, err := Spawn(p)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestSpawnAddsTheStreamsVariables(t *testing.T) {
	p := spawnParams(t)
	p.Template = unboundTrigger(t)
	p.Stream.Variables = map[string]string{"receiver_program": p.Captured["receiver_program"]}
	delete(p.Captured, "receiver_program")
	d, err := Spawn(p)
	require.NoError(t, err)
	require.Len(t, d.Variables, 3)
	require.Equal(t, p.Stream.Variables["receiver_program"], d.Variables["receiver_program"])
}

func streamParams(t *testing.T) StreamParams {
	t.Helper()
	tmpl := parseDoc(t, templates.Templates["claim.json"])
	return StreamParams{Template: tmpl, MinExpiry: time.Hour, Encryption: true}
}

// the claim template with receiver_program left out of its trigger's binds
func unboundTrigger(t *testing.T) *template.Template {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(templates.Templates["claim.json"], &doc))
	rule := doc["delegation"].(map[string]any)["trigger"].(map[string]any)["htlc"].(map[string]any)
	delete(rule["capture"].(map[string]any), "receiver_program")
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return parseDoc(t, raw)
}

// spawnParams is a funding output of the vhtlc test vector, whose preimage is its own ciphertext.
func spawnParams(t *testing.T) SpawnParams {
	t.Helper()
	var v struct {
		ReceiverProgram, PkScript string
		Tapscripts                []string
		Preimage                  string
	}
	require.NoError(t, json.Unmarshal(fixture(t, "vhtlc_vector.json"), &v))
	tree, err := txutils.TapTree(v.Tapscripts).Encode()
	require.NoError(t, err)
	output, err := hex.DecodeString(v.PkScript)
	require.NoError(t, err)
	tmpl := parseDoc(t, templates.Templates["claim.json"])
	return SpawnParams{
		Stream: Stream{
			ID:         7,
			TemplateID: tmpl.ID(),
			Variables:  map[string]string{},
		},
		Template: tmpl,
		Output:   output,
		Captured: map[string]string{
			"taptree": hex.EncodeToString(tree), "receiver_program": v.ReceiverProgram,
			"preimage": v.Preimage,
		},
		Now: time.Unix(1_800_000_000, 0),
		Keys: template.Keys{
			Server: scalarKey(1), Emulator: scalarKey(3), Cosigner: scalarKey(99),
		},
		Network: arklib.BitcoinRegTest,
		Decrypt: func(ciphertext []byte) ([]byte, error) { return ciphertext, nil },
	}
}

func scalarKey(n uint32) *btcec.PublicKey {
	var s btcec.ModNScalar
	s.SetInt(n)
	return btcec.PrivKeyFromScalar(&s).PubKey()
}

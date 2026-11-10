package delegation

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/templates"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestOnlyActiveDelegationCanBeCancelled(t *testing.T) {
	d := Delegation{Status: StatusActive}
	require.NoError(t, d.Cancel())
	require.Equal(t, StatusCancelled, d.Status)
	for _, status := range []string{StatusCancelled, StatusExpired} {
		d := Delegation{Status: status}
		require.ErrorIs(t, d.Cancel(), ErrNotActive, status)
		require.Equal(t, status, d.Status)
	}
}

func TestOnlyCancelledDelegationCanBeResumed(t *testing.T) {
	d := Delegation{Status: StatusCancelled}
	require.NoError(t, d.Resume())
	require.Equal(t, StatusActive, d.Status)
	for _, status := range []string{StatusActive, StatusExpired} {
		d := Delegation{Status: status}
		require.ErrorIs(t, d.Resume(), ErrNotCancelled, status)
		require.Equal(t, status, d.Status)
	}
}

func TestNewDelegationDerivesVtxoAddressAndInputFromTemplate(t *testing.T) {
	p := renewalParams(t)
	d, err := NewDelegation(p)
	require.NoError(t, err)
	require.Equal(t, StatusActive, d.Status)
	require.Zero(t, d.StreamID)
	require.Equal(t, p.Template.ID(), d.TemplateID)
	require.Equal(t, fingerprint(p.Template.ID(), p.Variables), d.Fingerprint)
	require.Equal(t, p.Variables, d.Variables)
	require.Nil(t, d.ExpiresAt)
	require.True(t, strings.HasPrefix(d.Address, arklib.BitcoinRegTest.Addr))

	require.Len(t, d.Inputs, 1)
	in := d.Inputs[0]
	require.Equal(t, "funds", in.Name)
	require.False(t, in.Onchain)
	require.NotEmpty(t, in.Tapscripts)
	require.Len(t, in.Script, 68)
	require.True(t, strings.HasPrefix(in.Script, "5120"))

	decoded, err := arklib.DecodeAddressV0(d.Address)
	require.NoError(t, err)
	require.Equal(t, in.Script, "5120"+hex.EncodeToString(schnorr.SerializePubKey(decoded.VtxoTapKey)))
	require.Equal(t, schnorr.SerializePubKey(p.Keys.Server), schnorr.SerializePubKey(decoded.Signer))
}

func TestNewDelegationKeepsExpiryAndVariablesChangeTheAddress(t *testing.T) {
	p := renewalParams(t)
	expires := p.Now.Add(48 * time.Hour)
	p.ExpiresAt = &expires
	d, err := NewDelegation(p)
	require.NoError(t, err)
	require.Equal(t, &expires, d.ExpiresAt)

	other := renewalParams(t)
	other.Variables["max_fee"] = scriptNum(2000)
	o, err := NewDelegation(other)
	require.NoError(t, err)
	require.NotEqual(t, d.Address, o.Address)
	require.NotEqual(t, d.Fingerprint, o.Fingerprint)
}

func TestNewDelegationRefusesSeveralInputs(t *testing.T) {
	p := renewalParams(t)
	p.Template = parseDoc(t, fixture(t, "counter.json"))
	p.Variables = nil
	_, err := NewDelegation(p)
	require.ErrorIs(t, err, ErrInvalidArgs)
}

func TestNewDelegationRefusesStreamTriggerTemplates(t *testing.T) {
	p := renewalParams(t)
	p.Template = parseDoc(t, templates.Templates["claim.json"])
	_, err := NewDelegation(p)
	require.ErrorIs(t, err, ErrStreamOnly)
}

func TestNewDelegationRefusesMalformedOrMismatchedVariables(t *testing.T) {
	for name, mutate := range map[string]func(map[string]string){
		"upper-case hex": func(v map[string]string) { v["owner"] = strings.ToUpper(v["owner"]) },
		"odd hex":        func(v map[string]string) { v["owner"] = "abc" },
		"missing":        func(v map[string]string) { delete(v, "owner") },
		"extra":          func(v map[string]string) { v["other"] = "00" },
		"wrong type":     func(v map[string]string) { v["owner"] = "00" },
	} {
		t.Run(name, func(t *testing.T) {
			p := renewalParams(t)
			mutate(p.Variables)
			_, err := NewDelegation(p)
			require.ErrorIs(t, err, ErrInvalidArgs)
		})
	}
}

func TestNewDelegationWithSecretsNeedsAnEncryptionKey(t *testing.T) {
	_, err := NewDelegation(secretParams(t, nil))
	require.ErrorIs(t, err, ErrNoEncryptionKey)

	d, err := NewDelegation(secretParams(t, func([]byte) ([]byte, error) { return make([]byte, 32), nil }))
	require.NoError(t, err)
	require.NotEmpty(t, d.Address)
}

func TestNewDelegationRefusesLeafSignedByTheCosignerKey(t *testing.T) {
	p := renewalParams(t)
	p.Template = parseDoc(t, fixture(t, "minimal.json"))
	p.Variables = nil
	_, err := NewDelegation(p)
	require.ErrorIs(t, err, ErrCosignerKeyLeaf)
}

func TestNewDelegationAcceptsCosignerKeyUsedOnlyInsideACovenant(t *testing.T) {
	p := renewalParams(t)
	p.Template = parseDoc(t, templates.Templates["board.json"])
	p.Variables["boarding_exit_delay"] = scriptNum(1<<22 | 2)
	_, err := NewDelegation(p)
	require.NoError(t, err)
}

func TestNewDelegationInputKeepsTheRefundLeafLocktimeButNotTheClaimLeaf(t *testing.T) {
	p := spawnParams(t)
	var v struct{ Vars map[string]string }
	require.NoError(t, json.Unmarshal(fixture(t, "vhtlc_vector.json"), &v))
	p2 := DelegationParams{Variables: v.Vars, Now: p.Now, Keys: p.Keys, Decrypt: p.Decrypt, Network: arklib.BitcoinRegTest}
	p2.Template = parseDoc(t, fixture(t, "vhtlc_refund.json"))
	d, err := NewDelegation(p2)
	require.NoError(t, err)
	require.Equal(t, arklib.AbsoluteLocktime(1791000000), d.Inputs[0].Locktime)

	p2.Template = parseDoc(t, fixture(t, "vhtlc_claim.json"))
	d, err = NewDelegation(p2)
	require.NoError(t, err)
	require.Zero(t, d.Inputs[0].Locktime)
}

func TestNewDelegationExpiryMustBeInTheFutureAndBeyondMinTTL(t *testing.T) {
	for name, tc := range map[string]struct {
		min   time.Duration
		ahead time.Duration
		ok    bool
	}{
		"past":          {min: 0, ahead: -time.Second},
		"now":           {min: 0, ahead: 0},
		"future no min": {min: 0, ahead: time.Second, ok: true},
		"under min":     {min: time.Hour, ahead: time.Hour - time.Second},
		"at min":        {min: time.Hour, ahead: time.Hour, ok: true},
		"over min":      {min: time.Hour, ahead: 2 * time.Hour, ok: true},
	} {
		t.Run(name, func(t *testing.T) {
			p := renewalParams(t)
			p.MinExpiry = tc.min
			at := p.Now.Add(tc.ahead)
			p.ExpiresAt = &at
			_, err := NewDelegation(p)
			if tc.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInvalidArgs)
		})
	}
}

func TestEveryArkNetworkMapsToChainParamsAndUnknownFails(t *testing.T) {
	for _, n := range []arklib.Network{
		arklib.Bitcoin, arklib.BitcoinTestNet, arklib.BitcoinTestNet4, arklib.BitcoinSigNet, arklib.BitcoinMutinyNet, arklib.BitcoinRegTest,
	} {
		_, err := chainParams(n)
		require.NoError(t, err, n.Name)
	}
	_, err := chainParams(arklib.Network{Name: "moon"})
	require.Error(t, err)
}

func TestInstantiateRebuildsTheStoredScriptAndRejectsBadVariables(t *testing.T) {
	p := renewalParams(t)
	d, err := NewDelegation(p)
	require.NoError(t, err)
	inst, err := d.Instantiate(p.Template, p.Keys, nil)
	require.NoError(t, err)
	require.Equal(t, d.Inputs[0].Script, hex.EncodeToString(inst.PkScript(0)))

	d.Variables = map[string]string{"owner": "nope"}
	_, err = d.Instantiate(p.Template, p.Keys, nil)
	require.ErrorIs(t, err, ErrInvalidArgs)
}

func renewalParams(t *testing.T) DelegationParams {
	t.Helper()
	tmpl := parseDoc(t, templates.Templates["renew.json"])
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	return DelegationParams{
		Template: tmpl,
		Variables: map[string]string{
			"owner": hex.EncodeToString(owner.PubKey().SerializeCompressed()), "exit_delay": scriptNum(1<<22 | 1),
			"renewal_window": scriptNum(1024), "max_fee": scriptNum(1000),
		},
		Now: time.Unix(1_800_000_000, 0), MinExpiry: 24 * time.Hour,
		Keys: testKeys(t), Network: arklib.BitcoinRegTest,
	}
}

func secretParams(t *testing.T, decrypt func([]byte) ([]byte, error)) DelegationParams {
	t.Helper()
	p := renewalParams(t)
	p.Template = parseDoc(t, []byte(`{
  "format": "template/v1",
  "type": "offchain",
  "variables": {"ciphertext": "bytes"},
  "secrets": {"preimage": {"type": "bytes32", "from": "htlc", "ciphertext": "<ciphertext>"}},
  "inputs": [{
    "name": "htlc",
    "contract": {
      "definition": {
        "contractName": "HashLock",
        "constructorInputs": [{"name": "h", "type": "bytes20"}],
        "structs": [],
        "functions": [{"name": "claim", "leaves": [{"name": "claim",
          "asm": ["OP_HASH160", "<h>", "OP_EQUALVERIFY", "<SERVER_KEY>", "OP_CHECKSIG"],
          "witness": [{"name": "preimage", "type": "bytes32", "encoding": "raw"},
                      {"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}]
      },
      "arguments": {"h": "$(<preimage> OP_HASH160)"}
    },
    "spend": {"function": "claim", "leaf": "claim", "witness": {"preimage": "<preimage>"}}
  }],
  "outputs": [{"name": "payout", "index": 0, "value": {"from": "htlc"},
    "locking": "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}]
}`))
	p.Variables = map[string]string{"ciphertext": "00"}
	p.Decrypt = decrypt
	return p
}

func parseDoc(t *testing.T, doc []byte) *template.Template {
	t.Helper()
	tmpl, err := template.Parse(doc, artifactDocs())
	require.NoError(t, err)
	return tmpl
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	doc, err := os.ReadFile("../../../../pkg/template/testdata/" + name)
	require.NoError(t, err)
	return doc
}

func testKeys(t *testing.T) template.Keys {
	t.Helper()
	keys := make([]*btcec.PublicKey, 3)
	for i := range keys {
		k, err := btcec.NewPrivateKey()
		require.NoError(t, err)
		keys[i] = k.PubKey()
	}
	return template.Keys{Server: keys[0], Emulator: keys[1], Cosigner: keys[2]}
}

func scriptNum(n int64) string {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return hex.EncodeToString(b)
}

func artifactDocs() map[string][]byte {
	docs := map[string][]byte{}
	for _, a := range templates.Artifacts {
		if parsed, err := template.ParseArtifact(a); err == nil {
			docs[parsed.ID] = a
		}
	}
	return docs
}

package template_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

type vector struct {
	ArtifactVersion string                     `json:"artifact_version"`
	Format          string                     `json:"format"`
	Name            string                     `json:"name"`
	Template        json.RawMessage            `json:"template"`
	TemplateText    *string                    `json:"template_text,omitempty"`
	Artifacts       map[string]json.RawMessage `json:"artifacts"`
	Bindings        struct {
		Keys struct {
			Server   string `json:"server"`
			Emulator string `json:"emulator"`
			Cosigner string `json:"cosigner"`
		} `json:"keys"`
		Variables map[string]string `json:"variables"`
	} `json:"bindings"`
	Request struct {
		Sources []struct {
			Tx     string `json:"tx_hex"`
			TxID   string `json:"txid"`
			Vout   uint32 `json:"vout"`
			Amount string `json:"amount"`
			Assets []struct {
				ID     string `json:"id"`
				Amount string `json:"amount"`
			} `json:"assets"`
			Expiry    string `json:"expiry"`
			CreatedAt string `json:"created_at"`
			Confirms  int    `json:"confirmations"`
			Swept     bool   `json:"swept"`
		} `json:"sources"`
		Fee struct {
			Dust   string  `json:"dust"`
			Rate   *string `json:"onchain_sat_per_vbyte,omitempty"`
			Intent struct {
				OffchainInput  string `json:"offchain_input"`
				OnchainInput   string `json:"onchain_input"`
				OffchainOutput string `json:"offchain_output"`
				OnchainOutput  string `json:"onchain_output"`
			} `json:"intent"`
		} `json:"fee"`
		Decryption map[string]string `json:"decryption"`
	} `json:"request"`
	Expected struct {
		ID         string `json:"template_id,omitempty"`
		SpendID    string `json:"spend_id,omitempty"`
		Canonical  string `json:"canonical_hex,omitempty"`
		PSBT       string `json:"psbt_hex,omitempty"`
		UnsignedTx string `json:"unsigned_tx_hex,omitempty"`
		Fee        string `json:"fee,omitempty"`
		Extension  int    `json:"extension,omitempty"`
		Error      *struct {
			Stage string `json:"stage"`
			Code  string `json:"code"`
		} `json:"error,omitempty"`
	} `json:"expected"`
}

func TestVectors(t *testing.T) {
	paths, err := filepath.Glob("testdata/vectors/v1/*.json")
	require.NoError(t, err)
	require.NotEmpty(t, paths)
	for _, path := range paths {
		name := filepath.Base(path)
		name = name[:len(name)-5]
		t.Run(name, func(t *testing.T) {
			v := loadVector(t, name)
			a, err := executeVector(t, v)
			if want := v.Expected.Error; want != nil {
				require.Error(t, err)
				var diagnostic *template.Error
				require.ErrorAs(t, err, &diagnostic)
				require.Equal(t, want.Stage, diagnostic.Stage)
				require.Equal(t, want.Code, diagnostic.Code)
				return
			}
			require.NoError(t, err)
			checkAction(t, v, a)
			// The compatibility API must produce the same complete PSBT.
			raw := map[string][]byte{}
			for id, doc := range v.Artifacts {
				raw[id] = doc
			}
			compiled, err := template.Parse(v.document(), raw)
			require.NoError(t, err)
			b, r := v.bindings(t), v.request(t)
			instance, err := compiled.Instantiate(
				template.Context{
					Keys:      b.Keys,
					Variables: b.Variables,
					Decrypt:   r.Runtime.Decrypt,
					Sources:   r.Sources,
				},
			)
			require.NoError(t, err)
			legacy, err := instance.Build(r.Sources, r.Fee)
			require.NoError(t, err)
			checkAction(t, v, legacy)
		})
	}
}

func TestBindingsOwnValuesAndRebuildFromSources(t *testing.T) {
	v := loadVector(t, "renew-fee")
	d, compiled := compileVector(t, v)
	canonical := d.Canonical()
	canonical[0] = '!'
	require.Equal(t, unhex(t, v.Expected.Canonical), d.Canonical())
	ids := d.ArtifactIDs()
	ids[0] = "changed"
	require.NotEqual(t, ids, d.ArtifactIDs())
	bindings := v.bindings(t)
	bound, err := compiled.Bind(bindings)
	require.NoError(t, err)
	for _, value := range bindings.Variables {
		clear(value)
	}
	*bindings.Keys.Server = *bindings.Keys.Cosigner
	req := v.request(t)
	a, err := bound.Build(req)
	require.NoError(t, err)
	checkAction(t, v, a)
	// Different sources cannot inherit a previous build's value or outpoint.
	req.Sources[0].Amount = 200000
	req.Sources[0].Tx.TxOut[req.Sources[0].Outpoint.Index].Value = 200000
	req.Sources[0].Outpoint.Hash = req.Sources[0].Tx.TxHash()
	b, err := bound.Build(req)
	require.NoError(t, err)
	require.EqualValues(t, 199800, b.Tx.UnsignedTx.TxOut[0].Value)
	require.NotEqual(
		t,
		a.Tx.UnsignedTx.TxIn[0].PreviousOutPoint,
		b.Tx.UnsignedTx.TxIn[0].PreviousOutPoint,
	)
	require.EqualValues(t, 99800, a.Tx.UnsignedTx.TxOut[0].Value)
	// Mutating a returned result cannot affect the bound template.
	a.Tx.UnsignedTx.TxOut[0].PkScript[0] = 0
	again, err := bound.Build(v.request(t))
	require.NoError(t, err)
	checkAction(t, v, again)
}

func TestBuildSealedValuesAreLocalAndOpenedOnce(t *testing.T) {
	v := loadVector(t, "vhtlc-claim")
	_, compiled := compileVector(t, v)
	bound, err := compiled.Bind(v.bindings(t))
	require.NoError(t, err)
	req := v.request(t)
	original := req.Runtime.Decrypt
	calls := atomic.Int32{}
	req.Runtime.Decrypt = func(ct []byte) ([]byte, error) { calls.Add(1); return original(ct) }
	for range 2 {
		a, err := bound.Build(req)
		require.NoError(t, err)
		checkAction(t, v, a)
	}
	require.EqualValues(
		t,
		2,
		calls.Load(),
		"each build decrypts once, never caches between requests",
	)
	req.Runtime.Decrypt = func([]byte) ([]byte, error) { return nil, errors.New("refused") }
	_, err = bound.Build(req)
	require.ErrorIs(t, err, template.ErrIneligible)
}

func TestConcurrentBuildsAndCompiles(t *testing.T) {
	v := loadVector(t, "counter")
	d, compiled := compileVector(t, v)
	bound, err := compiled.Bind(v.bindings(t))
	require.NoError(t, err)
	req := v.request(t)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			c, err := template.Compile(d, nil)
			if !assertNoError(t, err) {
				return
			}
			if c.ID() != compiled.ID() {
				t.Error("ID changed")
			}
			a, err := bound.Build(req)
			if !assertNoError(t, err) {
				return
			}
			var tx bytes.Buffer
			if !assertNoError(t, a.Tx.UnsignedTx.Serialize(&tx)) {
				return
			}
			if !bytes.Equal(unhex(t, v.Expected.UnsignedTx), tx.Bytes()) {
				t.Error("transaction changed")
			}
		})
	}
	wg.Wait()
}

func TestExplicitInputContractDerivation(t *testing.T) {
	v := loadVector(t, "renew-assets")
	_, compiled := compileVector(t, v)
	b, err := compiled.Bind(v.bindings(t))
	require.NoError(t, err)
	in, err := b.InputContracts(template.Runtime{})
	require.NoError(t, err)
	s := v.request(t).Sources[0]
	require.Equal(t, s.Tx.TxOut[s.Outpoint.Index].PkScript, in.PkScript(0))
	multi := loadVector(t, "counter")
	_, compiled = compileVector(t, multi)
	b, err = compiled.Bind(multi.bindings(t))
	require.NoError(t, err)
	in, err = b.InputContracts(template.Runtime{})
	require.NoError(t, err, "every input of a delegation is watched")
	for slot, s := range multi.request(t).Sources {
		require.Equal(t, s.Tx.TxOut[s.Outpoint.Index].PkScript, in.PkScript(slot))
	}
	_, err = b.Build(template.BuildRequest{})
	require.ErrorIs(t, err, template.ErrIneligible)
}

func TestVersionDispatchBeforeLanguageRules(t *testing.T) {
	for _, raw := range []string{`{"format":"template/v2","new":1.5}`, `{"format":"template/v99","inputs":null}`} {
		_, err := template.Decode([]byte(raw))
		require.ErrorIs(t, err, template.ErrUnsupportedVersion)
		var version *template.UnsupportedVersionError
		require.ErrorAs(t, err, &version)
		require.True(t, strings.HasPrefix(version.Version, "template/v"))
	}
	// Structural ambiguity is rejected before choosing either version.
	_, err := template.Decode([]byte(`{"format":"template/v1","format":"template/v2"}`))
	require.ErrorIs(t, err, template.ErrInvalidTemplate)
	_, err = template.Compile(nil, nil)
	require.ErrorIs(t, err, template.ErrInvalidTemplate)
	_, err = template.Compile(&template.Document{}, nil)
	require.ErrorIs(t, err, template.ErrInvalidTemplate)
	supported := template.SupportedVersions()
	supported[0] = "changed"
	require.Equal(t, []string{template.Version1}, template.SupportedVersions())
}

func TestDecoderDiagnosticPath(t *testing.T) {
	v := loadVector(t, "onchain")
	var doc map[string]any
	require.NoError(t, json.Unmarshal(v.Template, &doc))
	doc["inputs"].([]any)[0].(map[string]any)["spend"].(map[string]any)["leaf"] = false
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	_, err = template.Decode(raw)
	var diagnostic *template.Error
	require.ErrorAs(t, err, &diagnostic)
	require.Equal(t, "/inputs/0/spend/leaf", diagnostic.Path)
	require.ErrorIs(t, err, template.ErrInvalidTemplate)
}

func TestMissingKeysAndMalformedSourcesReturnErrors(t *testing.T) {
	v := loadVector(t, "renew-fee")
	_, compiled := compileVector(t, v)
	bindings := v.bindings(t)
	bindings.Keys.Server = nil
	_, err := compiled.Bind(bindings)
	require.ErrorIs(t, err, template.ErrUnsupported)
	bound, err := compiled.Bind(v.bindings(t))
	require.NoError(t, err)
	for _, which := range []string{"input", "output"} {
		r := v.request(t)
		if which == "input" {
			r.Sources[0].Tx.TxIn[0] = nil
		} else {
			r.Sources[0].Tx.TxOut[0] = nil
		}
		_, err = bound.Build(r)
		require.ErrorIs(t, err, template.ErrIneligible)
	}
}

func FuzzDecode(f *testing.F) {
	v := loadVector(f, "onchain")
	f.Add(v.document())
	f.Add([]byte(`{"format":"template/v2"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		d, err := template.Decode(raw)
		if err != nil {
			var diagnostic *template.Error
			require.ErrorAs(t, err, &diagnostic)
			return
		}
		canonical := d.Canonical()
		again, err := template.Decode(canonical)
		require.NoError(t, err)
		require.Equal(t, d.ID(), again.ID())
		require.Equal(t, canonical, again.Canonical())
	})
}

func loadVector(t testing.TB, name string) vector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors", "v1", name+".json"))
	require.NoError(t, err)
	var v vector
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	require.NoError(t, d.Decode(&v))
	require.ErrorIs(t, d.Decode(new(any)), io.EOF)
	require.Equal(t, "template-test/v1", v.Format)
	require.Equal(t, name, v.Name)
	require.NotEqual(
		t,
		v.Template == nil,
		v.TemplateText == nil,
		"exactly one document representation",
	)
	return v
}

func (v vector) document() []byte {
	if v.TemplateText != nil {
		return []byte(*v.TemplateText)
	}
	return v.Template
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func decimal(t testing.TB, s string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(s, 10, 64)
	require.NoError(t, err)
	require.Equal(t, strconv.FormatUint(n, 10), s)
	return n
}

func (v vector) bindings(t testing.TB) template.Bindings {
	t.Helper()
	key := func(h string) *btcec.PublicKey {
		if h == "" {
			return nil
		}
		k, err := btcec.ParsePubKey(unhex(t, h))
		require.NoError(t, err)
		return k
	}
	b := template.Bindings{
		Keys: template.Keys{
			Server:   key(v.Bindings.Keys.Server),
			Emulator: key(v.Bindings.Keys.Emulator),
			Cosigner: key(v.Bindings.Keys.Cosigner),
		},
		Variables: map[string][]byte{},
	}
	for n, s := range v.Bindings.Variables {
		b.Variables[n] = unhex(t, s)
	}
	return b
}

func (v vector) request(t testing.TB) template.BuildRequest {
	t.Helper()
	r := template.BuildRequest{}
	for _, s := range v.Request.Sources {
		tx := wire.NewMsgTx(2)
		reader := bytes.NewReader(unhex(t, s.Tx))
		require.NoError(t, tx.Deserialize(reader))
		require.Zero(t, reader.Len())
		op, err := wire.NewOutPointFromString(fmt.Sprintf("%s:%d", s.TxID, s.Vout))
		require.NoError(t, err)
		expiry, err := time.Parse(time.RFC3339, s.Expiry)
		require.NoError(t, err)
		birth, err := time.Parse(time.RFC3339, s.CreatedAt)
		require.NoError(t, err)
		src := &template.Source{
			Tx:        tx,
			Outpoint:  *op,
			Amount:    decimal(t, s.Amount),
			Expiry:    expiry,
			CreatedAt: birth,
			Confirms:  s.Confirms,
			Swept:     s.Swept,
		}
		for _, a := range s.Assets {
			src.Assets = append(
				src.Assets,
				template.Asset{ID: unhex(t, a.ID), Amount: decimal(t, a.Amount)},
			)
		}
		r.Sources = append(r.Sources, src)
	}
	f := v.Request.Fee
	r.Fee = template.Fee{
		Dust: decimal(t, f.Dust),
		Intent: arkfee.Config{
			IntentOffchainInputProgram:  f.Intent.OffchainInput,
			IntentOnchainInputProgram:   f.Intent.OnchainInput,
			IntentOffchainOutputProgram: f.Intent.OffchainOutput,
			IntentOnchainOutputProgram:  f.Intent.OnchainOutput,
		},
	}
	if f.Rate != nil {
		rate := decimal(t, *f.Rate)
		r.Fee.Onchain = func(n int) uint64 {
			require.GreaterOrEqual(t, n, 0)
			if n > 0 {
				require.LessOrEqual(t, rate, uint64(math.MaxUint64)/uint64(n))
			}
			return uint64(n) * rate
		}
	}
	if v.Request.Decryption != nil {
		responses := map[string][]byte{}
		for ct, plain := range v.Request.Decryption {
			responses[ct] = unhex(t, plain)
		}
		r.Runtime.Decrypt = func(ct []byte) ([]byte, error) {
			p, ok := responses[hex.EncodeToString(ct)]
			if !ok {
				return nil, errors.New("fixture has no decryption response")
			}
			return bytes.Clone(p), nil
		}
	}
	return r
}

// executeVector uses only public APIs and serialized fixture inputs. It never

// constructs source contracts or calculates expected transaction data.

func executeVector(t testing.TB, v vector) (*template.Action, error) {
	t.Helper()
	d, err := template.Decode(v.document())
	if err != nil {
		return nil, err
	}
	// Parse only dependencies, exactly as an application loading a registry would.
	artifacts := map[string]*artifact.Artifact{}
	for _, id := range d.ArtifactIDs() {
		if raw, ok := v.Artifacts[id]; ok {
			a, err := artifact.ParseVersion(artifact.Version1, raw)
			if err != nil {
				return nil, err
			}
			artifacts[id] = a
		}
	}
	compiled, err := template.Compile(d, artifacts)
	if err != nil {
		return nil, err
	}
	if v.Expected.Error == nil {
		require.Equal(t, v.Expected.ID, d.ID())
		require.Equal(t, v.Expected.SpendID, d.SpendID())
		require.Equal(t, d.ID(), compiled.ID())
		require.Equal(t, unhex(t, v.Expected.Canonical), d.Canonical())
		require.Equal(t, template.Version1, compiled.Version())
	}
	b, err := compiled.Bind(v.bindings(t))
	if err != nil {
		return nil, err
	}
	return b.Build(v.request(t))
}

func checkAction(t testing.TB, v vector, a *template.Action) {
	t.Helper()
	require.NotNil(t, a)
	var tx, packet bytes.Buffer
	require.NoError(t, a.Tx.UnsignedTx.Serialize(&tx))
	require.NoError(t, a.Tx.Serialize(&packet))
	require.Equal(t, unhex(t, v.Expected.UnsignedTx), tx.Bytes())
	require.Equal(t, decimal(t, v.Expected.Fee), a.Fee)
	require.Equal(t, v.Expected.Extension, a.Extension)
	require.Equal(
		t,
		psbtMaps(t, unhex(t, v.Expected.PSBT)),
		psbtMaps(t, packet.Bytes()),
		"all PSBT key/value pairs, including proprietary fields",
	)
}

// Map ordering is deliberately ignored; every key and value is compared. Unknown

// fields are retained. Duplicate keys, trailing bytes and malformed PSBTs fail.

func psbtMaps(t testing.TB, raw []byte) []map[string]string {
	t.Helper()
	packet, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(raw), 5)
	require.Equal(t, []byte{'p', 's', 'b', 't', 0xff}, raw[:5])
	r := bytes.NewReader(raw[5:])
	out := make([]map[string]string, 1+len(packet.Inputs)+len(packet.Outputs))
	for i := range out {
		out[i] = map[string]string{}
		for {
			key, err := wire.ReadVarBytes(r, 0, uint32(len(raw)), "PSBT key")
			require.NoError(t, err)
			if len(key) == 0 {
				break
			}
			value, err := wire.ReadVarBytes(r, 0, uint32(len(raw)), "PSBT value")
			require.NoError(t, err)
			k := hex.EncodeToString(key)
			_, duplicate := out[i][k]
			require.False(t, duplicate, "duplicate PSBT key")
			out[i][k] = hex.EncodeToString(value)
		}
	}
	require.Zero(t, r.Len(), "trailing PSBT data")
	return out
}

func compileVector(t testing.TB, v vector) (*template.Document, *template.Template) {
	t.Helper()
	d, err := template.Decode(v.document())
	require.NoError(t, err)
	raw := map[string][]byte{}
	for id, a := range v.Artifacts {
		raw[id] = a
	}
	arts, err := artifact.ParseSet(v.ArtifactVersion, raw)
	require.NoError(t, err)
	compiled, err := template.Compile(d, arts)
	require.NoError(t, err)
	return d, compiled
}

func assertNoError(t *testing.T, err error) bool {
	t.Helper()
	if err != nil {
		t.Error(err)
		return false
	}
	return true
}

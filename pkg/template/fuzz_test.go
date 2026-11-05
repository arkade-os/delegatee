package template

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/arkade-os/delegatee/pkg/template/internal/asm"

	"github.com/arkade-os/delegatee/pkg/template/internal/jcs"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func FuzzParse(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("testdata", "*.json"))
	require.NoError(f, err)
	for _, p := range paths {
		doc, err := os.ReadFile(p)
		require.NoError(f, err)
		f.Add(doc)
	}
	docs := artifacts(f)
	f.Fuzz(func(t *testing.T, doc []byte) {
		tmpl, err := Parse(doc, docs)
		if err != nil {
			requireSentinel(t, err, ErrInvalidTemplate, ErrInvalidArtifact, ErrUnsupported)
			return
		}
		v, err := jcs.Decode(doc)
		require.NoError(t, err)
		canon, err := jcs.Canonical(v)
		require.NoError(t, err)
		again, err := Parse(canon, docs)
		require.NoError(t, err)
		require.Equal(t, tmpl.ID(), again.ID())
	})
}

func FuzzParseArtifact(f *testing.F) {
	paths, err := filepath.Glob(filepath.Join("testdata", "artifacts", "*.json"))
	require.NoError(f, err)
	for _, p := range paths {
		doc, err := os.ReadFile(p)
		require.NoError(f, err)
		f.Add(doc)
	}
	f.Fuzz(func(t *testing.T, doc []byte) {
		a, err := ParseArtifact(doc)
		if err != nil {
			requireSentinel(t, err, ErrInvalidArtifact)
			return
		}
		canon, err := jcs.Canonical(a.Definition.Canonical())
		require.NoError(t, err)
		again, err := ParseArtifact(canon)
		require.NoError(t, err)
		require.Equal(t, a.ID, again.ID)
	})
}

// FuzzEval evaluates a binding against a source transaction, variables reading as v.
func FuzzEval(f *testing.F) {
	owner := testKey(f, 2).SerializeCompressed()
	for _, pkt := range [][]byte{owner, {5, 0, 0, 0, 0, 0, 0, 0}, {}} {
		var src bytes.Buffer
		require.NoError(f, sourceWith(f, 100_000, packets.Raw(packets.TypeState, pkt)).Tx.Serialize(&src))
		for _, expr := range []string{
			"$(2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY)",
			"$(2 OP_PUSHCURRENTINPUTINDEX OP_INSPECTINPUTPACKET OP_VERIFY OP_BIN2NUM OP_1ADD 8 OP_NUM2BIN)",
			"$(<preimage> OP_HASH160)",
			"ab$(<v> OP_SIZE)<v>",
		} {
			f.Add(expr, src.Bytes(), pkt)
		}
	}
	f.Fuzz(func(t *testing.T, binding string, rawTx, v []byte) {
		b, err := parseByteTemplate(binding)
		if err != nil {
			requireSentinel(t, err, ErrInvalidTemplate)
			return
		}
		tx := wire.NewMsgTx(3)
		if tx.Deserialize(bytes.NewReader(rawTx)) != nil || len(tx.TxOut) == 0 || tx.TxOut[0].Value < 0 {
			return
		}
		for _, pc := range b {
			if pc.expr == nil || asm.CheckExpression(pc.expr) != nil {
				continue
			}
			src := &Source{Outpoint: wire.OutPoint{Hash: tx.TxHash()}, Tx: tx, Amount: uint64(tx.TxOut[0].Value)}
			d := newDraft(Intent, []*Source{src})
			lookup := func(string) (asm.Value, error) { return asm.Value{Type: "bytes", Raw: v}, nil }
			if _, err := d.eval(pc.expr, 1, lookup); err != nil {
				requireSentinel(t, err, ErrIneligible)
			}
		}
	})
}

func requireSentinel(t *testing.T, err error, sentinels ...error) {
	t.Helper()
	for _, s := range sentinels {
		if errors.Is(err, s) {
			return
		}
	}
	t.Fatalf("error wraps no sentinel: %v", err)
}

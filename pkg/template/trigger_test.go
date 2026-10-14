package template

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"testing"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestTriggerMatch(t *testing.T) {
	keys := TriggerKeys{Keys: testKeys(t)}
	server := keys.Server.SerializeCompressed()
	to := bytes.Repeat([]byte{7}, 32)
	push := pushScript(t, to)
	tr := parseDoc(t, triggerDoc(t, baseTrigger())).Trigger()
	require.NotNil(t, tr)
	require.Equal(t, []string{"note", "to", "tree"}, tr.Bound())

	ptx, tree := streamed(t, tlv(1, []byte("hi"), 2, push, 3, server, 9, []byte{1}))
	got, err := tr.Match(ptx, keys)
	require.NoError(t, err)
	require.Equal(t, []Binding{{Output: 0, Variables: map[string]string{
		"note": hex.EncodeToString([]byte("hi")), "to": hex.EncodeToString(to), "tree": hex.EncodeToString(tree),
	}}}, got, "only the output whose tree derives its key; unknown tag 9 is ignored")

	for name, body := range map[string][]byte{
		"another key":       tlv(1, []byte("hi"), 2, push, 3, testKey(t, 2).SerializeCompressed()),
		"no key":            tlv(1, []byte("hi"), 2, push),
		"missing bind":      tlv(2, push, 3, server),
		"truncated":         append(tlv(1, []byte("hi"), 2, push, 3, server), 1, 0),
		"wrong opcode":      tlv(1, nil, 2, append([]byte{0x75}, push[1:]...), 3, server),
		"trailing bytes":    tlv(1, nil, 2, append(push, 0x51), 3, server),
		"script too short":  tlv(1, nil, 2, push[:5], 3, server),
		"capture not push":  tlv(1, nil, 2, []byte{0x76, 0x51, 0x87}, 3, server),
		"wrong push length": tlv(1, nil, 2, pushScript(t, to[:31]), 3, server),
		"non-minimal push":  tlv(1, nil, 2, append(append([]byte{0x76, 0x4c, 0x20}, to...), 0x87), 3, server),
	} {
		p, _ := streamed(t, body)
		_, err := tr.Match(p, keys)
		require.ErrorIs(t, err, ErrNoMatch, name)
	}

	noExt, _ := streamed(t, nil)
	_, err = tr.Match(noExt, keys)
	require.ErrorIs(t, err, ErrNoMatch, "no packet 4")

	foreign, _ := streamed(t, tlv(1, nil, 2, push, 3, server))
	foreign.UnsignedTx.TxOut[0].PkScript = append([]byte{0x51, 0x20}, make([]byte, 32)...)
	_, err = tr.Match(foreign, keys)
	require.ErrorIs(t, err, ErrNoMatch, "a tree that does not derive its output's key is no candidate")

	last, _ := streamed(t, tlv(1, []byte("a"), 1, []byte("b"), 2, push, 3, server))
	got, err = tr.Match(last, keys)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString([]byte("b")), got[0].Variables["note"], "a repeated tag keeps the last value")

	two, tree := streamed(t, tlv(1, nil, 2, push, 3, server))
	two.UnsignedTx.TxOut[1].PkScript = bytes.Clone(two.UnsignedTx.TxOut[0].PkScript)
	two.Outputs[1].TaprootTapTree = tree
	got, err = tr.Match(two, keys)
	require.NoError(t, err)
	require.Len(t, got, 2, "several candidate outputs")
	require.Equal(t, []int{0, 1}, []int{got[0].Output, got[1].Output})
}

func TestTriggerMinValue(t *testing.T) {
	keys := TriggerKeys{Keys: testKeys(t)}
	body := tlv(1, nil, 2, pushScript(t, bytes.Repeat([]byte{7}, 32)), 3, keys.Server.SerializeCompressed())
	trig := baseTrigger()
	trig["min_value"] = 1000
	tr := parseDoc(t, triggerDoc(t, trig)).Trigger()

	two, tree := streamed(t, body)
	two.UnsignedTx.TxOut[1].PkScript = bytes.Clone(two.UnsignedTx.TxOut[0].PkScript)
	two.UnsignedTx.TxOut[1].Value = 999
	two.Outputs[1].TaprootTapTree = tree
	got, err := tr.Match(two, keys)
	require.NoError(t, err)
	require.Len(t, got, 1, "an output below the minimum is skipped")
	require.Equal(t, 0, got[0].Output, "an output at the minimum is kept")

	two.UnsignedTx.TxOut[0].Value = 999
	_, err = tr.Match(two, keys)
	require.ErrorIs(t, err, ErrNoMatch)

	for _, v := range []any{-1, 1.5, "1000", maxScriptNum + 1} {
		trig := baseTrigger()
		trig["min_value"] = v
		_, err := Parse(t.Context(), triggerDoc(t, trig), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, v)
		require.ErrorContains(t, err, "min_value", v)
	}

	zero := baseTrigger()
	zero["min_value"] = 0
	require.Equal(t, parseDoc(t, triggerDoc(t, baseTrigger())).ID(), parseDoc(t, triggerDoc(t, zero)).ID(), "a zero minimum is the default")
}

func TestTriggerRequiresAndRaw(t *testing.T) {
	rotated, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	current, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	keys := TriggerKeys{Encryption: []*btcec.PublicKey{current.PubKey(), rotated.PubKey()}, Keys: testKeys(t)}
	to := bytes.Repeat([]byte{7}, 32)
	for name, want := range map[string][]byte{
		"<ENCRYPTION_KEY>": rotated.PubKey().SerializeCompressed(),
		"<EMULATOR_KEY>":   keys.Emulator.SerializeCompressed(),
		"<DELEGATE_KEY>":   keys.Delegate.SerializeCompressed(),
	} {
		trig := baseTrigger()
		trig["require"] = map[string]any{"tlv:3": name}
		ptx, _ := streamed(t, tlv(1, nil, 2, pushScript(t, to), 3, want))
		_, err := parseDoc(t, triggerDoc(t, trig)).Trigger().Match(ptx, keys)
		require.NoError(t, err, name)
	}

	pushed := append([]byte{0x20}, to...)
	raw := map[string]any{
		"packet": 4, "decode": "raw", "require": map[string]any{"raw": "0x" + hex.EncodeToString(pushed)},
		"bind":                  map[string]any{"note": "raw", "tree": "output:taptree", "to": map[string]any{"from": "raw", "asm": []any{"<to>"}}},
		"expires_after_seconds": 60,
	}
	tr := parseDoc(t, triggerDoc(t, raw)).Trigger()
	ptx, tree := streamed(t, pushed)
	got, err := tr.Match(ptx, keys)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"note": hex.EncodeToString(pushed), "to": hex.EncodeToString(to), "tree": hex.EncodeToString(tree)}, got[0].Variables)
	other, _ := streamed(t, to)
	_, err = tr.Match(other, keys)
	require.ErrorIs(t, err, ErrNoMatch, "the literal requirement compares the whole body")
}

func TestTriggerParse(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"no bind":           func(m map[string]any) { m["bind"] = map[string]any{} },
		"undeclared":        func(m map[string]any) { bind(m)["nope"] = "tlv:1" },
		"bad decode":        func(m map[string]any) { m["decode"] = "cbor" },
		"raw source in tlv": func(m map[string]any) { bind(m)["note"] = "raw" },
		"tag out of range":  func(m map[string]any) { bind(m)["note"] = "tlv:256" },
		"tag not canonical": func(m map[string]any) { bind(m)["note"] = "tlv:01" },
		"output in require": func(m map[string]any) { m["require"] = map[string]any{"output:taptree": "0x00"} },
		"unknown key value": func(m map[string]any) { m["require"] = map[string]any{"tlv:3": "<OTHER_KEY>"} },
		"output to bytes32": func(m map[string]any) { bind(m)["to"] = "output:taptree" },
		"asm on output": func(m map[string]any) {
			bind(m)["tree"] = map[string]any{"from": "output:taptree", "asm": []any{"<tree>"}}
		},
		"capture twice": func(m map[string]any) {
			bind(m)["to"] = map[string]any{"from": "tlv:2", "asm": []any{"<to>", "<to>"}}
		},
		"capture absent": func(m map[string]any) {
			bind(m)["to"] = map[string]any{"from": "tlv:2", "asm": []any{"OP_DUP"}}
		},
		"other name in asm": func(m map[string]any) {
			bind(m)["to"] = map[string]any{"from": "tlv:2", "asm": []any{"<to>", "<note>"}}
		},
		"zero ttl":            func(m map[string]any) { m["expires_after_seconds"] = 0 },
		"packet out of range": func(m map[string]any) { m["packet"] = 256 },
	} {
		trig := baseTrigger()
		edit(trig)
		_, err := Parse(t.Context(), triggerDoc(t, trig), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, name)
	}

	for _, typ := range []string{"int", "bool"} {
		trig := baseTrigger()
		bind(trig)["count"] = map[string]any{"from": "tlv:2", "asm": []any{"<count>"}}
		doc := edited(t, triggerDoc(t, trig), func(m map[string]any) { m["variables"].(map[string]any)["count"] = typ })
		_, err := Parse(t.Context(), doc, nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, typ)
		require.ErrorContains(t, err, "capture", typ)
	}

	two := edited(t, triggerDoc(t, baseTrigger()), func(m map[string]any) {
		c := maps.Clone(m["inputs"].([]any)[0].(map[string]any))
		c["name"] = "coin2"
		m["inputs"] = append(m["inputs"].([]any), c)
		m["outputs"] = append(m["outputs"].([]any), map[string]any{"name": "out2", "index": 1, "value": map[string]any{"from": "coin2"}, "locking": "5120<to>"})
	})
	_, err := Parse(t.Context(), two, nil)
	require.ErrorIs(t, err, ErrInvalidTemplate)
	require.ErrorContains(t, err, "trigger", "a trigger template has one input")

	a := parseDoc(t, triggerDoc(t, baseTrigger()))
	trig := baseTrigger()
	trig["expires_after_seconds"] = 7200
	b := parseDoc(t, triggerDoc(t, trig))
	require.NotEqual(t, a.ID(), b.ID(), "the trigger is part of the document hash")
	require.Nil(t, parseDoc(t, []byte(treeDoc)).Trigger())
}

// triggerDoc is treeDoc bound from packet 4.
func triggerDoc(t *testing.T, trigger map[string]any) []byte {
	t.Helper()
	return edited(t, []byte(treeDoc), func(m map[string]any) {
		m["variables"].(map[string]any)["note"] = "bytes"
		m["trigger"] = trigger
	})
}

func baseTrigger() map[string]any {
	return map[string]any{
		"packet": 4, "decode": "tlv",
		"require": map[string]any{"tlv:3": "<SERVER_KEY>"},
		"bind": map[string]any{
			"note": "tlv:1",
			"to":   map[string]any{"from": "tlv:2", "asm": []any{"OP_DUP", "<to>", "OP_EQUAL"}},
			"tree": "output:taptree",
		},
		"expires_after_seconds": 3600,
	}
}

// tlv encodes tag, value pairs; a nil value is an empty record.
func tlv(records ...any) []byte {
	var b bytes.Buffer
	for i := 0; i < len(records); i += 2 {
		v, _ := records[i+1].([]byte)
		b.WriteByte(byte(records[i].(int)))
		b.Write(binary.BigEndian.AppendUint16(nil, uint16(len(v))))
		b.Write(v)
	}
	return b.Bytes()
}

// streamed stamps body as packet 4, unless nil, and pays two outputs; the first is locked by the tree it carries.
func streamed(t *testing.T, body []byte) (*psbt.Packet, []byte) {
	t.Helper()
	tree, err := txutils.TapTree([]string{serverLeaf(t), closureLeaf(t, testKey(t, 2))}).Encode()
	require.NoError(t, err)
	pkScript, err := taptreeScript(tree)
	require.NoError(t, err)
	tx := wire.NewMsgTx(3)
	tx.AddTxIn(&wire.TxIn{})
	tx.AddTxOut(wire.NewTxOut(1000, pkScript))
	tx.AddTxOut(wire.NewTxOut(1000, append([]byte{0x51, 0x20}, bytes.Repeat([]byte{2}, 32)...)))
	if body != nil {
		ext, err := extension.Extension{packets.Raw(4, body)}.TxOut()
		require.NoError(t, err)
		tx.AddTxOut(ext)
	}
	ptx, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	ptx.Outputs[0].TaprootTapTree = tree
	return ptx, tree
}

func pushScript(t *testing.T, to []byte) []byte {
	t.Helper()
	s, err := assemble([]string{"OP_DUP", "<to>", "OP_EQUAL"}, func(string) (value, error) { return value{"bytes", to}, nil })
	require.NoError(t, err)
	return s
}

func bind(trigger map[string]any) map[string]any {
	return trigger["bind"].(map[string]any)
}

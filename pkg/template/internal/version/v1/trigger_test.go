package v1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"maps"
	"testing"
	"time"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/arkade-os/executor/pkg/template/internal/contract"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/executor/pkg/template/packets"
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
	tr := parseDoc(t, triggerDoc(t, baseTrigger())).Triggers()[0]
	require.NotNil(t, tr)
	require.Equal(t, 0, tr.Input())
	require.Equal(t, []string{"note", "to", "tree"}, tr.Captured())

	ptx, tree := streamed(t, tlv(1, []byte("hi"), 2, push, 3, server, 9, []byte{1}))
	got, err := tr.Match(ptx, keys, nil, nil)
	require.NoError(t, err)
	require.Equal(t, []Capture{{Output: 0, Variables: map[string]string{
		"note": hex.EncodeToString(
			[]byte("hi"),
		),
		"to":   hex.EncodeToString(to),
		"tree": hex.EncodeToString(tree),
	}}}, got, "only the output whose tree derives its key; unknown tag 9 is ignored")

	for name, body := range map[string][]byte{
		"another key":      tlv(1, []byte("hi"), 2, push, 3, testKey(t, 2).SerializeCompressed()),
		"no key":           tlv(1, []byte("hi"), 2, push),
		"missing capture":  tlv(2, push, 3, server),
		"truncated":        append(tlv(1, []byte("hi"), 2, push, 3, server), 1, 0),
		"script too short": tlv(1, nil, 2, push[:5], 3, server),
	} {
		p, _ := streamed(t, body)
		_, err := tr.Match(p, keys, nil, nil)
		require.ErrorIs(t, err, ErrNoMatch, name)
	}

	noExt, _ := streamed(t, nil)
	_, err = tr.Match(noExt, keys, nil, nil)
	require.ErrorIs(t, err, ErrNoMatch, "no packet 4")

	foreign, _ := streamed(t, tlv(1, nil, 2, push, 3, server))
	foreign.UnsignedTx.TxOut[0].PkScript = append([]byte{0x51, 0x20}, make([]byte, 32)...)
	_, err = tr.Match(foreign, keys, nil, nil)
	require.ErrorIs(
		t, err, ErrNoMatch, "a tree that does not derive its output's key is no candidate",
	)

	last, _ := streamed(t, tlv(1, []byte("a"), 1, []byte("b"), 2, push, 3, server))
	got, err = tr.Match(last, keys, nil, nil)
	require.NoError(t, err)
	require.Equal(
		t, hex.EncodeToString([]byte("b")), got[0].Variables["note"],
		"a repeated tag keeps the last value",
	)

	two, tree := streamed(t, tlv(1, nil, 2, push, 3, server))
	two.UnsignedTx.TxOut[1].PkScript = bytes.Clone(two.UnsignedTx.TxOut[0].PkScript)
	two.Outputs[1].TaprootTapTree = tree
	got, err = tr.Match(two, keys, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 2, "several candidate outputs")
	require.Equal(t, []int{0, 1}, []int{got[0].Output, got[1].Output})
}

func TestTriggerMinValue(t *testing.T) {
	keys := TriggerKeys{Keys: testKeys(t)}
	body := tlv(
		1, nil, 2, pushScript(t, bytes.Repeat([]byte{7}, 32)), 3, keys.Server.SerializeCompressed(),
	)
	trig := baseTrigger()
	trig["min_value"] = 1000
	tr := parseDoc(t, triggerDoc(t, trig)).Triggers()[0]

	two, tree := streamed(t, body)
	two.UnsignedTx.TxOut[1].PkScript = bytes.Clone(two.UnsignedTx.TxOut[0].PkScript)
	two.UnsignedTx.TxOut[1].Value = 999
	two.Outputs[1].TaprootTapTree = tree
	got, err := tr.Match(two, keys, nil, nil)
	require.NoError(t, err)
	require.Len(t, got, 1, "an output below the minimum is skipped")
	require.Equal(t, 0, got[0].Output, "an output at the minimum is kept")

	two.UnsignedTx.TxOut[0].Value = 999
	_, err = tr.Match(two, keys, nil, nil)
	require.ErrorIs(t, err, ErrNoMatch)

	for _, v := range []any{-1, "1000"} {
		trig := baseTrigger()
		trig["min_value"] = v
		_, err := Parse(triggerDoc(t, trig), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, v)
		require.ErrorContains(t, err, "min_value", v)
	}
	// a fraction or an unsafe integer is refused by the decoder, before any field is read
	for _, v := range []any{1.5, asm.MaxScriptNum + 1} {
		trig := baseTrigger()
		trig["min_value"] = v
		_, err := Parse(triggerDoc(t, trig), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, v)
	}

	zero := baseTrigger()
	zero["min_value"] = 0
	require.Equal(
		t, parseDoc(t, triggerDoc(t, baseTrigger())).ID(), parseDoc(t, triggerDoc(t, zero)).ID(),
		"a zero minimum is the default",
	)
}

func TestTriggerRequiresAndRaw(t *testing.T) {
	encryption, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	keys := TriggerKeys{Encryption: encryption.PubKey(), Keys: testKeys(t)}
	to := bytes.Repeat([]byte{7}, 32)
	for name, want := range map[string][]byte{
		"<ENCRYPTION_KEY>": encryption.PubKey().SerializeCompressed(),
		"<EMULATOR_KEY>":   keys.Emulator.SerializeCompressed(),
		"<COSIGNER_KEY>":   keys.Cosigner.SerializeCompressed(),
	} {
		trig := baseTrigger()
		trig["require"] = map[string]any{"tlv:3": name}
		ptx, _ := streamed(t, tlv(1, nil, 2, pushScript(t, to), 3, want))
		_, err := parseDoc(t, triggerDoc(t, trig)).Triggers()[0].Match(ptx, keys, nil, nil)
		require.NoError(t, err, name)
	}

	pushed := append([]byte{0x20}, to...)
	raw := map[string]any{
		"packet":  4,
		"decode":  "raw",
		"require": map[string]any{"raw": "0x" + hex.EncodeToString(pushed)},
		"capture": map[string]any{
			"note": "raw", "tree": "output:taptree", "to": "$(<raw> 1 32 OP_SUBSTR)",
		},
		"expires_after_seconds": 60,
	}
	tr := parseDoc(t, triggerDoc(t, raw)).Triggers()[0]
	ptx, tree := streamed(t, pushed)
	got, err := tr.Match(ptx, keys, nil, nil)
	require.NoError(t, err)
	require.Equal(
		t,
		map[string]string{
			"note": hex.EncodeToString(pushed), "to": hex.EncodeToString(to),
			"tree": hex.EncodeToString(tree),
		},
		got[0].Variables,
	)
	other, _ := streamed(t, to)
	_, err = tr.Match(other, keys, nil, nil)
	require.ErrorIs(t, err, ErrNoMatch, "the literal requirement compares the whole body")
}

// TestTriggerVariableRequirements: a given variable pins a stream, an expression filters, a spliced
// program runs on the stack, and a sealed variable stands for its plaintext.
func TestTriggerVariableRequirements(t *testing.T) {
	keys := TriggerKeys{Keys: testKeys(t)}
	to := bytes.Repeat([]byte{7}, 32)
	push := pushScript(t, to)
	terms := []byte{0x02, 0x10, 0x27, 0xa2} // 10000 OP_GREATERTHANOREQUAL
	termsHash := sha256.Sum256(terms)
	doc := edited(t, triggerDoc(t, map[string]any{
		"packet": 4,
		"decode": "tlv",
		"require": map[string]any{
			"tlv:0": "<stream>", "tlv:4": "$(<terms> OP_SHA256 <terms_hash> OP_EQUAL)",
			"tlv:5": "$(<quote> <!terms>)",
		},
		"capture": map[string]any{
			"note": "tlv:1", "to": "$(<tlv:2> 2 32 OP_SUBSTR)", "tree": "output:taptree",
			"terms": "tlv:4", "quote": "tlv:5",
		},
		"expires_after_seconds": 60,
	}), func(m map[string]any) {
		v := m["variables"].(map[string]any)
		v["stream"], v["terms_hash"], v["terms"], v["quote"] = "bytes32", "bytes32", "bytes", "int"
	})
	tr := parseDoc(t, doc).Triggers()[0]
	stream := bytes.Repeat([]byte{9}, 32)
	given := map[string][]byte{"stream": stream, "terms_hash": termsHash[:]}
	body := func(id []byte, terms []byte, quote int64) []byte {
		return tlv(0, id, 1, nil, 2, push, 4, terms, 5, asm.ScriptNum(quote))
	}
	ptx, _ := streamed(t, body(stream, terms, 10_000))
	got, err := tr.Match(ptx, keys, given, nil)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString(terms), got[0].Variables["terms"])

	for name, b := range map[string][]byte{
		"another stream": body(bytes.Repeat([]byte{8}, 32), terms, 10_000),
		"swapped terms":  body(stream, []byte{0x51}, 10_000),
		"quote too low":  body(stream, terms, 9_999),
		"terms read tx":  body(stream, []byte{0xcd}, 10_000), // OP_PUSHCURRENTINPUTINDEX is not context-free
	} {
		ptx, _ := streamed(t, b)
		if name == "terms read tx" {
			h := sha256.Sum256([]byte{0xcd})
			given = map[string][]byte{"stream": stream, "terms_hash": h[:]}
		}
		_, err := tr.Match(ptx, keys, given, nil)
		require.ErrorIs(t, err, ErrNoMatch, name)
	}

	sealed := edited(t, triggerDoc(t, map[string]any{
		"packet": 4,
		"decode": "tlv",
		"require": map[string]any{
			"tlv:3": "<SERVER_KEY>", "tlv:6": "$(<secret> OP_SHA256 <tlv:6> OP_EQUAL)",
		},
		"capture": map[string]any{
			"note": "tlv:1", "to": "$(<tlv:2> 2 32 OP_SUBSTR)", "tree": "output:taptree",
			"secret": "tlv:7",
		},
		"expires_after_seconds": 60,
	}), func(m map[string]any) {
		m["variables"].(map[string]any)["secret"] = "bytes32"
		m["delegation"].(map[string]any)["sealed"] = []any{"secret"}
	})
	tr = parseDoc(t, sealed).Triggers()[0]
	plain := bytes.Repeat([]byte{5}, 32)
	digest := sha256.Sum256(plain)
	open := func(ct []byte) ([]byte, error) {
		require.Equal(t, []byte("ct"), ct)
		return plain, nil
	}
	ptx, _ = streamed(
		t,
		tlv(1, nil, 2, push, 3, keys.Server.SerializeCompressed(), 6, digest[:], 7, []byte("ct")),
	)
	got, err = tr.Match(ptx, keys, nil, open)
	require.NoError(t, err, "the requirement reads the plaintext")
	require.Equal(
		t, hex.EncodeToString([]byte("ct")), got[0].Variables["secret"],
		"the ciphertext is captured",
	)
	_, err = tr.Match(ptx, keys, nil, nil)
	require.ErrorIs(t, err, ErrNoMatch, "no decryption for a sealed requirement")
}

func TestTriggerGroups(t *testing.T) {
	keys := TriggerKeys{Keys: testKeys(t)}
	doc := edited(t, triggerDoc(t, nil), func(m map[string]any) {
		c := maps.Clone(m["inputs"].([]any)[0].(map[string]any))
		c["name"] = "coin2"
		m["inputs"] = append(m["inputs"].([]any), c)
		m["outputs"] = append(
			m["outputs"].([]any),
			map[string]any{
				"name":    "out2",
				"index":   1,
				"value":   map[string]any{"from": "coin2"},
				"locking": "5120<to>",
			},
		)
		m["variables"].(map[string]any)["operator"] = "pubkey"
		m["delegation"] = map[string]any{"trigger": map[string]any{
			"coin": map[string]any{
				"packet":  7,
				"decode":  "tlv",
				"require": map[string]any{"tlv:0": "<operator>"},
				"group":   "tlv:1",
				"capture": map[string]any{
					"to": "tlv:2", "tree": "output:taptree",
				},
				"expires_after_seconds": 60,
			},
			"coin2": map[string]any{
				"packet": 7, "decode": "tlv",
				"require":               map[string]any{"tlv:0": "<operator>", "tlv:3": "<note>"},
				"group":                 "tlv:1",
				"capture":               map[string]any{"note": "tlv:4"},
				"expires_after_seconds": 120,
			},
		}}
	})
	trs := parseDoc(t, doc).Triggers()
	require.Len(t, trs, 2)
	require.Equal(t, []int{0, 1}, []int{trs[0].Input(), trs[1].Input()})
	require.Equal(t, 120*time.Second, trs[1].TTL())

	op := keys.Server.SerializeCompressed()
	ptx, _ := streamed7(t, tlv(0, op, 1, []byte("g"), 3, []byte("n"), 4, []byte("n")))
	got, err := trs[1].Match(ptx, keys, map[string][]byte{"operator": op}, nil)
	require.NoError(t, err)
	require.Equal(t, hex.EncodeToString([]byte("g")), got[0].Group)

	ptx, _ = streamed7(t, tlv(0, op, 1, []byte("g"), 3, []byte("x"), 4, []byte("n")))
	_, err = trs[1].Match(ptx, keys, map[string][]byte{"operator": op}, nil)
	require.ErrorIs(t, err, ErrNoMatch, "a requirement on its own capture holds at once")

	for name, edit := range map[string]func(map[string]any){
		"no group": func(m map[string]any) {
			delete(m["delegation"].(map[string]any)["trigger"].(map[string]any)["coin"].(map[string]any), "group")
		},
		"captured twice": func(m map[string]any) {
			m["delegation"].(map[string]any)["trigger"].(map[string]any)["coin2"].(map[string]any)["capture"] = map[string]any{"to": "tlv:4"}
		},
		"group not a source": func(m map[string]any) {
			m["delegation"].(map[string]any)["trigger"].(map[string]any)["coin"].(map[string]any)["group"] = "raw"
		},
		"no fixed requirement": func(m map[string]any) {
			m["delegation"].(map[string]any)["trigger"].(map[string]any)["coin2"].(map[string]any)["require"] = map[string]any{"tlv:3": "<note>"}
		},
	} {
		_, err := Parse(edited(t, doc, edit), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, name)
	}
}

func TestTriggerParse(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"no capture":            func(m map[string]any) { m["capture"] = map[string]any{} },
		"no require":            func(m map[string]any) { m["require"] = map[string]any{} },
		"undeclared":            func(m map[string]any) { bind(m)["nope"] = "tlv:1" },
		"bad decode":            func(m map[string]any) { m["decode"] = "cbor" },
		"raw source in tlv":     func(m map[string]any) { bind(m)["note"] = "raw" },
		"tag out of range":      func(m map[string]any) { bind(m)["note"] = "tlv:256" },
		"tag not canonical":     func(m map[string]any) { bind(m)["note"] = "tlv:01" },
		"output in require":     func(m map[string]any) { m["require"] = map[string]any{"output:taptree": "0x00"} },
		"unknown name":          func(m map[string]any) { m["require"] = map[string]any{"tlv:3": "<OTHER_KEY>"} },
		"output to bytes32":     func(m map[string]any) { bind(m)["to"] = "output:taptree" },
		"variable in capture":   func(m map[string]any) { bind(m)["to"] = "$(<tlv:2> <note> OP_CAT)" },
		"capture not free":      func(m map[string]any) { bind(m)["to"] = "$(<tlv:2> OP_PUSHCURRENTINPUTINDEX OP_DROP)" },
		"require not free":      func(m map[string]any) { m["require"].(map[string]any)["tlv:4"] = "$(OP_INSPECTVERSION)" },
		"splice not bytes":      func(m map[string]any) { m["require"].(map[string]any)["tlv:4"] = "$(<!to>)" },
		"forbidden opcode":      func(m map[string]any) { m["require"].(map[string]any)["tlv:4"] = "$(OP_TXID)" },
		"bare string":           func(m map[string]any) { m["require"].(map[string]any)["tlv:4"] = "abcd" },
		"source of other rule":  func(m map[string]any) { m["require"].(map[string]any)["tlv:4"] = "$(<raw>)" },
		"zero ttl":              func(m map[string]any) { m["expires_after_seconds"] = 0 },
		"packet out of range":   func(m map[string]any) { m["packet"] = 256 },
		"group with one rule":   func(m map[string]any) { m["group"] = "tlv:1" },
		"only captured require": func(m map[string]any) { m["require"] = map[string]any{"tlv:3": "<note>"} },
	} {
		trig := baseTrigger()
		edit(trig)
		_, err := Parse(triggerDoc(t, trig), nil)
		require.ErrorIs(t, err, ErrInvalidTemplate, name)
	}

	onchain := edited(t, triggerDoc(t, baseTrigger()), func(m map[string]any) {
		m["type"] = "proof"
		m["inputs"].([]any)[0].(map[string]any)["type"] = "onchain"
	})
	_, err := Parse(onchain, nil)
	require.ErrorIs(t, err, ErrInvalidTemplate, "a triggered input is offchain")

	a := parseDoc(t, triggerDoc(t, baseTrigger()))
	trig := baseTrigger()
	trig["expires_after_seconds"] = 7200
	b := parseDoc(t, triggerDoc(t, trig))
	require.NotEqual(t, a.ID(), b.ID(), "the trigger is part of the template id")
	require.Equal(t, a.SpendID(), b.SpendID(), "the trigger is not part of the spend id")
	require.Nil(t, parseDoc(t, []byte(treeDoc)).Triggers())
}

// triggerDoc is treeDoc whose coin is triggered by trigger, unless nil.
func triggerDoc(t *testing.T, trigger map[string]any) []byte {
	t.Helper()
	return edited(t, []byte(treeDoc), func(m map[string]any) {
		m["variables"].(map[string]any)["note"] = "bytes"
		m["delegation"] = map[string]any{}
		if trigger != nil {
			m["delegation"] = map[string]any{"trigger": map[string]any{"coin": trigger}}
		}
	})
}

func baseTrigger() map[string]any {
	return map[string]any{
		"packet": 4, "decode": "tlv",
		"require": map[string]any{"tlv:3": "<SERVER_KEY>"},
		"capture": map[string]any{
			"note": "tlv:1", "to": "$(<tlv:2> 2 32 OP_SUBSTR)", "tree": "output:taptree",
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

// streamed7 is streamed with body as packet 7.
func streamed7(t *testing.T, body []byte) (*psbt.Packet, []byte) {
	t.Helper()
	ptx, tree := streamed(t, nil)
	ext, err := extension.Extension{packets.Raw(7, body)}.TxOut()
	require.NoError(t, err)
	ptx.UnsignedTx.AddTxOut(ext)
	ptx.Outputs = append(ptx.Outputs, psbt.POutput{})
	return ptx, tree
}

// streamed stamps body as packet 4, unless nil, and pays two outputs; the first is locked by the
// tree it carries.
func streamed(t *testing.T, body []byte) (*psbt.Packet, []byte) {
	t.Helper()
	tree, err := txutils.TapTree([]string{serverLeaf(t), closureLeaf(t, testKey(t, 2))}).Encode()
	require.NoError(t, err)
	pkScript, err := contract.TaptreeScript(tree)
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
	s, err := asm.Assemble(
		[]string{"OP_DUP", "<to>", "OP_EQUAL"},
		func(string) (asm.Value, error) { return asm.Value{Type: "bytes", Raw: to}, nil },
	)
	require.NoError(t, err)
	return s
}

func bind(trigger map[string]any) map[string]any {
	return trigger["capture"].(map[string]any)
}

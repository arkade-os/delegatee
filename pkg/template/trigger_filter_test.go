package template

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/common/types/traits"
	"github.com/google/cel-go/ext"
	"github.com/stretchr/testify/require"
)

type FilterTestTx struct {
	Extension map[int64]string `json:"extension,omitempty"`
}

func filterEvaluator(t *testing.T, tr *Trigger, keys TriggerKeys) func(map[int64]string) bool {
	t.Helper()
	env, err := cel.NewEnv(
		ext.NativeTypes(reflect.TypeFor[FilterTestTx](), ext.ParseStructTag("json")),
		cel.Variable("tx", cel.ObjectType("template.FilterTestTx")),
		cel.Function("hasPacket", cel.Overload("hasPacket_map_int_string_int_bool",
			[]*cel.Type{cel.MapType(cel.IntType, cel.StringType), cel.IntType}, cel.BoolType,
			cel.BinaryBinding(func(extension, packet ref.Val) ref.Val {
				return extension.(traits.Mapper).Contains(packet)
			}))),
	)
	require.NoError(t, err)
	ast, issues := env.Compile(tr.Filter(keys))
	require.NoError(t, issues.Err())
	require.Equal(t, cel.BoolType, ast.OutputType())
	program, err := env.Program(ast)
	require.NoError(t, err)
	return func(extension map[int64]string) bool {
		result, _, err := program.Eval(map[string]any{"tx": FilterTestTx{Extension: extension}})
		require.NoError(t, err)
		return result == types.True
	}
}

func TestTriggerFilterRequirements(t *testing.T) {
	current, retained, foreign := testKey(t, 1), testKey(t, 2), testKey(t, 3)
	keys := TriggerKeys{Encryption: []*btcec.PublicKey{current, nil, retained}, Keys: testKeys(t)}
	marker := []byte("delegatee-secrets/v1")
	tr := &Trigger{packet: 4, require: []requirement{
		{source: "tlv:3", key: "ENCRYPTION_KEY"},
		{source: "tlv:9", lit: marker},
	}}
	eval := filterEvaluator(t, tr, keys)
	for _, key := range []*btcec.PublicKey{current, retained} {
		body := tlv(9, marker, 3, key.SerializeCompressed())
		require.True(t, eval(map[int64]string{4: hex.EncodeToString(body)}))
		ptx, _ := streamed(t, body)
		_, err := tr.Match(ptx, keys)
		require.NoError(t, err)
	}
	for name, body := range map[string][]byte{
		"foreign key":  tlv(9, marker, 3, foreign.SerializeCompressed()),
		"no key":       tlv(9, marker),
		"no marker":    tlv(3, current.SerializeCompressed()),
		"wrong tag":    tlv(9, marker, 4, current.SerializeCompressed()),
		"wrong length": tlv(9, marker, 3, append(current.SerializeCompressed(), 0)),
	} {
		t.Run(name, func(t *testing.T) {
			require.False(t, eval(map[int64]string{4: hex.EncodeToString(body)}))
		})
	}
	require.False(t, eval(nil))
	require.False(t, eval(map[int64]string{5: hex.EncodeToString(tlv(9, marker, 3, current.SerializeCompressed()))}))
	require.Equal(t, "false", tr.Filter(TriggerKeys{}))
	require.False(t, filterEvaluator(t, tr, TriggerKeys{})(nil))
}

func TestTriggerFilterLiteralBoundaries(t *testing.T) {
	for _, size := range []int{0, 1, 255, 256} {
		value := bytes.Repeat([]byte{0xab}, size)
		tr := &Trigger{packet: 255, require: []requirement{{source: "tlv:7", lit: value}}}
		eval := filterEvaluator(t, tr, TriggerKeys{})
		require.True(t, eval(map[int64]string{255: hex.EncodeToString(tlv(7, value))}))
		require.False(t, eval(map[int64]string{255: hex.EncodeToString(tlv(8, value))}))
		require.False(t, eval(map[int64]string{255: hex.EncodeToString(tlv(7, append(value, 0)))}))
	}
	tr := &Trigger{packet: 4, require: []requirement{{source: "tlv:1", lit: make([]byte, 65536)}}}
	require.Equal(t, "false", tr.Filter(TriggerKeys{}))
}

func TestTriggerFilterOversizedFallsBack(t *testing.T) {
	for _, raw := range []bool{false, true} {
		value := bytes.Repeat([]byte{0xab}, 65535)
		source := "tlv:7"
		body := tlv(7, value)
		if raw {
			source, body = "raw", value
		}
		tr := &Trigger{packet: 4, raw: raw, require: []requirement{{source: source, lit: value}}}
		require.Equal(t, "has(tx.extension) && hasPacket(tx.extension, 4)", tr.Filter(TriggerKeys{}))
		eval := filterEvaluator(t, tr, TriggerKeys{})
		require.True(t, eval(map[int64]string{4: hex.EncodeToString(body)}))
		require.False(t, eval(map[int64]string{5: hex.EncodeToString(body)}))
		ptx, _ := streamed(t, body)
		_, err := tr.Match(ptx, TriggerKeys{})
		require.NoError(t, err)
		tr.require = append(tr.require, requirement{source: source, key: "ENCRYPTION_KEY"})
		require.Equal(t, "false", tr.Filter(TriggerKeys{}))
	}
	tr := &Trigger{packet: 4}
	for range 100 {
		tr.require = append(tr.require, requirement{source: "tlv:7", lit: bytes.Repeat([]byte{1}, 100)})
	}
	require.Equal(t, "has(tx.extension) && hasPacket(tx.extension, 4)", tr.Filter(TriggerKeys{}))
}

func TestTriggerFilterRawAndPacketOnly(t *testing.T) {
	for _, key := range []string{"SERVER_KEY", "EMULATOR_KEY", "DELEGATE_KEY"} {
		tr := &Trigger{packet: 4, raw: true, require: []requirement{{source: "raw", key: key}}}
		keys := TriggerKeys{Keys: testKeys(t)}
		body := tr.require[0].values(keys)[0]
		eval := filterEvaluator(t, tr, keys)
		require.True(t, eval(map[int64]string{4: hex.EncodeToString(body)}))
		require.False(t, eval(map[int64]string{4: hex.EncodeToString(append(body, 0))}))
		require.Equal(t, "false", tr.Filter(TriggerKeys{}))
	}
	tr := &Trigger{packet: 4, raw: true, require: []requirement{{source: "raw", lit: []byte{0xab}}}}
	eval := filterEvaluator(t, tr, TriggerKeys{})
	require.True(t, eval(map[int64]string{4: "ab"}))
	require.False(t, eval(map[int64]string{4: "00ab"}))
	require.False(t, eval(map[int64]string{4: "ab00"}))
	tr.require = nil
	eval = filterEvaluator(t, tr, TriggerKeys{})
	require.True(t, eval(map[int64]string{4: ""}))
	require.False(t, eval(map[int64]string{5: "ab"}))
	require.False(t, eval(nil))
}

func TestTriggerFilterMatchRemainsAuthoritative(t *testing.T) {
	keys := TriggerKeys{Keys: testKeys(t)}
	tr := parseDoc(t, triggerDoc(t, baseTrigger())).Trigger()
	eval := filterEvaluator(t, tr, keys)
	key := keys.Server.SerializeCompressed()
	fields := tlv(1, []byte("hi"), 2, pushScript(t, bytes.Repeat([]byte{7}, 32)))
	for name, records := range map[string][]byte{
		"embedded record":    tlv(9, tlv(3, key)),
		"duplicate override": tlv(3, key, 3, testKey(t, 7).SerializeCompressed()),
	} {
		t.Run(name, func(t *testing.T) {
			body := append(bytes.Clone(fields), records...)
			require.True(t, eval(map[int64]string{4: hex.EncodeToString(body)}))
			ptx, _ := streamed(t, body)
			_, err := tr.Match(ptx, keys)
			require.ErrorIs(t, err, ErrNoMatch)
		})
	}
	for _, records := range [][]byte{tlv(3, key), tlv(3, []byte{0}, 3, key)} {
		body := append(bytes.Clone(fields), records...)
		ptx, _ := streamed(t, body)
		_, err := tr.Match(ptx, keys)
		require.NoError(t, err)
		require.True(t, eval(map[int64]string{4: hex.EncodeToString(body)}))
	}
}

package template

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllocate(t *testing.T) {
	for _, tc := range []struct {
		name            string
		amount, fee     uint64
		assets          []Asset
		wantChange      uint64
		wantChangeAsset uint64
		err             error
	}{
		{name: "remainder", amount: 100_000, wantChange: 75_000},
		{name: "fee from the remainder", amount: 100_000, fee: 600, wantChange: 74_400},
		{name: "fee at the cap", amount: 100_000, fee: 1000, wantChange: 74_000},
		{name: "fee above the cap", amount: 100_000, fee: 1001, err: ErrIneligible},
		{name: "fixed draw not covered", amount: 20_000, err: ErrIneligible},
		{name: "dust remainder", amount: 25_100, err: ErrIneligible},
		{name: "dust remainder after the fee", amount: 25_600, fee: 300, err: ErrIneligible},
		{name: "source above 21e14", amount: 21e14 + 1, err: ErrIneligible},
		{name: "assets follow the catch-all", amount: 100_000, assets: []Asset{{ID: assetID(1), Amount: 7}}, wantChange: 75_000, wantChangeAsset: 7},
		{name: "asset entries combine", amount: 100_000, assets: []Asset{{ID: assetID(1), Amount: 7}, {ID: assetID(1), Amount: 3}}, wantChange: 75_000, wantChangeAsset: 10},
		{name: "asset above 21e14 is routed", amount: 100_000, assets: []Asset{{ID: assetID(1), Amount: 3e15}}, wantChange: 75_000, wantChangeAsset: 3e15},
		{name: "asset entries overflow", amount: 100_000, assets: []Asset{{ID: assetID(1), Amount: 1 << 63}, {ID: assetID(1), Amount: 1 << 63}}, err: ErrIneligible},
		{name: "asset id of 33 bytes", amount: 100_000, assets: []Asset{{ID: assetID(1)[:33], Amount: 7}}, err: ErrIneligible},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst, d, src := mixedPayment(t, tc.amount, tc.assets)
			got, err := inst.allocate(d, src, tc.fee, 330)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, []uint64{tc.wantChange, 25_000}, got.sats)
			require.Equal(t, tc.wantChangeAsset, got.assets[0][hex.EncodeToString(assetID(1))])
			requireBalanced(t, inst, got, src)
		})
	}
}

func TestAllocateWithoutFees(t *testing.T) {
	inst, d, src := mixedPaymentNoFees(t, 100_000)
	_, err := inst.allocate(d, src, 1, 330)
	require.ErrorIs(t, err, ErrIneligible, "a template without fees pays none")
	require.ErrorContains(t, err, "pays no fee")
	got, err := inst.allocate(d, src, 0, 330)
	require.NoError(t, err)
	requireBalanced(t, inst, got, src)
}

func TestAllocateTwoInputs(t *testing.T) {
	// extra pays the fee and its change also takes $(OP_PUSHCURRENTINPUTINDEX) of asset 1 from funds
	inst, d, src := instanceOf(t, twoFunds(t),
		coin(t, 100_000, Asset{ID: assetID(1), Amount: 10}), coin(t, 50_000, Asset{ID: assetID(2), Amount: 4}))
	got, err := inst.allocate(d, src, 700, 330)
	require.NoError(t, err)
	require.Equal(t, []uint64{75_000, 49_300, 25_000}, got.sats)
	a1, a2 := hex.EncodeToString(assetID(1)), hex.EncodeToString(assetID(2))
	require.Equal(t, map[string]uint64{a1: 8}, got.assets[0])
	require.Equal(t, map[string]uint64{a1: 2, a2: 4}, got.assets[1], "the context input is extra, at draft index 2")
	requireBalanced(t, inst, got, src)

	_, err = inst.allocate(d, []*Source{nil, src[1]}, 0, 330)
	require.ErrorIs(t, err, ErrIneligible)
	require.ErrorContains(t, err, `"funds"`)
	_, err = inst.allocate(d, src[:1], 0, 330)
	require.ErrorIs(t, err, ErrIneligible)
	_, err = inst.allocate(d, src, 49_700, 330)
	require.ErrorIs(t, err, ErrIneligible, "fee above the cap")
}

func TestAllocatePooled(t *testing.T) {
	inst, d, src := instanceOf(t, pooled(t), coin(t, 10_000, Asset{ID: assetID(1), Amount: 3}), coin(t, 20_000))
	got, err := inst.allocate(d, src, 700, 330)
	require.NoError(t, err)
	require.Equal(t, []uint64{4_300, 25_000}, got.sats, "neither input alone pays 25,000")
	require.Equal(t, map[string]uint64{hex.EncodeToString(assetID(1)): 3}, got.assets[0])
	requireBalanced(t, inst, got, src)

	inst, d, src = instanceOf(t, pooled(t), coin(t, 10_000), coin(t, 15_000))
	_, err = inst.allocate(d, src, 0, 330)
	require.ErrorIs(t, err, ErrIneligible, "the pool cannot pay 25,000 and leave dust")
}

func TestParsePoolRejects(t *testing.T) {
	out := func(m map[string]any, i int) map[string]any { return m["outputs"].([]any)[i].(map[string]any) }
	for name, edit := range map[string]func(map[string]any){
		"input twice":    func(m map[string]any) { out(m, 0)["value"] = map[string]any{"from": []any{"funds", "funds"}} },
		"unknown input":  func(m map[string]any) { out(m, 0)["value"] = map[string]any{"from": []any{"funds", "nope"}} },
		"empty pool":     func(m map[string]any) { out(m, 0)["value"] = map[string]any{"from": []any{}} },
		"not a name":     func(m map[string]any) { out(m, 0)["value"] = map[string]any{"from": []any{"funds", 1}} },
		"two pools":      func(m map[string]any) { out(m, 1)["value"] = map[string]any{"from": "extra", "amount": 25000} },
		"two remainders": func(m map[string]any) { out(m, 1)["value"] = map[string]any{"from": []any{"extra", "funds"}} },
		"input in no pool": func(m map[string]any) {
			out(m, 0)["value"] = map[string]any{"from": "funds"}
			out(m, 1)["value"] = map[string]any{"from": "funds", "amount": 25000}
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(t.Context(), edited(t, pooled(t), edit), nil)
			require.ErrorIs(t, err, ErrInvalidTemplate)
		})
	}
}

func TestAllocateAssetOverflowAcrossInputs(t *testing.T) {
	doc := edited(t, twoFunds(t), func(m map[string]any) {
		outs := m["outputs"].([]any)
		outs[0].(map[string]any)["assets"] = []any{map[string]any{"from": "funds"}, map[string]any{"from": "extra"}}
		delete(outs[1].(map[string]any), "assets")
	})
	inst, d, src := instanceOf(t, doc,
		coin(t, 100_000, Asset{ID: assetID(1), Amount: 1 << 63}), coin(t, 50_000, Asset{ID: assetID(1), Amount: 1 << 63}))
	_, err := inst.allocate(d, src, 0, 330)
	require.ErrorIs(t, err, ErrIneligible)

	src[1].Assets[0].Amount = 1<<63 - 1
	got, err := inst.allocate(d, src, 0, 330)
	require.NoError(t, err)
	require.Equal(t, uint64(1<<64-1), got.assets[0][hex.EncodeToString(assetID(1))])
}

func TestFixedAmountWrapsResolveErrors(t *testing.T) {
	inst, d, _ := mixedPayment(t, 100_000, nil)
	_, err := inst.fixedAmount(byteTemplate{{name: "nope"}}, d, 0)
	require.ErrorIs(t, err, ErrIneligible)
	require.ErrorIs(t, err, ErrInvalidTemplate)
	_, err = inst.fixedAmount(byteTemplate{{hex: []byte{0x81}}}, d, 0)
	require.ErrorIs(t, err, ErrIneligible, "negative")
}

func TestAllocateAssetWithoutRoute(t *testing.T) {
	inst, d, src := noAssetRoute(t, 100_000, []Asset{{ID: assetID(1), Amount: 7}})
	_, err := inst.allocate(d, src, 0, 330)
	require.ErrorIs(t, err, ErrIneligible, "a balance without a route is a loss")
}

func TestAllocateDustDraw(t *testing.T) {
	inst, d, src := mixedPayment(t, 100_000, nil)
	_, err := inst.allocate(d, src, 0, 25_001)
	require.ErrorIs(t, err, ErrIneligible, "a fixed draw below the minimum")
}

func TestAllocateAssetRoutes(t *testing.T) {
	// change takes 3 of asset 1 and the rest of asset 2; nothing takes the rest
	doc := edited(t, mixedPaymentDoc(t, true), func(m map[string]any) {
		m["outputs"].([]any)[0].(map[string]any)["assets"] = []any{
			map[string]any{"from": "funds", "asset": hex.EncodeToString(assetID(1)), "amount": 3},
			map[string]any{"from": "funds", "asset": hex.EncodeToString(assetID(2))},
		}
	})
	for _, tc := range []struct {
		name   string
		assets []Asset
		want   map[string]uint64
	}{
		{name: "exact", assets: []Asset{{ID: assetID(1), Amount: 3}, {ID: assetID(2), Amount: 5}},
			want: map[string]uint64{hex.EncodeToString(assetID(1)): 3, hex.EncodeToString(assetID(2)): 5}},
		{name: "remainder route of an absent asset", assets: []Asset{{ID: assetID(1), Amount: 3}},
			want: map[string]uint64{hex.EncodeToString(assetID(1)): 3}},
		{name: "fixed draw of an absent asset", assets: []Asset{{ID: assetID(2), Amount: 5}}},
		{name: "fixed draw not covered", assets: []Asset{{ID: assetID(1), Amount: 2}}},
		{name: "rest of a fixed asset", assets: []Asset{{ID: assetID(1), Amount: 4}}},
		{name: "asset without a route", assets: []Asset{{ID: assetID(1), Amount: 3}, {ID: assetID(3), Amount: 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst, d, src := instanceOf(t, doc, coin(t, 100_000, tc.assets...))
			got, err := inst.allocate(d, src, 0, 330)
			if tc.want == nil {
				require.ErrorIs(t, err, ErrIneligible)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got.assets[0])
			require.Empty(t, got.assets[1])
			requireBalanced(t, inst, got, src)
		})
	}
}

// outputs combine assets of several inputs: assets are summed over all inputs
func requireBalanced(t *testing.T, inst *Instance, a *allocation, src []*Source) {
	t.Helper()
	in, out := map[string]uint64{}, map[string]uint64{}
	for slot, s := range src {
		pool := inst.tmpl.poolOf(slot)
		if pool[0] == slot {
			held, drawn := uint64(0), uint64(0)
			for _, i := range pool {
				held += src[i].Amount
			}
			if f := inst.tmpl.fee; f != nil && slices.Contains(pool, f.from) {
				drawn = a.fee
			}
			for k, o := range inst.tmpl.outputs {
				if slices.Equal(o.pool, pool) {
					drawn += a.sats[k]
				}
			}
			require.Equal(t, held, drawn, "pool %v", pool)
		}
		for _, as := range s.Assets {
			in[hex.EncodeToString(as.ID)] += as.Amount
		}
	}
	for _, m := range a.assets {
		for k, n := range m {
			out[k] += n
		}
	}
	require.Equal(t, in, out)
}

func assetID(n int) []byte { return bytes.Repeat([]byte{byte(n)}, 34) }

// mixedPayment is an intent paying 25,000 on chain from funds, the rest back to funds' script with every asset.
func mixedPayment(t *testing.T, amount uint64, assets []Asset) (*Instance, *draft, []*Source) {
	t.Helper()
	return instanceOf(t, mixedPaymentDoc(t, true), coin(t, amount, assets...))
}

func mixedPaymentNoFees(t *testing.T, amount uint64) (*Instance, *draft, []*Source) {
	t.Helper()
	return instanceOf(t, mixedPaymentDoc(t, false), coin(t, amount))
}

// noAssetRoute is mixedPayment whose change carries no asset.
func noAssetRoute(t *testing.T, amount uint64, assets []Asset) (*Instance, *draft, []*Source) {
	t.Helper()
	doc := edited(t, mixedPaymentDoc(t, true), func(m map[string]any) {
		delete(m["outputs"].([]any)[0].(map[string]any), "assets")
	})
	return instanceOf(t, doc, coin(t, amount, assets...))
}

func coin(t *testing.T, amount uint64, assets ...Asset) *Source {
	t.Helper()
	src := sourceWith(t, int64(amount))
	src.Assets = assets
	return src
}

// instanceOf moves sources to its input contracts' scripts, owned by testKey 2.
func instanceOf(t *testing.T, doc []byte, sources ...*Source) (*Instance, *draft, []*Source) {
	t.Helper()
	tmpl := parseDoc(t, doc)
	for slot, src := range sources {
		c, err := build(tmpl.inputs[slot].contract.def, map[string]value{"owner": {"pubkey", testKey(t, 2).SerializeCompressed()}}, testKeys(t))
		require.NoError(t, err)
		lockTo(src, c.pkScript)
	}
	inst, err := tmpl.Instantiate(t.Context(), Context{Keys: testKeys(t), Sources: sources})
	require.NoError(t, err)
	return inst, newDraft(tmpl.typ, sources), sources
}

// twoFunds: funds pays change and 25,000; extra pays extraChange, the fee, and takes $(OP_PUSHCURRENTINPUTINDEX) of asset 1 from funds.
func twoFunds(t *testing.T) []byte {
	t.Helper()
	return edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		ins := m["inputs"].([]any)
		extra := maps.Clone(ins[0].(map[string]any))
		extra["name"] = "extra"
		m["inputs"] = append(ins, extra)
		outs := m["outputs"].([]any)
		outs[1].(map[string]any)["index"] = 3
		m["outputs"] = []any{outs[0], map[string]any{
			"name": "extra_change", "index": 1, "value": map[string]any{"from": "extra"}, "locking": map[string]any{"from": "extra"},
			"assets": []any{
				map[string]any{"from": "funds", "asset": hex.EncodeToString(assetID(1)), "amount": "$(OP_PUSHCURRENTINPUTINDEX)"},
				map[string]any{"from": "extra"},
			},
		}, outs[1]}
		m["packets"] = map[string]any{"output_index": 2}
		m["fees"] = map[string]any{"from": "extra", "max": 1000}
	})
}

// pooled: funds and extra pay 25,000 on chain together; extra pays the fee.
func pooled(t *testing.T) []byte {
	t.Helper()
	return edited(t, mixedPaymentDoc(t, false), func(m map[string]any) {
		ins := m["inputs"].([]any)
		extra := maps.Clone(ins[0].(map[string]any))
		extra["name"] = "extra"
		m["inputs"] = append(ins, extra)
		outs := m["outputs"].([]any)
		change, payment := outs[0].(map[string]any), outs[1].(map[string]any)
		change["value"] = map[string]any{"from": []any{"funds", "extra"}}
		change["assets"] = []any{map[string]any{"from": "funds"}, map[string]any{"from": "extra"}}
		payment["value"] = map[string]any{"from": []any{"extra", "funds"}, "amount": 25000}
		m["fees"] = map[string]any{"from": "extra", "max": 1000}
	})
}

func mixedPaymentDoc(t *testing.T, fees bool) []byte {
	t.Helper()
	feeField := ""
	if fees {
		feeField = `, "fees": {"from": "funds", "max": 1000}`
	}
	return fmt.Appendf(nil, `{
  "format": "delegateed-template/v1",
  "type": "intent",
  "inputs": [{
    "name": "funds",
    "contract": {
      "definition": {
        "contractName": "DelegatedVtxo",
        "constructorInputs": [{"name": "owner", "type": "pubkey"}],
        "structs": [],
        "functions": [
          {"name": "spend", "leaves": [{"name": "spend", "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<owner>", "OP_CHECKSIG"],
            "witness": [{"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                        {"name": "ownerSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]},
          {"name": "pay", "arkade": {"inputs": [], "asm": ["OP_1"]},
            "leaves": [{"name": "pay", "asm": ["<SERVER_KEY>", "OP_CHECKSIGVERIFY", "<EMULATOR_KEY:pay>", "OP_CHECKSIG"],
            "witness": [{"name": "serverSig", "type": "signature", "encoding": "schnorr-64", "injected": true},
                        {"name": "emulatorSig", "type": "signature", "encoding": "schnorr-64", "injected": true}]}]}
        ]
      },
      "arguments": {"owner": "%x"}
    },
    "spend": {"function": "pay", "leaf": "pay"}
  }],
  "outputs": [
    {"name": "change", "index": 0, "value": {"from": "funds"}, "locking": {"from": "funds"}, "assets": [{"from": "funds"}]},
    {"name": "payment", "type": "onchain", "index": 2, "value": {"from": "funds", "amount": 25000},
      "locking": "5120f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"}
  ],
  "packets": {"output_index": 1}%s
}`, testKey(t, 2).SerializeCompressed(), feeField)
}

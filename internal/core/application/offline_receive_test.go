package application

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"maps"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func offlineStream(t *testing.T) (*testEnv, *btcec.PrivateKey, *domain.Delegation) {
	t.Helper()
	e, _ := serverEnv(t)
	key, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{key}
	d, err := e.svc.RegisterStreamDelegation(t.Context(), e.trust(t, e.fixture(t, "offline_receive.json")), nil)
	require.NoError(t, err)
	e.scan(t)
	return e, key, d
}

func offlinePacket(ciphertext, script, key []byte) []byte {
	marker := []byte("delegatee-secrets/v1")
	body := binary.BigEndian.AppendUint16([]byte{127}, uint16(len(marker)))
	body = append(body, marker...)
	body = append(body, claimPacket(ciphertext, nil, key)...)
	return append(body, claimPacket(nil, script, nil)...)
}

func offlineFunding(t *testing.T, e *testEnv, key *btcec.PrivateKey, id string, alter func(map[string]any)) (*psbt.Packet, map[string]string) {
	t.Helper()
	ptx, legacy := funding(t, e, key.PubKey())
	ct, err := hex.DecodeString(legacy["ciphertext"])
	require.NoError(t, err)
	preimage, err := ecies.Decrypt(key, ct)
	require.NoError(t, err)
	envelope := map[string]any{"format": "delegatee-secrets/v1", "template_id": id, "values": map[string]string{
		"preimage": hex.EncodeToString(preimage), "minimum_value": hex.EncodeToString(scriptNum(10_000)), "receiver_program": legacy["receiver_program"],
	}}
	if alter != nil {
		alter(envelope)
	}
	raw, err := json.Marshal(envelope)
	require.NoError(t, err)
	ct, err = ecies.Encrypt(key.PubKey(), raw)
	require.NoError(t, err)
	program, err := hex.DecodeString(legacy["receiver_program"])
	require.NoError(t, err)
	setOfflinePacket(t, ptx, offlinePacket(ct, enforcePayTo(t, program), key.PubKey().SerializeCompressed()))
	return ptx, legacy
}

func setOfflinePacket(t *testing.T, ptx *psbt.Packet, body []byte) {
	t.Helper()
	out, err := extension.Extension{packets.Raw(4, body)}.TxOut()
	require.NoError(t, err)
	ptx.UnsignedTx.TxOut[1] = out
}

func TestOfflineReceivePacketPersistsAndRetriesAfterRestart(t *testing.T) {
	e, key, d := offlineStream(t)
	ptx, _ := offlineFunding(t, e, key, d.TemplateID, nil)
	events := make(chan clientlib.TransactionEvent)
	e.indexer.setTxs(events)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); e.svc.watchStreams(ctx) }()
	events <- clientlib.TransactionEvent{ArkTx: &clientlib.TxNotification{TxData: clientlib.TxData{Tx: b64(t, ptx)}}}
	require.Eventually(t, func() bool { return len(children(t, e, d.ID)) == 1 }, 5*time.Second, 10*time.Millisecond)
	cancel()
	<-done
	child := children(t, e, d.ID)[0]
	require.Contains(t, child.Variables, "receiver_program")
	require.WithinDuration(t, time.Now().Add(24*time.Hour), *child.ExpiresAt, time.Minute)
	e.svc.react(t.Context(), b64(t, ptx))
	require.Len(t, children(t, e, d.ID), 1)
	e.indexer.vtxos = append(e.indexer.vtxos, e.vtxoAt(t, ptx.UnsignedTx.TxOut[0].PkScript, 10_000, time.Hour))
	calls := 0
	e.emulator.submitTx = func(string, []string) (string, []string, error) {
		calls++
		return "", nil, status.Error(codes.InvalidArgument, "retryable emulator rejection")
	}
	r := e.restart(t)
	r.scan(t)
	require.Equal(t, 1, calls)
	require.NotNil(t, r.svc.watched[child.ID])
	r = r.restart(t)
	r.indexer.serve(e.indexer.vtxos...)
	r.scan(t)
	require.Equal(t, 2, calls)
	require.Len(t, children(t, r, d.ID), 1)
}

func TestOfflineReceiveMinimumAmount(t *testing.T) {
	for _, amount := range []int64{9999, 10_000, 12_000} {
		e, key, d := offlineStream(t)
		ptx, legacy := offlineFunding(t, e, key, d.TemplateID, nil)
		ptx.UnsignedTx.TxOut[0].Value = amount
		e.svc.react(t.Context(), b64(t, ptx))
		require.Len(t, children(t, e, d.ID), 1)
		child := children(t, e, d.ID)[0]
		tmpl, err := e.svc.parseTemplate(t.Context(), d.TemplateID)
		require.NoError(t, err)
		inst, err := e.svc.newInstance(t.Context(), tmpl, e.svc.cosigners[0], child.Variables, nil, nil)
		require.NoError(t, err)
		tx := ptx.UnsignedTx
		source := &template.Source{Tx: tx, Amount: uint64(amount), Assets: []template.Asset{{ID: bytes.Repeat([]byte{1}, 34), Amount: 7}}}
		source.Outpoint.Hash = tx.TxHash()
		act, err := inst.Build(t.Context(), []*template.Source{source}, template.Fee{Dust: 330})
		if amount < 10_000 {
			require.ErrorIs(t, err, template.ErrIneligible)
			require.Nil(t, act)
		} else {
			require.NoError(t, err)
			require.EqualValues(t, amount, act.Tx.UnsignedTx.TxOut[0].Value)
			ext, err := extension.NewExtensionFromTx(act.Tx.UnsignedTx)
			require.NoError(t, err)
			assets := ext.GetAssetPacket()
			require.Len(t, assets, 1)
			require.Len(t, assets[0].Outputs, 1)
			require.EqualValues(t, 0, assets[0].Outputs[0].Vout)
			require.EqualValues(t, 7, assets[0].Outputs[0].Amount)
			require.Equal(t, "5120"+legacy["receiver_program"], hex.EncodeToString(act.Tx.UnsignedTx.TxOut[0].PkScript))
		}
	}
}

func TestOfflineReceiveRejectsForeignEnvelopes(t *testing.T) {
	for _, field := range []string{"template_id", "format", "preimage"} {
		t.Run(field, func(t *testing.T) {
			e, key, d := offlineStream(t)
			ptx, _ := offlineFunding(t, e, key, d.TemplateID, func(v map[string]any) {
				if field == "format" || field == "template_id" {
					v[field] = "wrong"
				} else {
					v["values"].(map[string]string)[field] = hex.EncodeToString(make([]byte, 32))
				}
			})
			e.svc.react(t.Context(), b64(t, ptx))
			require.Empty(t, children(t, e, d.ID))
		})
	}
	for _, name := range []string{"foreign key", "foreign encryption", "malformed JSON", "raw preimage", "missing marker", "foreign marker", "changed payout"} {
		t.Run(name, func(t *testing.T) {
			e, key, d := offlineStream(t)
			ptx, legacy := offlineFunding(t, e, key, d.TemplateID, nil)
			if name == "changed payout" {
				altered := maps.Clone(legacy)
				altered["receiver_program"] = hex.EncodeToString(e.userKey.PubKey().SerializeCompressed()[1:])
				tmpl, err := e.svc.parseTemplate(t.Context(), e.fixture(t, "vhtlc_claim.json"))
				require.NoError(t, err)
				inst, err := e.svc.newInstance(t.Context(), tmpl, e.svc.cosigners[0], altered, nil, nil)
				require.NoError(t, err)
				tree, err := txutils.TapTree(inst.Tapscripts(0)).Encode()
				require.NoError(t, err)
				ptx.UnsignedTx.TxOut[0] = wire.NewTxOut(10_000, inst.PkScript(0))
				ptx.Outputs[0].TaprootTapTree = tree
			} else {
				body, _ := packets.Find(ptx.UnsignedTx, 4)
				switch name {
				case "foreign key":
					other, _ := hexKey(t)
					body = append(body, claimPacket(nil, nil, other.PubKey().SerializeCompressed())...)
				case "foreign encryption":
					other, _ := hexKey(t)
					ct, err := ecies.Encrypt(other.PubKey(), []byte("{}"))
					require.NoError(t, err)
					body = append(body, claimPacket(ct, nil, nil)...)
				case "malformed JSON", "raw preimage":
					raw := []byte("{invalid")
					if name == "raw preimage" {
						raw = make([]byte, 32)
					}
					ct, err := ecies.Encrypt(key.PubKey(), raw)
					require.NoError(t, err)
					body = append(body, claimPacket(ct, nil, nil)...)
				case "missing marker":
					body = body[3+len("delegatee-secrets/v1"):]
				case "foreign marker":
					body[3] = 'x'
				}
				setOfflinePacket(t, ptx, body)
			}
			e.svc.react(t.Context(), b64(t, ptx))
			require.Empty(t, children(t, e, d.ID))
			if name == "changed payout" {
				body, _ := packets.Find(ptx.UnsignedTx, 4)
				body = append(body, claimPacket(nil, enforcePayTo(t, e.userKey.PubKey().SerializeCompressed()[1:]), nil)...)
				setOfflinePacket(t, ptx, body)
				e.svc.react(t.Context(), b64(t, ptx))
				require.Len(t, children(t, e, d.ID), 1)
				child := children(t, e, d.ID)[0]
				tmpl, err := e.svc.parseTemplate(t.Context(), d.TemplateID)
				require.NoError(t, err)
				inst, err := e.svc.newInstance(t.Context(), tmpl, e.svc.cosigners[0], child.Variables, nil, nil)
				require.NoError(t, err)
				source := &template.Source{Tx: ptx.UnsignedTx, Amount: 10_000}
				source.Outpoint.Hash = ptx.UnsignedTx.TxHash()
				act, err := inst.Build(t.Context(), []*template.Source{source}, template.Fee{Dust: 330})
				require.ErrorIs(t, err, template.ErrIneligible)
				require.Nil(t, act)
			}
		})
	}
}

func TestOfflineReceiveKeepsLegacyStreamSeparate(t *testing.T) {
	e, key, d := offlineStream(t)
	legacy, err := e.svc.RegisterStreamDelegation(t.Context(), e.trust(t, e.fixture(t, "noninteractiveclaim.json")), nil)
	require.NoError(t, err)
	e.scan(t)
	sealed, _ := offlineFunding(t, e, key, d.TemplateID, nil)
	e.svc.react(t.Context(), b64(t, sealed))
	require.Len(t, children(t, e, d.ID), 1)
	require.Empty(t, children(t, e, legacy.ID))
	raw, _ := funding(t, e, key.PubKey())
	e.svc.react(t.Context(), b64(t, raw))
	require.Len(t, children(t, e, d.ID), 1)
	require.Len(t, children(t, e, legacy.ID), 1)
	_, err = e.svc.RegisterDelegation(t.Context(), d.TemplateID, children(t, e, d.ID)[0].Variables, nil)
	require.ErrorIs(t, err, ErrInvalidArgs)
}

func TestOfflineReceiveRejectsAuthenticatedConstraintsBeforeDisclosure(t *testing.T) {
	for _, name := range []string{"receiver", "zero minimum", "negative minimum", "excessive minimum", "noncanonical minimum", "missing minimum"} {
		t.Run(name, func(t *testing.T) {
			e, key, d := offlineStream(t)
			ptx, _ := offlineFunding(t, e, key, d.TemplateID, func(envelope map[string]any) {
				values := envelope["values"].(map[string]string)
				switch name {
				case "receiver":
					values["receiver_program"] = hex.EncodeToString(e.userKey.PubKey().SerializeCompressed()[1:])
				case "zero minimum":
					values["minimum_value"] = ""
				case "negative minimum":
					values["minimum_value"] = "81"
				case "excessive minimum":
					values["minimum_value"] = hex.EncodeToString(scriptNum(2100000000000001))
				case "noncanonical minimum":
					values["minimum_value"] = "0100"
				case "missing minimum":
					delete(values, "minimum_value")
				}
			})
			e.svc.react(t.Context(), b64(t, ptx))
			require.Len(t, children(t, e, d.ID), 1)
			child := children(t, e, d.ID)[0]
			tmpl, err := e.svc.parseTemplate(t.Context(), d.TemplateID)
			require.NoError(t, err)
			inst, err := e.svc.newInstance(t.Context(), tmpl, e.svc.cosigners[0], child.Variables, nil, nil)
			require.NoError(t, err)
			source := &template.Source{Tx: ptx.UnsignedTx, Amount: 10_000}
			source.Outpoint.Hash = ptx.UnsignedTx.TxHash()
			act, err := inst.Build(t.Context(), []*template.Source{source}, template.Fee{Dust: 330})
			require.ErrorIs(t, err, template.ErrIneligible)
			require.Nil(t, act)
			e.indexer.vtxos = append(e.indexer.vtxos, e.vtxoAt(t, ptx.UnsignedTx.TxOut[0].PkScript, 10_000, time.Hour))
			calls := 0
			e.emulator.submitTx = func(string, []string) (string, []string, error) { calls++; return "", nil, errBoom }
			e.scan(t)
			require.Zero(t, calls)
		})
	}
}

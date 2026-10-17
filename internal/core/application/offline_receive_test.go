package application

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"maps"
	"testing"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/arkade-os/delegatee/pkg/template"
	"github.com/arkade-os/delegatee/pkg/template/ecies"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func offlineClaim(t *testing.T) (*testEnv, string, map[string]string, map[string]string, time.Time) {
	t.Helper()
	e, _ := serverEnv(t)
	key, _ := hexKey(t)
	e.svc.encryptionKeys = []*btcec.PrivateKey{key}
	ptx, legacy := fundingWith(t, e, key.PubKey(), func(ct, script []byte) []byte { return claimPacket(ct, script, key.PubKey().SerializeCompressed()) })
	encrypted, err := hex.DecodeString(legacy["ciphertext"])
	require.NoError(t, err)
	preimage, err := ecies.Decrypt(key, encrypted)
	require.NoError(t, err)
	id := e.trust(t, e.fixture(t, "offline_receive.json"))
	until := time.Now().Add(time.Hour).Truncate(time.Second)
	payload, err := json.Marshal(map[string]any{
		"format": "delegatee-secrets/v1", "template_id": id,
		"values": map[string]string{
			"preimage":       hex.EncodeToString(preimage),
			"minimum_value":  hex.EncodeToString(scriptNum(10_000)),
			"claim_until":    hex.EncodeToString(scriptNum(until.Unix())),
			"lockup_program": hex.EncodeToString(ptx.UnsignedTx.TxOut[0].PkScript[2:]),
		},
	})
	require.NoError(t, err)
	ciphertext, err := ecies.Encrypt(key.PubKey(), payload)
	require.NoError(t, err)
	return e, id, map[string]string{
		"taptree":          hex.EncodeToString(ptx.Outputs[0].TaprootTapTree),
		"receiver_program": legacy["receiver_program"], "ciphertext": hex.EncodeToString(ciphertext),
	}, legacy, until
}

func TestOfflineReceivePersistsBeforeFunding(t *testing.T) {
	e, id, vars, _, until := offlineClaim(t)
	e.svc.limits.MinWatchExpiry = 24 * time.Hour
	d, err := e.svc.RegisterDelegation(t.Context(), id, vars, nil)
	require.NoError(t, err)
	require.Equal(t, until, *d.ExpiresAt)
	repeated, err := e.svc.RegisterDelegation(t.Context(), id, vars, nil)
	require.NoError(t, err)
	require.Equal(t, d.ID, repeated.ID)

	pk, err := hex.DecodeString(d.Slots[0].Script)
	require.NoError(t, err)
	e.indexer.vtxos = append(e.indexer.vtxos, e.vtxoAt(t, pk, 10_000, time.Hour))
	r := e.restart(t)
	calls := 0
	r.emulator.submitTx = func(string, []string) (string, []string, error) {
		calls++
		return "", nil, errBoom
	}
	r.scan(t)
	require.Equal(t, 1, calls, "funding while stopped is found by indexer scan, without stream delivery")
	require.NotNil(t, r.svc.watched[d.ID])
}

func TestOfflineReceiveRejectsUnderfundingAndBorrowedCiphertext(t *testing.T) {
	e, id, vars, legacy, _ := offlineClaim(t)
	tmpl, err := e.svc.parseTemplate(t.Context(), id)
	require.NoError(t, err)
	inst, err := e.svc.newInstance(t.Context(), tmpl, e.svc.cosigners[0], vars, nil, nil)
	require.NoError(t, err)
	for _, amount := range []int64{9999, 10_000, 12_000} {
		tx := e.source(t, []*wire.TxOut{wire.NewTxOut(amount, inst.PkScript(0))})
		source := &template.Source{Tx: tx, Amount: uint64(amount)}
		source.Outpoint.Hash = tx.TxHash()
		act, err := inst.Build(t.Context(), []*template.Source{source}, template.Fee{Dust: 330})
		if amount < 10_000 {
			require.ErrorIs(t, err, template.ErrIneligible)
			require.Nil(t, act)
		} else {
			require.NoError(t, err)
			require.EqualValues(t, amount, act.Tx.UnsignedTx.TxOut[0].Value)
		}
	}
	altered := maps.Clone(legacy)
	altered["receiver_program"] = hex.EncodeToString(e.userKey.PubKey().SerializeCompressed()[1:])
	original, err := e.svc.parseTemplate(t.Context(), e.fixture(t, "vhtlc_claim.json"))
	require.NoError(t, err)
	other, err := e.svc.newInstance(t.Context(), original, e.svc.cosigners[0], altered, nil, nil)
	require.NoError(t, err)
	tree, err := txutils.TapTree(other.Tapscripts(0)).Encode()
	require.NoError(t, err)
	borrowed := maps.Clone(vars)
	borrowed["taptree"] = hex.EncodeToString(tree)
	borrowed["receiver_program"] = altered["receiver_program"]
	otherInstance, err := e.svc.newInstance(t.Context(), tmpl, e.svc.cosigners[0], borrowed, nil, nil)
	require.NoError(t, err)
	tx := e.source(t, []*wire.TxOut{wire.NewTxOut(10_000, other.PkScript(0))})
	source := &template.Source{Tx: tx, Amount: 10_000}
	source.Outpoint.Hash = tx.TxHash()
	_, err = otherInstance.Build(t.Context(), []*template.Source{source}, template.Fee{Dust: 330})
	require.ErrorIs(t, err, template.ErrIneligible)
}

func TestOfflineReceiveRejectsLegacyAndDisabledTemplates(t *testing.T) {
	e, id, vars, legacy, _ := offlineClaim(t)
	wrong := maps.Clone(vars)
	wrong["ciphertext"] = legacy["ciphertext"]
	_, err := e.svc.RegisterDelegation(t.Context(), id, wrong, nil)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "preimage\":")
	require.NoError(t, e.svc.SetTemplateStatus(t.Context(), id, domain.TemplateStatusDisabled))
	_, err = e.svc.RegisterDelegation(t.Context(), id, vars, nil)
	require.ErrorIs(t, err, domain.ErrTemplateDisabled)
}

func TestOfflineReceiveQueuedPastDeadlineDoesNotDisclose(t *testing.T) {
	e, id, vars, _, _ := offlineClaim(t)
	d, err := e.svc.RegisterDelegation(t.Context(), id, vars, nil)
	require.NoError(t, err)
	inputs := dueAt(t, e, d)
	past := time.Now().Add(-time.Second)
	inputs[0].watched.delegation.ExpiresAt = &past
	calls := 0
	e.emulator.submitTx = func(string, []string) (string, []string, error) {
		calls++
		return "", nil, errBoom
	}
	result := e.svc.runDirect(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.ErrorIs(t, result.err, context.DeadlineExceeded)
	require.Zero(t, calls)
}

func TestOfflineReceiveAuthenticatesTemplateAndDeadline(t *testing.T) {
	for _, field := range []string{"template_id", "claim_until"} {
		t.Run(field, func(t *testing.T) {
			e, id, vars, _, _ := offlineClaim(t)
			ciphertext, err := hex.DecodeString(vars["ciphertext"])
			require.NoError(t, err)
			key := e.svc.encryptionKeys[0]
			plaintext, err := ecies.Decrypt(key, ciphertext)
			require.NoError(t, err)
			var payload map[string]any
			require.NoError(t, json.Unmarshal(plaintext, &payload))
			if field == "template_id" {
				payload[field] = "00"
			} else {
				payload["values"].(map[string]any)[field] = hex.EncodeToString(scriptNum(time.Now().Add(-time.Minute).Unix()))
			}
			plaintext, err = json.Marshal(payload)
			require.NoError(t, err)
			ciphertext, err = ecies.Encrypt(key.PubKey(), plaintext)
			require.NoError(t, err)
			vars["ciphertext"] = hex.EncodeToString(ciphertext)
			_, err = e.svc.RegisterDelegation(t.Context(), id, vars, nil)
			require.Error(t, err)
		})
	}
}

func TestOfflineReceiveDeadlinePreservesOrdinaryWatchActions(t *testing.T) {
	e, _, inputs := claimEnv(t)
	past := time.Now().Add(-time.Second)
	inputs[0].watched.delegation.ExpiresAt = &past
	calls := 0
	e.emulator.submitTx = func(string, []string) (string, []string, error) {
		calls++
		return "", nil, errBoom
	}
	e.svc.runDirect(t.Context(), e.svc.cosigners[0], inputs, e.ark.info.Fees.IntentFees)
	require.Equal(t, 1, calls)
}

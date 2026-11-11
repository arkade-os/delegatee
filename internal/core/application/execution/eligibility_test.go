package execution

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	delegationapp "github.com/arkade-os/executor/internal/core/application/delegation"
	registryapp "github.com/arkade-os/executor/internal/core/application/registry"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/internal/core/domain/execution"
	"github.com/arkade-os/executor/internal/core/domain/registry"
	"github.com/arkade-os/executor/internal/core/ports"
	"github.com/arkade-os/executor/pkg/template"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/stretchr/testify/require"
)

func TestStreamBuildFailureClassification(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		streamID int64
		charge   bool
	}{
		{"stream ineligible", template.ErrIneligible, 1, false},
		{"client ineligible", template.ErrIneligible, 0, true},
		{"bad transaction", execution.ErrBadTx, 1, true},
		{"refusal", refused{errors.New("rejected")}, 1, true},
		{"backend error", errors.New("backend unavailable"), 1, false},
		{"deadline", context.DeadlineExceeded, 1, false},
		{"ineligible bad transaction", errors.Join(template.ErrIneligible, execution.ErrBadTx), 1, true},
		{"ineligible refusal", errors.Join(template.ErrIneligible, refused{errors.New("rejected")}), 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inst := &delegationapp.Instance{Delegation: &delegation.Delegation{StreamID: tc.streamID}}
			err := localBuildError(inst, tc.err)
			require.EqualError(t, err, tc.err.Error())
			require.ErrorIs(t, err, tc.err)
			require.Equal(t, tc.charge, chargesTemplate(fmt.Errorf("worker: %w", err)))
		})
	}
}

func TestStreamEligibilityDoesNotDisableTemplate(t *testing.T) {
	for _, typ := range []template.Type{template.Offchain, template.Intent} {
		for _, streamID := range []int64{0, 1} {
			t.Run(fmt.Sprintf("%s/stream_%d", typ, streamID), func(t *testing.T) {
				var doc map[string]any
				require.NoError(t, json.Unmarshal(fixture(t, "minimal.json"), &doc))
				doc["type"] = string(typ)
				delete(doc, "fees")
				doc["inputs"].([]any)[0].(map[string]any)["predicate"] = "00"
				raw, err := json.Marshal(doc)
				require.NoError(t, err)
				tmpl, err := template.Parse(raw, nil)
				require.NoError(t, err)
				inst := instance(t, raw, nil)
				d := delegation.Delegation{ID: 1, StreamID: streamID, TemplateID: tmpl.ID(), Status: delegation.StatusActive}
				d.Inputs = []delegation.Input{{Name: "funds", Script: hex.EncodeToString(inst.PkScript(0)), Tapscripts: inst.Tapscripts(0)}}
				source := wire.NewMsgTx(3)
				source.AddTxIn(&wire.TxIn{})
				source.AddTxOut(wire.NewTxOut(10000, inst.PkScript(0)))
				coin := delegation.Coin{Outpoint: source.TxHash().String() + ":0", DelegationID: d.ID, Script: d.Inputs[0].Script, Amount: 10000, Status: delegation.Present}
				templates := &eligibilityTemplates{row: registry.Template{ID: tmpl.ID(), Document: raw, Status: registry.TemplateStatusActive}}
				registryService := registryapp.NewService(nil, templates, registryapp.Limits{})
				key := testKey(1)
				delegations := delegationapp.NewService(registryService, &eligibilityDelegations{row: d}, nil, nil, key.PubKey(), nil, key.PubKey(), key.PubKey(), arklib.BitcoinRegTest, delegationapp.Limits{})
				coins, attempts := &eligibilityCoins{}, &eligibilityAttempts{}
				s := &Service{ctx: t.Context(), delegations: delegations, templates: registryService, coins: coins, attempts: attempts,
					indexer: &eligibilityIndexer{tx: source}, ark: &eligibilitySigner{}, cosignerKey: key, info: ports.ArkInfo{Dust: 330}, limits: Limits{TemplateMaxFailures: 10}}
				bound := &delegationapp.Instance{Delegation: &d, Template: inst, Type: typ}
				if typ == template.Offchain {
					_, _, err = s.build(t.Context(), bound, []delegation.Coin{coin})
				} else {
					_, err = (&batchWorker{s: s}).intentOf(t.Context(), bound, execution.Entry{Coins: []delegation.Coin{coin}})
				}
				require.ErrorIs(t, err, template.ErrIneligible)
				require.EqualError(t, err, "build: ineligible: predicate must return one canonical true")
				wrapped := fmt.Errorf("worker: %w", err)
				for attempt := range 11 {
					s.failed(attemptFailed{attempt: delegation.Attempt{DelegationID: 1, Coins: []string{coin.Outpoint}, Status: delegation.Submitted}, err: wrapped, retryIn: 5 * time.Second}, now.Add(time.Duration(attempt)*time.Minute))
				}
				require.Len(t, attempts.rows, 11)
				require.Len(t, coins.ready, 11)
				for attempt, at := range coins.ready {
					require.Equal(t, now.Add(time.Duration(attempt)*time.Minute+5*time.Second), at)
					require.Equal(t, delegation.Failed, attempts.rows[attempt].Status)
					require.Equal(t, []string{coin.Outpoint}, attempts.rows[attempt].Coins)
				}
				if streamID != 0 {
					require.Zero(t, templates.row.Failures)
					require.Zero(t, s.templateFailures)
					_, err := registryService.Usable(t.Context(), tmpl.ID())
					require.NoError(t, err)
				} else {
					require.Equal(t, 11, templates.row.Failures)
					require.EqualValues(t, 11, s.templateFailures)
					require.Equal(t, registry.TemplateStatusDisabled, templates.row.Status)
				}
			})
		}
	}
}

type eligibilityIndexer struct {
	ports.Indexer
	tx *wire.MsgTx
}

func (r *eligibilityIndexer) VirtualTxs(context.Context, []string) (map[string]*wire.MsgTx, error) {
	return map[string]*wire.MsgTx{r.tx.TxHash().String(): r.tx}, nil
}

type eligibilitySigner struct{ ports.Signer }

func (*eligibilitySigner) Info(context.Context) (ports.ArkInfo, error) {
	return ports.ArkInfo{Dust: 330}, nil
}

type eligibilityTemplates struct {
	registry.TemplateRepository
	row registry.Template
}

func (r *eligibilityTemplates) Get(context.Context, string) (*registry.Template, error) {
	row := r.row
	return &row, nil
}
func (r *eligibilityTemplates) AddOrUpdate(_ context.Context, row *registry.Template) error {
	r.row = *row
	return nil
}

type eligibilityDelegations struct {
	delegation.DelegationRepository
	row delegation.Delegation
}

func (r *eligibilityDelegations) Get(context.Context, int64) (*delegation.Delegation, error) {
	row := r.row
	return &row, nil
}

type eligibilityAttempts struct {
	delegation.AttemptRepository
	rows []delegation.Attempt
}

func (r *eligibilityAttempts) AddOrUpdate(_ context.Context, row *delegation.Attempt) error {
	r.rows = append(r.rows, *row)
	return nil
}

type eligibilityCoins struct {
	delegation.CoinRepository
	ready []time.Time
}

func (r *eligibilityCoins) Release(_ context.Context, _ []string, ready time.Time) error {
	r.ready = append(r.ready, ready)
	return nil
}

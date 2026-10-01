package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	clientlib "github.com/arkade-os/arkd/pkg/client-lib"
	arkclient "github.com/arkade-os/arkd/pkg/client-lib/client"
	"github.com/arkade-os/arkd/pkg/client-lib/indexer"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// TestLiveDelegatee boards a coin through a deployed delegatee: pay the printed address (e.g. faucet.mutinynet.com). Run with:
//
//	DELEGATEE_URL=https://delegatee.mutinynet.arkade.sh \
//	ARK_URL=https://mutinynet.arkade.sh \
//	go test -v -count=1 -timeout 40m -run TestLiveDelegatee ./test/e2e/
//
// OWNER_KEY (hex) reuses an earlier owner; the coin renews only in its last 1024 s, so rerun when told.
func TestLiveDelegatee(t *testing.T) {
	delegateeURL, arkURL := os.Getenv("DELEGATEE_URL"), os.Getenv("ARK_URL")
	if delegateeURL == "" || arkURL == "" {
		t.Skip("set DELEGATEE_URL and ARK_URL")
	}
	ctx := t.Context()
	client := restClient{base: strings.TrimSuffix(delegateeURL, "/")}
	indexerSvc, err := indexer.NewClient(arkURL)
	require.NoError(t, err)
	t.Cleanup(indexerSvc.Close)
	info, err := client.GetInfo(ctx, &delegateev1.GetInfoRequest{})
	require.NoError(t, err)
	arkClient, err := arkclient.NewClient(arkURL, "e2e")
	require.NoError(t, err)
	t.Cleanup(arkClient.Close)
	arkInfo, err := arkClient.GetInfo(ctx)
	require.NoError(t, err)
	o := owner{liveOwnerKey(t), keysOf(t, info)}
	vars := o.variables(0)
	vars["exit_delay"] = scriptNum(sequence(t, arkInfo.UnilateralExitDelay))
	boardingVars := maps.Clone(vars)
	boardingVars["boarding_exit_delay"] = scriptNum(sequence(t, arkInfo.BoardingExitDelay))

	renewal, boarding := liveTemplates(t, client)
	r, err := client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: renewal, Variables: vars})
	require.NoError(t, err)
	w, err := client.RegisterDelegation(ctx, &delegateev1.RegisterDelegationRequest{TemplateId: boarding, Variables: boardingVars})
	require.NoError(t, err)
	fmt.Printf("\n>>> pay the boarding address %s, checking every 10s\n\n", w.Delegation.Address)

	script := scriptOf(t, r.Delegation)
	var boarded clientlib.Vtxo
	require.Eventually(t, func() bool {
		vtxos := vtxosAt(ctx, indexerSvc, script)
		if len(vtxos) > 0 {
			boarded = vtxos[0]
		}
		return len(vtxos) > 0
	}, 30*time.Minute, 10*time.Second, "nothing boarded")
	opensAt := boarded.ExpiresAt.Add(-1024 * time.Second)
	if time.Until(opensAt) > 10*time.Minute {
		t.Logf("%s expires %s: rerun after %s with OWNER_KEY", boarded.Outpoint.String(), boarded.ExpiresAt, opensAt.Format(time.RFC3339))
		return
	}
	require.Eventually(t, func() bool {
		return slices.ContainsFunc(vtxosAt(ctx, indexerSvc, script), func(v clientlib.Vtxo) bool { return v.Txid != boarded.Txid && !v.Preconfirmed })
	}, 30*time.Minute, 15*time.Second, "not renewed")
}

type restClient struct{ base string }

func (c restClient) GetInfo(ctx context.Context, _ *delegateev1.GetInfoRequest) (*delegateev1.GetInfoResponse, error) {
	out := &delegateev1.GetInfoResponse{}
	return out, c.do(ctx, http.MethodGet, c.base+"/v1/info", nil, out)
}

func (c restClient) RegisterDelegation(ctx context.Context, req *delegateev1.RegisterDelegationRequest) (*delegateev1.RegisterDelegationResponse, error) {
	out := &delegateev1.RegisterDelegationResponse{}
	return out, c.do(ctx, http.MethodPost, c.base+"/v1/delegate", req, out)
}

func (c restClient) RegisterTemplate(ctx context.Context, req *delegateev1.RegisterTemplateRequest) (*delegateev1.RegisterTemplateResponse, error) {
	out := &delegateev1.RegisterTemplateResponse{}
	return out, c.do(ctx, http.MethodPost, c.base+"/v1/template", req, out)
}

func (c restClient) RegisterArtifact(ctx context.Context, req *delegateev1.RegisterArtifactRequest) (*delegateev1.RegisterArtifactResponse, error) {
	out := &delegateev1.RegisterArtifactResponse{}
	return out, c.do(ctx, http.MethodPost, c.base+"/v1/artifact", req, out)
}

func (c restClient) do(ctx context.Context, method, url string, in, out proto.Message) error {
	var body io.Reader
	if in != nil {
		raw, err := protojson.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s: %d %s", method, url, resp.StatusCode, raw)
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(raw, out)
}

// vtxosAt is empty on error.
func vtxosAt(ctx context.Context, indexerSvc clientlib.Indexer, script string) []clientlib.Vtxo {
	resp, err := indexerSvc.GetVtxos(ctx, clientlib.WithScripts([]string{script}), clientlib.WithSpendableOnly())
	if err != nil {
		return nil
	}
	return resp.Vtxos
}

// liveOwnerKey is OWNER_KEY, else a new key logged for reruns.
func liveOwnerKey(t *testing.T) []byte {
	t.Helper()
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	if k := os.Getenv("OWNER_KEY"); k != "" {
		raw, err := hex.DecodeString(k)
		require.NoError(t, err)
		key, _ = btcec.PrivKeyFromBytes(raw)
	}
	t.Logf("OWNER_KEY=%x", key.Serialize())
	return key.PubKey().SerializeCompressed()
}

// liveTemplates registers the default templates and their artifact.
func liveTemplates(t *testing.T, client restClient) (renewal, boarding string) {
	t.Helper()
	_, err := client.RegisterArtifact(t.Context(), &delegateev1.RegisterArtifactRequest{Document: string(fixture(t, "artifacts/delegated_vtxo.json"))})
	require.NoError(t, err)
	register := func(file string) string {
		resp, err := client.RegisterTemplate(t.Context(), &delegateev1.RegisterTemplateRequest{Document: string(fixture(t, file))})
		require.NoError(t, err)
		return resp.Template.Id
	}
	return register("renewal.json"), register("boarding.json")
}

// sequence is arkd's delay, seconds from 512 and blocks below, in BIP 68.
func sequence(t *testing.T, delay int64) int64 {
	t.Helper()
	lt := arklib.RelativeLocktime{Type: arklib.LocktimeTypeBlock, Value: uint32(delay)}
	if delay >= 512 {
		lt.Type = arklib.LocktimeTypeSecond
	}
	seq, err := arklib.BIP68Sequence(lt)
	require.NoError(t, err)
	return int64(seq)
}

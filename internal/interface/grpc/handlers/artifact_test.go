package handlers

import (
	"os"
	"strings"
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	delegationapp "github.com/arkade-os/executor/internal/core/application/delegation"
	executionapp "github.com/arkade-os/executor/internal/core/application/execution"
	app "github.com/arkade-os/executor/internal/core/application/registry"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterArtifactThenGet(t *testing.T) {
	h := testHandler(t, 10)
	doc := testDocument(t)
	reg, err := h.RegisterArtifact(t.Context(), &executorv1.RegisterArtifactRequest{Document: doc})
	require.NoError(t, err)
	require.Len(t, reg.GetArtifact().GetId(), 64)
	require.Equal(t, doc, reg.GetArtifact().GetDocument())
	require.NotZero(t, reg.GetArtifact().GetCreatedAt())

	got, err := h.GetArtifact(t.Context(), &executorv1.GetArtifactRequest{Id: reg.GetArtifact().GetId()})
	require.NoError(t, err)
	require.Equal(t, reg.GetArtifact().GetId(), got.GetArtifact().GetId())
	require.Equal(t, doc, got.GetArtifact().GetDocument())
}

func TestRegisterArtifactErrors(t *testing.T) {
	h := testHandler(t, 1)
	_, err := h.RegisterArtifact(t.Context(), &executorv1.RegisterArtifactRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.RegisterArtifact(t.Context(), &executorv1.RegisterArtifactRequest{Document: "nope"})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = h.RegisterArtifact(t.Context(), &executorv1.RegisterArtifactRequest{Document: testDocument(t)})
	require.NoError(t, err)
	other := strings.Replace(testDocument(t), `"DelegatedVtxo"`, `"Other"`, 1)
	_, err = h.RegisterArtifact(t.Context(), &executorv1.RegisterArtifactRequest{Document: other})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestGetArtifactErrors(t *testing.T) {
	h := testHandler(t, 0)
	_, err := h.GetArtifact(t.Context(), &executorv1.GetArtifactRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.GetArtifact(t.Context(), &executorv1.GetArtifactRequest{Id: "missing"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func testHandler(t *testing.T, maxArtifacts int) *Executor {
	t.Helper()
	return testHandlerWithLimits(t, maxArtifacts, delegationapp.Limits{MinDelegationExpiry: 24 * time.Hour})
}

func testHandlerWithLimits(t *testing.T, maxArtifacts int, limits delegationapp.Limits) *Executor {
	t.Helper()
	h, _ := testHandlerAndCoins(t, maxArtifacts, limits)
	return h
}

// testHandlerAndCoins wires the handler over in-memory repositories and the keys of testKeys.
func testHandlerAndCoins(t *testing.T, maxArtifacts int, limits delegationapp.Limits) (*Executor, *coins) {
	t.Helper()
	h, coins, _ := testHandlerAndStores(t, maxArtifacts, limits)
	return h, coins
}

func testHandlerAndStores(t *testing.T, maxArtifacts int, limits delegationapp.Limits) (*Executor, *coins, *attempts) {
	t.Helper()
	reg := testService(t, maxArtifacts)
	server, emulator, cosigner := testKeys(t)
	svc := delegationapp.NewService(reg, newDelegations(), newStreams(), nil, cosigner.PubKey(), nil, server.PubKey(), emulator.PubKey(), arklib.BitcoinRegTest, limits)
	coins, attempts := newCoins(), newAttempts()
	execution := executionapp.NewService(svc, nil, nil, nil, nil, nil, nil, coins, attempts, nil, executionapp.Limits{})
	return NewExecutor(reg, svc, execution, "test"), coins, attempts
}

// testKeys derives the server, emulator and cosigner keys from fixed scalars.
func testKeys(t *testing.T) (server, emulator, cosigner *btcec.PrivateKey) {
	t.Helper()
	keys := make([]*btcec.PrivateKey, 3)
	for i := range keys {
		var scalar btcec.ModNScalar
		scalar.SetInt(uint32(i + 1))
		keys[i] = btcec.PrivKeyFromScalar(&scalar)
	}
	return keys[0], keys[1], keys[2]
}

func testService(t *testing.T, maxArtifacts int) *app.Service {
	t.Helper()
	templates := newTemplates()
	return app.NewService(newArtifacts(templates), templates, app.Limits{
		MaxArtifacts: maxArtifacts, MaxTemplates: maxArtifacts, MaxDocumentBytes: 1 << 20,
	})
}

func testDocument(t *testing.T) string {
	t.Helper()
	doc, err := os.ReadFile("../../../../templates/artifacts/delegated_vtxo.json")
	require.NoError(t, err)
	return string(doc)
}

package handlers

import (
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/arkade-os/emulator/pkg/arkade"
	executorv1 "github.com/arkade-os/executor/api-spec/protobuf/gen/executor/v1"
	delegationapp "github.com/arkade-os/executor/internal/core/application/delegation"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterDelegationThenGet(t *testing.T) {
	h := testHandler(t, 10)
	id := registerDefault(t, h)

	reg, err := h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t)})
	require.NoError(t, err)
	d := reg.GetDelegation()
	require.NotZero(t, d.GetId())
	require.Len(t, d.GetFingerprint(), 64)
	require.NotEmpty(t, d.GetAddress())
	require.Equal(t, id, d.GetTemplateId())
	require.Len(t, d.GetInputs(), 1)
	require.Equal(t, "funds", d.GetInputs()[0].GetName())
	require.NotEmpty(t, d.GetInputs()[0].GetScript())
	require.NotEmpty(t, d.GetInputs()[0].GetTapscripts())
	require.Zero(t, d.GetStreamId())
	require.Zero(t, d.GetExpiresAt())
	require.Equal(t, "active", d.GetStatus())
	require.NotZero(t, d.GetCreatedAt())

	got, err := h.GetDelegation(t.Context(), &executorv1.GetDelegationRequest{Id: d.GetId()})
	require.NoError(t, err)
	require.Equal(t, d.GetAddress(), got.GetDelegation().GetAddress())
	got, err = h.GetDelegation(t.Context(), &executorv1.GetDelegationRequest{Address: d.GetAddress()})
	require.NoError(t, err)
	require.Equal(t, d.GetId(), got.GetDelegation().GetId())

	again, err := h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t)})
	require.NoError(t, err)
	require.Equal(t, d.GetId(), again.GetDelegation().GetId())
}

func TestRegisterDelegationWithExpiry(t *testing.T) {
	h := testHandler(t, 10)
	id := registerDefault(t, h)
	expires := time.Now().Add(48 * time.Hour).Unix()
	reg, err := h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{
		TemplateId: id, Variables: renewalVariables(t), ExpiresAt: expires,
	})
	require.NoError(t, err)
	require.Equal(t, expires, reg.GetDelegation().GetExpiresAt())

	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{
		TemplateId: id, Variables: renewalVariables(t), ExpiresAt: time.Now().Add(time.Hour).Unix(),
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestRegisterDelegationErrors(t *testing.T) {
	h := testHandlerWithLimits(t, 10, delegationapp.Limits{MaxDelegations: 1})
	_, err := h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: "missing"})
	require.Equal(t, codes.NotFound, status.Code(err))

	id := registerDefault(t, h)
	bad := renewalVariables(t)
	bad["owner"] = "nope"
	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: id, Variables: bad})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	release := registerDocument(t, h, "../../../../pkg/template/testdata/delegate_release.json")
	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: release})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "a leaf naming the cosigner key")

	two := registerDocument(t, h, "../../../../pkg/template/testdata/counter.json")
	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: two})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "two inputs")

	require.NoError(t, h.registry.SetTemplateStatus(t.Context(), id, "disabled"))
	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t)})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "disabled")
	require.NoError(t, h.registry.SetTemplateStatus(t.Context(), id, "active"))

	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t)})
	require.NoError(t, err)
	_, err = h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t, 2)})
	require.Equal(t, codes.ResourceExhausted, status.Code(err))
}

func TestGetDelegationListsCoins(t *testing.T) {
	h, coins := testHandlerAndCoins(t, 10, delegationapp.Limits{MinDelegationExpiry: 24 * time.Hour})
	id := registerDefault(t, h)
	reg, err := h.RegisterDelegation(t.Context(), &executorv1.RegisterDelegationRequest{TemplateId: id, Variables: renewalVariables(t)})
	require.NoError(t, err)
	d := reg.GetDelegation()
	got, err := h.GetDelegation(t.Context(), &executorv1.GetDelegationRequest{Id: d.GetId()})
	require.NoError(t, err)
	require.Empty(t, got.GetCoins())

	now := time.Now()
	present := delegation.Coin{
		Outpoint: "aa:0", DelegationID: d.GetId(), Script: d.GetInputs()[0].GetScript(), Amount: 1000,
		ExpiresAt: now.Add(time.Hour), CreatedAt: now, Due: now.Add(time.Minute), Status: delegation.Present, Confirmations: 2,
	}
	spent := delegation.Coin{
		Outpoint: "bb:1", DelegationID: d.GetId(), Script: present.Script, Amount: 5, CreatedAt: now.Add(-time.Hour),
		Status: delegation.Spent, SpentBy: "cc",
	}
	other := present
	other.Outpoint, other.DelegationID = "dd:0", d.GetId()+1
	require.NoError(t, coins.Upsert(t.Context(), present, spent, other))

	got, err = h.GetDelegation(t.Context(), &executorv1.GetDelegationRequest{Address: d.GetAddress()})
	require.NoError(t, err)
	require.Len(t, got.GetCoins(), 2)
	first, second := got.GetCoins()[0], got.GetCoins()[1]
	require.Equal(t, "bb:1", first.GetOutpoint())
	require.Equal(t, "spent", first.GetStatus())
	require.Equal(t, "cc", first.GetSpentBy())
	require.Zero(t, first.GetExpiresAt())
	require.Zero(t, first.GetDue())
	require.Equal(t, "aa:0", second.GetOutpoint())
	require.Equal(t, uint64(1000), second.GetAmount())
	require.Equal(t, now.Add(time.Hour).Unix(), second.GetExpiresAt())
	require.Equal(t, now.Add(time.Minute).Unix(), second.GetDue())
	require.Equal(t, "present", second.GetStatus())
	require.Equal(t, int32(2), second.GetConfirmations())
	require.Empty(t, second.GetSpentBy())
}

func TestGetDelegationErrors(t *testing.T) {
	h := testHandler(t, 0)
	_, err := h.GetDelegation(t.Context(), &executorv1.GetDelegationRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = h.GetDelegation(t.Context(), &executorv1.GetDelegationRequest{Id: 7})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = h.GetDelegation(t.Context(), &executorv1.GetDelegationRequest{Address: "nowhere"})
	require.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetInfo(t *testing.T) {
	h := testHandler(t, 0)
	server, emulator, cosigner := testKeys(t)
	info, err := h.GetInfo(t.Context(), &executorv1.GetInfoRequest{})
	require.NoError(t, err)
	require.Equal(t, "test", info.GetVersion())
	require.Equal(t, "regtest", info.GetNetwork())
	require.Equal(t, hex.EncodeToString(cosigner.PubKey().SerializeCompressed()), info.GetCosignerPubkey())
	require.Equal(t, hex.EncodeToString(server.PubKey().SerializeCompressed()), info.GetServerPubkey())
	require.Equal(t, hex.EncodeToString(emulator.PubKey().SerializeCompressed()), info.GetEmulatorPubkey())
	require.Empty(t, info.GetEncryptionPubkey())
}

func registerDocument(t *testing.T, h *Executor, path string) string {
	t.Helper()
	doc, err := os.ReadFile(path)
	require.NoError(t, err)
	reg, err := h.RegisterTemplate(t.Context(), &executorv1.RegisterTemplateRequest{Document: string(doc)})
	require.NoError(t, err)
	return reg.GetTemplate().GetId()
}

// renewalVariables are the renewal template's variables for a fixed owner, seed picking the owner key.
func renewalVariables(t *testing.T, seed ...uint32) map[string]string {
	t.Helper()
	var scalar btcec.ModNScalar
	scalar.SetInt(append(seed, 1)[0] + 100)
	owner := btcec.PrivKeyFromScalar(&scalar)
	return map[string]string{
		"owner": hex.EncodeToString(owner.PubKey().SerializeCompressed()), "exit_delay": scriptNum(1<<22 | 1),
		"renewal_window": scriptNum(1024), "max_fee": scriptNum(1000),
	}
}

func scriptNum(n int64) string {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return hex.EncodeToString(b)
}

package handlers

import (
	"testing"
	"time"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	delegateev1 "github.com/arkade-os/delegatee/api-spec/protobuf/gen/delegatee/v1"
	delegationapp "github.com/arkade-os/delegatee/internal/core/application/delegation"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRegisterListCancelStream(t *testing.T) {
	admin, id := testStreamAdmin(t)

	reg, err := admin.RegisterStream(t.Context(), &delegateev1.RegisterStreamRequest{TemplateId: id})
	require.NoError(t, err)
	st := reg.GetStream()
	require.NotZero(t, st.GetId())
	require.Equal(t, id, st.GetTemplateId())
	require.Equal(t, "active", st.GetStatus())
	require.NotZero(t, st.GetCreatedAt())

	again, err := admin.RegisterStream(t.Context(), &delegateev1.RegisterStreamRequest{TemplateId: id})
	require.NoError(t, err)
	require.Equal(t, st.GetId(), again.GetStream().GetId())

	list, err := admin.ListStreams(t.Context(), &delegateev1.ListStreamsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetStreams(), 1)

	_, err = admin.CancelStream(t.Context(), &delegateev1.CancelStreamRequest{Id: st.GetId()})
	require.NoError(t, err)
	list, err = admin.ListStreams(t.Context(), &delegateev1.ListStreamsRequest{})
	require.NoError(t, err)
	require.Equal(t, "cancelled", list.GetStreams()[0].GetStatus())

	_, err = admin.CancelStream(t.Context(), &delegateev1.CancelStreamRequest{Id: st.GetId()})
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = admin.RegisterStream(t.Context(), &delegateev1.RegisterStreamRequest{TemplateId: id})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "a cancelled stream stays cancelled")
}

func TestRegisterStreamErrors(t *testing.T) {
	admin, id := testStreamAdmin(t)
	_, err := admin.RegisterStream(t.Context(), &delegateev1.RegisterStreamRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.RegisterStream(t.Context(), &delegateev1.RegisterStreamRequest{TemplateId: "missing"})
	require.Equal(t, codes.NotFound, status.Code(err))
	_, err = admin.RegisterStream(t.Context(), &delegateev1.RegisterStreamRequest{TemplateId: id, Variables: map[string]string{"ciphertext": "00"}})
	require.Equal(t, codes.InvalidArgument, status.Code(err))

	_, err = admin.registry.RegisterArtifact(t.Context(), []byte(testDocument(t)))
	require.NoError(t, err)
	stored, err := admin.registry.RegisterTemplate(t.Context(), []byte(testTemplateDocument(t, "renewal.json")))
	require.NoError(t, err)
	renewal := stored.ID
	_, err = admin.RegisterStream(t.Context(), &delegateev1.RegisterStreamRequest{TemplateId: renewal})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "no trigger")

	_, err = admin.CancelStream(t.Context(), &delegateev1.CancelStreamRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = admin.CancelStream(t.Context(), &delegateev1.CancelStreamRequest{Id: 99})
	require.Equal(t, codes.NotFound, status.Code(err))
}

// testStreamAdmin is an admin over a daemon with an encryption key and the claim template, which has a trigger.
func testStreamAdmin(t *testing.T) (*Admin, string) {
	t.Helper()
	reg := testService(t, 10)
	server, emulator, cosigner := testKeys(t)
	encryption, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	svc := delegationapp.NewService(
		reg, newDelegations(), newStreams(), nil, cosigner.PubKey(), encryption, server.PubKey(), emulator.PubKey(),
		arklib.BitcoinRegTest, delegationapp.Limits{MinDelegationExpiry: time.Hour},
	)
	stored, err := reg.RegisterTemplate(t.Context(), []byte(testTemplateDocument(t, "noninteractiveclaim.json")))
	require.NoError(t, err)
	return NewAdmin(reg, svc, nil, nil), stored.ID
}

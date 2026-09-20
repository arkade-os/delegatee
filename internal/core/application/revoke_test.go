package application

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/stretchr/testify/require"
)

func TestRevokeDelegation(t *testing.T) {
	env := newTestEnv(t)
	ctx := t.Context()
	d := env.register(t, domain.Params{RenewalWindow: 600})
	now := time.Now().Unix()
	sign := func(priv *btcec.PrivateKey, address string, ts int64) string {
		sig, err := schnorr.Sign(priv, RevocationHash(address, ts))
		require.NoError(t, err)
		return hex.EncodeToString(sig.Serialize())
	}
	owner := hex.EncodeToString(schnorr.SerializePubKey(env.userKey.PubKey()))
	ownerCompressed := hex.EncodeToString(env.userKey.PubKey().SerializeCompressed())

	// someone else's key, even a valid signature
	stranger, _ := hexKey(t)
	err := env.svc.RevokeDelegation(ctx, d.Address, hex.EncodeToString(stranger.PubKey().SerializeCompressed()), sign(stranger, d.Address, now), now)
	require.ErrorIs(t, err, ErrInvalidSignature)
	require.ErrorContains(t, err, "not a key of the exit leaf")
	// the delegate leaf's server key is not an exit key either
	err = env.svc.RevokeDelegation(ctx, d.Address, hex.EncodeToString(env.svc.serverPubKey.SerializeCompressed()), sign(stranger, d.Address, now), now)
	require.ErrorContains(t, err, "not a key of the exit leaf")

	// the owner, but for another address, an old timestamp, or a mangled signature
	other := env.register(t, domain.Params{RenewalWindow: 700})
	err = env.svc.RevokeDelegation(ctx, d.Address, owner, sign(env.userKey, other.Address, now), now)
	require.ErrorIs(t, err, ErrInvalidSignature)
	err = env.svc.RevokeDelegation(ctx, d.Address, owner, sign(env.userKey, d.Address, now-3600), now-3600)
	require.ErrorContains(t, err, "timestamp")
	err = env.svc.RevokeDelegation(ctx, d.Address, owner, sign(env.userKey, d.Address, now), now+1)
	require.ErrorIs(t, err, ErrInvalidSignature)
	err = env.svc.RevokeDelegation(ctx, d.Address, owner, "zz", now)
	require.ErrorIs(t, err, ErrInvalidSignature)
	err = env.svc.RevokeDelegation(ctx, d.Address, "zz", sign(env.userKey, d.Address, now), now)
	require.ErrorIs(t, err, ErrInvalidSignature)
	err = env.svc.RevokeDelegation(ctx, "tark1nobody", owner, sign(env.userKey, "tark1nobody", now), now)
	require.ErrorIs(t, err, domain.ErrDelegationNotFound)
	got, err := env.svc.GetDelegation(ctx, d.Address)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusActive, got.Status, "nothing above may revoke")

	// the owner, x-only or compressed key
	require.NoError(t, env.svc.RevokeDelegation(ctx, d.Address, owner, sign(env.userKey, d.Address, now), now))
	got, err = env.svc.GetDelegation(ctx, d.Address)
	require.NoError(t, err)
	require.Equal(t, domain.DelegationStatusRevoked, got.Status)
	err = env.svc.RevokeDelegation(ctx, d.Address, owner, sign(env.userKey, d.Address, now), now)
	require.ErrorIs(t, err, ErrInvalidSignature, "an accepted revocation cannot be replayed")
	require.NoError(t, env.svc.RevokeDelegation(ctx, other.Address, ownerCompressed, sign(env.userKey, other.Address, now), now))
}

func TestIsExitKey(t *testing.T) {
	require.False(t, isExitKey([]string{"zz"}, nil))
}

package delegation

import (
	"context"
	"testing"

	arklib "github.com/arkade-os/arkd/pkg/ark-lib"
	"github.com/arkade-os/executor/internal/core/domain/delegation"
	"github.com/arkade-os/executor/pkg/template/ecies"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/require"
)

func TestAddReturnsTheActiveOne(t *testing.T) {
	s := &Service{delegations: &rows{}}
	first, err := s.add(t.Context(), testDelegation("a", 0), 0)
	require.NoError(t, err)
	again, err := s.add(t.Context(), testDelegation("a", 0), 0)
	require.NoError(t, err)
	require.Equal(t, first.ID, again.ID)
}

func TestAddBlockedAfterCancelNotAfterExpiry(t *testing.T) {
	repo := &rows{}
	s := &Service{delegations: repo}
	first, err := s.add(t.Context(), testDelegation("a", 0), 0)
	require.NoError(t, err)

	repo.list[0].Status = delegation.StatusCancelled
	_, err = s.add(t.Context(), testDelegation("a", 0), 0)
	require.ErrorIs(t, err, delegation.ErrBlocked)

	repo.list[0].Status = delegation.StatusExpired
	second, err := s.add(t.Context(), testDelegation("a", 0), 0)
	require.NoError(t, err)
	require.NotEqual(t, first.ID, second.ID)
}

func TestAddCapsOriginsApart(t *testing.T) {
	repo := &rows{}
	s := &Service{delegations: repo}
	_, err := s.add(t.Context(), testDelegation("a", 0), 1)
	require.NoError(t, err)
	_, err = s.add(t.Context(), testDelegation("b", 0), 1)
	require.ErrorIs(t, err, delegation.ErrCapReached)
	_, err = s.add(t.Context(), testDelegation("a", 0), 1)
	require.NoError(t, err, "the active one still comes back at the cap")

	_, err = s.add(t.Context(), testDelegation("c", 7), 1)
	require.NoError(t, err, "a spawned delegation is not counted with the others")
	_, err = s.add(t.Context(), testDelegation("d", 7), 1)
	require.ErrorIs(t, err, delegation.ErrCapReached)

	repo.list[0].Status = delegation.StatusExpired
	_, err = s.add(t.Context(), testDelegation("b", 0), 1)
	require.NoError(t, err, "only active delegations count")
}

func TestDecryptFor(t *testing.T) {
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pub := key.PubKey()
	without := NewService(nil, nil, nil, nil, pub, nil, pub, pub, arklib.BitcoinRegTest, Limits{})
	require.Nil(t, without.decryptFor("template"))

	s := NewService(nil, nil, nil, nil, pub, key, pub, pub, arklib.BitcoinRegTest, Limits{})
	plaintext := []byte("secret")
	ciphertext, err := ecies.Encrypt(pub, plaintext, "template")
	require.NoError(t, err)
	decrypt := s.decryptFor("template")
	require.NotNil(t, decrypt)
	got, err := decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, plaintext, got)
	_, err = s.decryptFor("other template")(ciphertext)
	require.Error(t, err)
}

func testDelegation(fingerprint string, streamID int64) *delegation.Delegation {
	return &delegation.Delegation{Fingerprint: fingerprint, StreamID: streamID, Status: delegation.StatusActive}
}

// rows is the part of a delegation.DelegationRepository that add uses.
type rows struct {
	delegation.DelegationRepository
	list []delegation.Delegation
}

func (r *rows) AddOrUpdate(_ context.Context, d *delegation.Delegation) error {
	d.ID = int64(len(r.list) + 1)
	r.list = append(r.list, *d)
	return nil
}

func (r *rows) GetByFingerprint(_ context.Context, fingerprint string) (*delegation.Delegation, error) {
	for i := len(r.list) - 1; i >= 0; i-- {
		if r.list[i].Fingerprint == fingerprint {
			v := r.list[i]
			return &v, nil
		}
	}
	return nil, delegation.ErrDelegationNotFound
}

func (r *rows) CountActive(context.Context) (clients, spawned int64, err error) {
	for _, d := range r.list {
		switch {
		case d.Status != delegation.StatusActive:
		case d.StreamID != 0:
			spawned++
		default:
			clients++
		}
	}
	return clients, spawned, nil
}

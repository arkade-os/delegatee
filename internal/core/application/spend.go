package application

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const maxSpendLifetime = 24 * time.Hour

func (s *service) RegisterSpend(
	ctx context.Context, templateID string, variables map[string]string, outpoints []string, expiresAt time.Time, pubkey, signature string,
) (*domain.Delegation, error) {
	if now := time.Now(); !expiresAt.After(now) || expiresAt.After(now.Add(maxSpendLifetime)) {
		return nil, fmt.Errorf("%w: expires_at must be within %s", ErrInvalidArgs, maxSpendLifetime)
	}
	fingerprint := domain.Fingerprint(templateID, variables, outpoints)
	key, err := checkSpendSignature(fingerprint, expiresAt, pubkey, signature)
	if err != nil {
		return nil, err
	}
	tmpl, err := s.parseTemplate(ctx, templateID)
	if err != nil {
		return nil, err
	}
	if len(outpoints) != len(tmpl.Inputs()) {
		return nil, fmt.Errorf("%w: %d outpoints for %d inputs", ErrInvalidArgs, len(outpoints), len(tmpl.Inputs()))
	}
	bound := make([]*wire.OutPoint, len(outpoints))
	for i, raw := range outpoints {
		op, err := wire.NewOutPointFromString(raw)
		if err != nil || op.String() != raw || slices.Index(outpoints, raw) != i {
			return nil, fmt.Errorf("%w: bad or repeated outpoint %q", ErrInvalidArgs, raw)
		}
		bound[i] = op
	}
	inst, err := s.instanceFor(ctx, tmpl, s.cosigners[0], variables, bound, nil)
	if err != nil {
		return nil, err
	}
	slots, _, err := bindSlots(tmpl, inst, outpoints)
	if err != nil {
		return nil, err
	}
	if !exitKeyOfEverySlot(slots, key) {
		return nil, fmt.Errorf("%w: pubkey is not the key of an exit leaf of every slot", ErrInvalidArgs)
	}
	d, err := s.create(ctx, domain.Delegation{
		Fingerprint: fingerprint, TemplateID: templateID, Variables: variables,
		ExpiresAt: &expiresAt, DelegatePubKey: s.cosigners[0].pubKey, Slots: slots,
	}, false)
	if err == nil {
		s.wakeScan()
	}
	return d, err
}

func (s *service) GetSpend(ctx context.Context, id string) (*domain.Delegation, error) {
	d, err := s.repo.GetByFingerprint(ctx, id)
	if err != nil {
		return nil, err
	}
	if !d.IsSpend() {
		return nil, domain.ErrDelegationNotFound
	}
	return d, nil
}

// spendMessage is what the owner signs to register a spend.
func spendMessage(fingerprint string, expiresAt time.Time) []byte {
	fp, _ := hex.DecodeString(fingerprint)
	return chainhash.TaggedHash([]byte("delegatee/spend"), binary.BigEndian.AppendUint64(fp, uint64(expiresAt.Unix())))[:]
}

// checkSpendSignature returns the x-only key that signed.
func checkSpendSignature(fingerprint string, expiresAt time.Time, pubkey, signature string) ([]byte, error) {
	key, _ := hex.DecodeString(pubkey)
	pub, err := schnorr.ParsePubKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: pubkey must be a 32-byte x-only key", ErrInvalidArgs)
	}
	raw, _ := hex.DecodeString(signature)
	if sig, err := schnorr.ParseSignature(raw); err != nil || !sig.Verify(spendMessage(fingerprint, expiresAt), pub) {
		return nil, fmt.Errorf("%w: bad signature", ErrInvalidArgs)
	}
	return key, nil
}

// exitKeyOfEverySlot: each slot has a CSV leaf of key alone.
func exitKeyOfEverySlot(slots []domain.SlotBinding, key []byte) bool {
	for _, sl := range slots {
		if !slices.ContainsFunc(sl.Tapscripts, func(leaf string) bool {
			raw, err := hex.DecodeString(leaf)
			if err != nil {
				return false
			}
			c, err := script.DecodeClosure(raw)
			exit, ok := c.(*script.CSVMultisigClosure)
			return err == nil && ok && len(exit.PubKeys) == 1 && bytes.Equal(schnorr.SerializePubKey(exit.PubKeys[0]), key)
		}) {
			return false
		}
	}
	return true
}

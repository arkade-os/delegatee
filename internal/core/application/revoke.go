package application

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/delegatee/internal/core/domain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	log "github.com/sirupsen/logrus"
)

// The owner of a delegate address proves it with a key of its exit leaf: a
// BIP340 signature over RevocationHash, valid for revocationWindow around
// the timestamp it carries, so a captured signature cannot be replayed later.
const (
	revocationTag    = "delegatee/revoke"
	revocationWindow = 10 * time.Minute
)

// RevocationHash is what the owner signs to stop a delegation: the tagged
// hash of "<address>:<unix timestamp>".
func RevocationHash(address string, timestamp int64) []byte {
	return chainhash.TaggedHash([]byte(revocationTag), []byte(address+":"+strconv.FormatInt(timestamp, 10)))[:]
}

// RevokeDelegation stops renewing address on the owner's request: pubKeyHex
// must be a key of the exit leaf and signatureHex its BIP340 signature over
// RevocationHash(address, timestamp).
func (s *service) RevokeDelegation(ctx context.Context, address, pubKeyHex, signatureHex string, timestamp int64) error {
	if skew := time.Since(time.Unix(timestamp, 0)); skew > revocationWindow || skew < -revocationWindow {
		return fmt.Errorf("%w: timestamp is not within %s of now", ErrInvalidSignature, revocationWindow)
	}
	pubKey, err := parseXOnly(pubKeyHex)
	if err != nil {
		return fmt.Errorf("%w: pubkey: %v", ErrInvalidSignature, err)
	}
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("%w: signature: %v", ErrInvalidSignature, err)
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("%w: signature: %v", ErrInvalidSignature, err)
	}

	d, err := s.repo.Get(ctx, address)
	if err != nil {
		return err
	}
	if timestamp <= d.LastRevocationTimestamp {
		return fmt.Errorf("%w: timestamp was already used", ErrInvalidSignature)
	}
	if !isExitKey(d.Tapscripts, pubKey) {
		return fmt.Errorf("%w: not a key of the exit leaf", ErrInvalidSignature)
	}
	if !sig.Verify(RevocationHash(address, timestamp), pubKey) {
		return ErrInvalidSignature
	}
	if err := s.repo.Revoke(ctx, address, timestamp); err != nil {
		if errors.Is(err, domain.ErrRevocationAlreadyUsed) {
			return fmt.Errorf("%w: timestamp was already used", ErrInvalidSignature)
		}
		return err
	}
	log.WithField("address", address).Info("delegation revoked by its owner")
	return nil
}

// parseXOnly accepts a 32-byte x-only or a 33-byte compressed key.
func parseXOnly(pubKeyHex string) (*btcec.PublicKey, error) {
	raw, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return nil, err
	}
	if len(raw) == 32 {
		return schnorr.ParsePubKey(raw)
	}
	return btcec.ParsePubKey(raw)
}

// isExitKey reports whether pubKey (by x coordinate) signs one of the exit
// closures of the vtxo script.
func isExitKey(tapscripts []string, pubKey *btcec.PublicKey) bool {
	vtxoScript, err := script.ParseVtxoScript(tapscripts)
	if err != nil {
		return false
	}
	x := schnorr.SerializePubKey(pubKey)
	for _, closure := range vtxoScript.ExitClosures() {
		var keys []*btcec.PublicKey
		switch c := closure.(type) {
		case *script.CSVMultisigClosure:
			keys = c.PubKeys
		case *script.CLTVMultisigClosure:
			keys = c.PubKeys
		case *script.ConditionCSVMultisigClosure:
			keys = c.PubKeys
		case *script.MultisigClosure:
			keys = c.PubKeys
		}
		for _, k := range keys {
			if string(schnorr.SerializePubKey(k)) == string(x) {
				return true
			}
		}
	}
	return false
}

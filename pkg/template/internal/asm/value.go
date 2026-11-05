package asm

import (
	"fmt"
	"regexp"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
)

// MaxScriptNum bounds the magnitude of an int value.
const MaxScriptNum = 1<<53 - 1

// ScalarTypes are the types a variable, a constructor field or a witness item can have.
var ScalarTypes = []string{"pubkey", "bytes", "bytes20", "bytes32", "asset", "int", "bool"}

var (
	// DecimalTok matches a decimal token without leading zeros.
	DecimalTok = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
	// HexTok matches a 0x-prefixed lowercase hex push.
	HexTok = regexp.MustCompile(`^0x([0-9a-f]{2})+$`)
	// Placeholder matches a <name> token.
	Placeholder = regexp.MustCompile(`^<([^<>]+)>$`)
)

// CanonicalBytes requires raw to be the canonical encoding of typ.
func CanonicalBytes(typ string, raw []byte) error {
	var err error
	switch typ {
	case "pubkey":
		if _, e := btcec.ParsePubKey(raw); len(raw) != 33 || e != nil {
			err = fmt.Errorf("pubkey must be a valid 33-byte key")
		}
	case "bytes":
		if len(raw) > maxPushSize {
			err = fmt.Errorf("bytes longer than %d", maxPushSize)
		}
	case "bytes20":
		if len(raw) != 20 {
			err = fmt.Errorf("bytes20 must be 20 bytes")
		}
	case "bytes32", "asset":
		if len(raw) != 32 {
			err = fmt.Errorf("%s must be 32 bytes", typ)
		}
	case "int":
		_, err = ParseScriptNum(raw)
	case "bool":
		if len(raw) > 1 || (len(raw) == 1 && raw[0] != 1) {
			err = fmt.Errorf("bool must be empty or 01")
		}
	default:
		err = fmt.Errorf("unknown type %q", typ)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadValue, err)
	}
	return nil
}

// ScriptNum encodes n as a minimal Script number.
func ScriptNum(n int64) []byte {
	b, _ := arkade.BigNumFromInt64(n).Bytes()
	return b
}

// ParseScriptNum decodes a minimal Script number with magnitude up to 2^53-1.
func ParseScriptNum(b []byte) (int64, error) {
	n, err := arkade.MakeScriptNum(b, true, 8)
	if err != nil || n > MaxScriptNum || n < -MaxScriptNum {
		return 0, fmt.Errorf("%w: bad number of %d bytes", ErrBadValue, len(b))
	}
	return int64(n), nil
}

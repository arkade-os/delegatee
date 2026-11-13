package model

import (
	"time"

	"github.com/arkade-os/arkd/pkg/ark-lib/arkfee"
	"github.com/arkade-os/executor/pkg/template/internal/contract"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

type Type string

const (
	// Proof is an Ark intent proof: a message input, then the template inputs.
	Proof Type = "proof"
	// Virtual is an Ark transaction spending virtual outputs.
	Virtual Type = "virtual"
	Onchain Type = "onchain"
)

// Schedule is when an input becomes eligible; the zero value is immediately.
type Schedule struct {
	BeforeExpiry     time.Duration // offchain
	MinConfirmations int           // onchain
}

type Slot struct {
	Name     string
	Onchain  bool
	Schedule Schedule
}

// Keys are the service keys a contract is resolved under; Cosigner is the daemon's cosigner.
type Keys = contract.Keys

type Context struct {
	Keys      Keys
	Variables map[string][]byte
	// Decrypt opens sealed variables: with it their values are ciphertexts, without it plaintexts.
	// It is called concurrently and its errors must not contain plaintext.
	Decrypt func(ciphertext []byte) ([]byte, error)
	// Sources are the outputs to spend, one per input; nil asks for a watch, built from the
	// variables alone.
	Sources []*Source
}

type Asset struct {
	ID     []byte // 34 bytes
	Amount uint64
}

type Source struct {
	Outpoint  wire.OutPoint
	Tx        *wire.MsgTx // the transaction that created Outpoint
	Amount    uint64
	Assets    []Asset
	Expiry    time.Time // offchain: when the virtual output expires
	Confirms  int       // onchain: confirmations of Tx
	CreatedAt time.Time
	Swept     bool // offchain: swept by the server, hence recoverable
}

type Fee struct {
	Intent  arkfee.Config          // the Ark server's fee programs, for intents
	Onchain func(vsize int) uint64 // the fee of an onchain transaction of vsize virtual bytes
	Dust    uint64                 // minimum output amount
}

type Action struct {
	Tx        *psbt.Packet
	Extension int // output index of the extension, -1 without
	Fee       uint64
}

// TriggerKeys are the daemon keys a trigger may require, compared compressed.
type TriggerKeys struct {
	Encryption *btcec.PublicKey
	Keys
}

// Capture is a candidate output of a matched transaction and the variables captured for it, in hex.
type Capture struct {
	Output    int
	Group     string // the rule's group bytes in hex, "" without a group
	Variables map[string]string
}

type Bindings struct {
	Keys      Keys
	Variables map[string][]byte
}

// Runtime supplies external operations. Decrypt must be safe for concurrent calls.
type Runtime struct{ Decrypt func([]byte) ([]byte, error) }

// BuildRequest is the complete context of one spend. Sources must not be mutated during a call.
type BuildRequest struct {
	Sources []*Source
	Fee     Fee
	Runtime Runtime
}

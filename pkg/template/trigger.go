package template

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/arkade-os/executor/pkg/template/internal/contract"
	"github.com/arkade-os/executor/pkg/template/packets"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// TriggerKeys are the daemon keys a trigger may require, compared compressed.
type TriggerKeys struct {
	Encryption *btcec.PublicKey
	Keys
}

// Capture is a candidate output of a matched transaction and the variables captured for it, in hex.
type Capture struct {
	Output    int
	Variables map[string]string
}

// Trigger selects streamed transactions by an extension packet and captures variables from them.
type Trigger struct {
	packet   uint8
	raw      bool // the body is one source, else tlv records
	require  []requirement
	captures []captureRule // sorted by variable
	ttl      time.Duration
	minValue int64
}

type requirement struct {
	source string
	key    string // a daemon key name; "" compares lit
	lit    []byte
}

type captureRule struct {
	variable, typ string
	source        string
	asm           []string // nil captures the source bytes
}

const outputTaptree = "output:taptree"

var daemonKeys = map[string]func(TriggerKeys) *btcec.PublicKey{
	"ENCRYPTION_KEY": func(k TriggerKeys) *btcec.PublicKey { return k.Encryption },
	"SERVER_KEY":     func(k TriggerKeys) *btcec.PublicKey { return k.Server },
	"EMULATOR_KEY":   func(k TriggerKeys) *btcec.PublicKey { return k.Emulator },
	"COSIGNER_KEY":   func(k TriggerKeys) *btcec.PublicKey { return k.Cosigner },
}

// Trigger is nil unless the template reacts to streamed transactions.
func (t *Template) Trigger() *Trigger { return t.trigger }

// TTL is how long a watch the trigger spawns lives.
func (tr *Trigger) TTL() time.Duration { return tr.ttl }

// Captured lists the variables the trigger captures, sorted.
func (tr *Trigger) Captured() []string {
	out := make([]string, len(tr.captures))
	for i, c := range tr.captures {
		out[i] = c.variable
	}
	return out
}

func (c *compiler) trigger() error {
	s := c.doc.Trigger
	if s == nil {
		return nil
	}
	if len(c.t.inputs) != 1 || c.t.inputs[0].onchain {
		return bad("a trigger template has one offchain input")
	}
	if !c.t.ContextFree() {
		return bad("a trigger template is watched: its contract must not depend on a source")
	}
	tr := &Trigger{packet: uint8(s.Packet), raw: s.Decode == "raw", ttl: time.Duration(s.ExpiresAfter) * time.Second, minValue: s.MinValue}
	for _, src := range slices.Sorted(maps.Keys(s.Require)) {
		if err := tr.checkSource(src, false); err != nil {
			return err
		}
		lit := s.Require[src]
		r := requirement{source: src}
		key := asm.Placeholder.FindStringSubmatch(lit)
		switch {
		case key != nil && daemonKeys[key[1]] != nil:
			r.key = key[1]
		case asm.HexTok.MatchString(lit):
			r.lit, _ = hex.DecodeString(lit[2:])
		default:
			return bad("trigger require %q: want a 0x literal or a daemon key, got %q", src, lit)
		}
		tr.require = append(tr.require, r)
	}
	for _, name := range slices.Sorted(maps.Keys(s.Capture)) {
		typ, ok := c.t.variables[name]
		if !ok {
			return bad("trigger captures undeclared variable %q", name)
		}
		b := s.Capture[name]
		cp := captureRule{variable: name, typ: typ, source: b.Source}
		if b.Asm != nil {
			cp.source = b.From
			var err error
			if cp.asm, err = capturePattern(b.Asm, name); err != nil {
				return err
			}
			if typ == "bool" || typ == "int" {
				return bad("trigger capture of %q: a %s is not captured from a data push", name, typ)
			}
		}
		if err := tr.checkSource(cp.source, cp.asm == nil); err != nil {
			return err
		}
		if cp.source == outputTaptree && typ != "bytes" {
			return bad("trigger captures a taptree into %s variable %q", typ, name)
		}
		tr.captures = append(tr.captures, cp)
	}
	c.t.trigger = tr
	return nil
}

// checkSource: a source fits the decoding; only a plain capture reads an output.
func (tr *Trigger) checkSource(src string, output bool) error {
	switch {
	case src == outputTaptree && output, src == "raw" && tr.raw:
		return nil
	case strings.HasPrefix(src, "tlv:") && !tr.raw:
		if n, err := strconv.Atoi(src[4:]); err == nil && n >= 0 && n <= math.MaxUint8 && strconv.Itoa(n) == src[4:] {
			return nil
		}
	}
	return bad("trigger source %q does not fit this trigger", src)
}

func noNames(string) (asm.Value, error) {
	return asm.Value{}, errors.New("a pattern names only its own variable")
}

// capturePattern checks a pattern assembles token by token and names its variable exactly once.
func capturePattern(toks []string, name string) ([]string, error) {
	seen := 0
	for _, s := range toks {
		if s == "<"+name+">" {
			seen++
			continue
		}
		if _, err := asm.Assemble([]string{s}, noNames); err != nil {
			return nil, bad("trigger capture of %q: %v", name, err)
		}
	}
	if seen != 1 {
		return nil, bad("trigger capture of %q names it %d times", name, seen)
	}
	return slices.Clone(toks), nil
}

// Match returns a capture per output of tx that may be the coin; the caller checks the template locks it.
func (tr *Trigger) Match(tx *psbt.Packet, keys TriggerKeys) ([]Capture, error) {
	body, ok := packets.Find(tx.UnsignedTx, tr.packet)
	if !ok {
		return nil, fmt.Errorf("%w: no packet %d", ErrNoMatch, tr.packet)
	}
	fields := map[string][]byte{"raw": body}
	if !tr.raw {
		var err error
		if fields, err = decodeTLV(body); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoMatch, err)
		}
	}
	for _, r := range tr.require {
		got, ok := fields[r.source]
		if want := r.value(keys); !ok || want == nil || !bytes.Equal(want, got) {
			return nil, fmt.Errorf("%w: %s", ErrNoMatch, r.source)
		}
	}
	vars := map[string]string{}
	var tree string
	for _, c := range tr.captures {
		if c.source == outputTaptree {
			tree = c.variable
			continue
		}
		got, ok := fields[c.source]
		if !ok {
			return nil, fmt.Errorf("%w: no %s", ErrNoMatch, c.source)
		}
		var err error
		if c.asm != nil {
			got, err = capturePush(got, c.asm, c.variable)
		}
		if err == nil {
			err = asm.CanonicalBytes(c.typ, got)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrNoMatch, c.variable, err)
		}
		vars[c.variable] = hex.EncodeToString(got)
	}
	var out []Capture
	for i, o := range tx.UnsignedTx.TxOut {
		if o.Value < tr.minValue {
			continue
		}
		v := maps.Clone(vars)
		if tree != "" {
			if i >= len(tx.Outputs) {
				continue
			}
			raw := tx.Outputs[i].TaprootTapTree
			if len(raw) == 0 {
				continue
			}
			if s, err := contract.TaptreeScript(raw); err != nil || !bytes.Equal(s, o.PkScript) {
				continue
			}
			v[tree] = hex.EncodeToString(raw)
		}
		out = append(out, Capture{Output: i, Variables: v})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no candidate output", ErrNoMatch)
	}
	return out, nil
}

// value is what r requires: its literal, or the daemon key compressed, nil without that key.
func (r requirement) value(k TriggerKeys) []byte {
	if r.key == "" {
		return r.lit
	}
	if pk := daemonKeys[r.key](k); pk != nil {
		return pk.SerializeCompressed()
	}
	return nil
}

// decodeTLV reads tag[1] || length[2, big-endian] || value records; a repeated tag keeps the last value.
func decodeTLV(body []byte) (map[string][]byte, error) {
	out := map[string][]byte{}
	for len(body) > 0 {
		if len(body) < 3 {
			return nil, errors.New("truncated record header")
		}
		n := int(binary.BigEndian.Uint16(body[1:3]))
		if len(body) < 3+n {
			return nil, fmt.Errorf("record %d wants %d bytes, %d left", body[0], n, len(body)-3)
		}
		out["tlv:"+strconv.Itoa(int(body[0]))] = body[3 : 3+n]
		body = body[3+n:]
	}
	return out, nil
}

// capturePush matches script against pattern token by token and returns the minimal push at the variable.
// A one-byte value 0x00..0x10 or 0x81 is never a data push, so it is not captured.
func capturePush(script []byte, pattern []string, name string) ([]byte, error) {
	tok := txscript.MakeScriptTokenizer(0, script)
	var captured []byte
	for _, p := range pattern {
		start := tok.ByteIndex()
		if !tok.Next() {
			if err := tok.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("script ends before %s", p)
		}
		got := script[start:tok.ByteIndex()]
		if p == "<"+name+">" {
			minimal, err := txscript.NewScriptBuilder().AddData(tok.Data()).Script()
			if op := tok.Opcode(); err != nil || op < txscript.OP_DATA_1 || op > txscript.OP_PUSHDATA4 || !bytes.Equal(got, minimal) {
				return nil, fmt.Errorf("%s is not a minimal data push", p)
			}
			captured = tok.Data()
			continue
		}
		want, _ := asm.Assemble([]string{p}, noNames) // checked when parsed
		if !bytes.Equal(got, want) {
			return nil, fmt.Errorf("token %s differs", p)
		}
	}
	if tok.Next() {
		return nil, errors.New("script has trailing bytes")
	}
	if err := tok.Err(); err != nil {
		return nil, err
	}
	return bytes.Clone(captured), nil
}

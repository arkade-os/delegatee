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

	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

var ErrNoMatch = errors.New("transaction does not match the trigger")

// TriggerKeys are the daemon keys a trigger may require, compared compressed.
type TriggerKeys struct {
	Encryption []*btcec.PublicKey
	Keys
}

// Binding is a candidate output of a matched transaction and the variables bound for it, in hex.
type Binding struct {
	Output    int
	Variables map[string]string
}

// Trigger selects streamed transactions by an extension packet and binds variables from them.
type Trigger struct {
	packet   uint8
	raw      bool // the body is one source, else tlv records
	require  []requirement
	binds    []capture // sorted by variable
	ttl      time.Duration
	minValue int64
}

type requirement struct {
	source string
	key    string // a daemon key name; "" compares lit
	lit    []byte
}

type capture struct {
	variable, typ string
	source        string
	asm           []string // nil binds the source bytes
}

const outputTaptree = "output:taptree"

var daemonKeys = map[string]func(TriggerKeys) []*btcec.PublicKey{
	"ENCRYPTION_KEY": func(k TriggerKeys) []*btcec.PublicKey { return k.Encryption },
	"SERVER_KEY":     func(k TriggerKeys) []*btcec.PublicKey { return []*btcec.PublicKey{k.Server} },
	"EMULATOR_KEY":   func(k TriggerKeys) []*btcec.PublicKey { return []*btcec.PublicKey{k.Emulator} },
	"DELEGATE_KEY":   func(k TriggerKeys) []*btcec.PublicKey { return []*btcec.PublicKey{k.Delegate} },
}

// Trigger is nil unless the template reacts to streamed transactions.
func (t *Template) Trigger() *Trigger { return t.trigger }

// TTL is how long a watch the trigger spawns lives.
func (tr *Trigger) TTL() time.Duration { return tr.ttl }

// Bound lists the variables the trigger binds, sorted.
func (tr *Trigger) Bound() []string {
	out := make([]string, len(tr.binds))
	for i, c := range tr.binds {
		out[i] = c.variable
	}
	return out
}

func (p *parser) trigger(m map[string]any) error {
	raw, ok := m["trigger"]
	if !ok {
		return nil
	}
	tm, err := object(ErrInvalidTemplate, raw, "trigger", []string{"packet", "decode", "bind", "expires_after_seconds"}, "require", "min_value")
	if err != nil {
		return err
	}
	if len(p.t.inputs) != 1 || p.t.inputs[0].onchain {
		return bad("a trigger template has one offchain input")
	}
	if !p.t.ContextFree() {
		return bad("a trigger template is watched: its contract must not depend on a source")
	}
	pkt, err := integer(tm["packet"], "trigger packet", 0, math.MaxUint8)
	if err != nil {
		return err
	}
	tr := &Trigger{packet: uint8(pkt)}
	switch tm["decode"] {
	case "raw":
		tr.raw = true
	case "tlv":
	default:
		return bad("trigger decode must be tlv or raw")
	}
	ttl, err := integer(tm["expires_after_seconds"], "expires_after_seconds", 1, math.MaxInt32)
	if err != nil {
		return err
	}
	tr.ttl = time.Duration(ttl) * time.Second
	if raw, ok := tm["min_value"]; ok {
		if tr.minValue, err = integer(raw, "trigger min_value", 0, maxScriptNum); err != nil {
			return err
		}
		if tr.minValue == 0 {
			delete(tm, "min_value")
		}
	}
	req, err := dict(tm, "require")
	if err != nil {
		return err
	}
	for _, src := range slices.Sorted(maps.Keys(req)) {
		if err := tr.checkSource(src, false); err != nil {
			return err
		}
		s, _ := req[src].(string)
		r := requirement{source: src}
		key := placeholder.FindStringSubmatch(s)
		switch {
		case key != nil && daemonKeys[key[1]] != nil:
			r.key = key[1]
		case hexTok.MatchString(s):
			r.lit, _ = hex.DecodeString(s[2:])
		default:
			return bad("trigger require %q: want a 0x literal or a daemon key, got %v", src, req[src])
		}
		tr.require = append(tr.require, r)
	}
	binds, err := dict(tm, "bind")
	if err != nil {
		return err
	}
	if len(binds) == 0 {
		return bad("a trigger binds at least one variable")
	}
	for _, name := range slices.Sorted(maps.Keys(binds)) {
		typ, ok := p.t.variables[name]
		if !ok {
			return bad("trigger binds undeclared variable %q", name)
		}
		c := capture{variable: name, typ: typ}
		switch b := binds[name].(type) {
		case string:
			c.source = b
		case map[string]any:
			bm, err := object(ErrInvalidTemplate, b, "trigger capture", []string{"from", "asm"})
			if err != nil {
				return err
			}
			c.source, _ = bm["from"].(string)
			if c.asm, err = capturePattern(bm["asm"], name); err != nil {
				return err
			}
		default:
			return bad("trigger bind %q is neither a source nor a capture", name)
		}
		if c.asm != nil && (typ == "bool" || typ == "int") {
			return bad("trigger capture of %q: a %s is not captured from a data push", name, typ)
		}
		if err := tr.checkSource(c.source, c.asm == nil); err != nil {
			return err
		}
		if c.source == outputTaptree && typ != "bytes" {
			return bad("trigger binds a taptree to %s variable %q", typ, name)
		}
		tr.binds = append(tr.binds, c)
	}
	p.t.trigger = tr
	return nil
}

// checkSource: a source fits the decoding; only a plain bind reads an output.
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

func noNames(string) (value, error) {
	return value{}, errors.New("a pattern names only its own variable")
}

func capturePattern(v any, name string) ([]string, error) {
	l, ok := v.([]any)
	if !ok || len(l) == 0 {
		return nil, bad("trigger capture of %q needs an asm token list", name)
	}
	toks := make([]string, len(l))
	seen := 0
	for i, x := range l {
		s, _ := x.(string)
		toks[i] = s
		if s == "<"+name+">" {
			seen++
			continue
		}
		if _, err := assemble([]string{s}, noNames); err != nil {
			return nil, bad("trigger capture of %q: %v", name, err)
		}
	}
	if seen != 1 {
		return nil, bad("trigger capture of %q names it %d times", name, seen)
	}
	return toks, nil
}

// Match returns a binding per output of tx that may be the coin; the caller checks the template locks it.
func (tr *Trigger) Match(tx *psbt.Packet, keys TriggerKeys) ([]Binding, error) {
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
		if !ok || !slices.ContainsFunc(r.values(keys), func(w []byte) bool { return bytes.Equal(w, got) }) {
			return nil, fmt.Errorf("%w: %s", ErrNoMatch, r.source)
		}
	}
	vars := map[string]string{}
	var tree string
	for _, c := range tr.binds {
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
			err = canonicalBytes(c.typ, got)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrNoMatch, c.variable, err)
		}
		vars[c.variable] = hex.EncodeToString(got)
	}
	var out []Binding
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
			if s, err := taptreeScript(raw); err != nil || !bytes.Equal(s, o.PkScript) {
				continue
			}
			v[tree] = hex.EncodeToString(raw)
		}
		out = append(out, Binding{Output: i, Variables: v})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no candidate output", ErrNoMatch)
	}
	return out, nil
}

func (r requirement) values(k TriggerKeys) [][]byte {
	if r.key == "" {
		return [][]byte{r.lit}
	}
	var out [][]byte
	for _, pk := range daemonKeys[r.key](k) {
		if pk != nil {
			out = append(out, pk.SerializeCompressed())
		}
	}
	return out
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
		want, _ := assemble([]string{p}, noNames) // checked when parsed
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

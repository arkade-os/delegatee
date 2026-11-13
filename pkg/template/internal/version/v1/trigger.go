package v1

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

	"github.com/arkade-os/executor/pkg/template/internal/model"

	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/arkade-os/executor/pkg/template/internal/contract"
	"github.com/arkade-os/executor/pkg/template/packets"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
)

type TriggerKeys = model.TriggerKeys
type Capture = model.Capture

type Trigger struct {
	tmpl     *Template
	input    int
	packet   uint8
	raw      bool // the body is one source, else tlv records
	minValue int64
	require  []requirement // sorted by source
	captures []captureRule // sorted by variable
	group    string        // a source, "" with a single rule
	ttl      time.Duration
}

// requirement is what one source must hold; exactly one of key, lit, variable and expr is set.
type requirement struct {
	source   string
	key      string
	lit      []byte
	variable string
	expr     []string
}

type captureRule struct {
	variable, typ string
	source        string   // a source or output:taptree; "" with expr
	expr          []string // over the rule's sources only
}

const outputTaptree = "output:taptree"

var serviceKeys = map[string]func(TriggerKeys) *btcec.PublicKey{
	"ENCRYPTION_KEY": func(k TriggerKeys) *btcec.PublicKey { return k.Encryption },
	"SERVER_KEY":     func(k TriggerKeys) *btcec.PublicKey { return k.Server },
	"EMULATOR_KEY":   func(k TriggerKeys) *btcec.PublicKey { return k.Emulator },
	"COSIGNER_KEY":   func(k TriggerKeys) *btcec.PublicKey { return k.Cosigner },
}

type valueOf func(name string) (asm.Value, bool, error)

func (t *Template) Triggers() []*Trigger { return slices.Clone(t.triggers) }
func (tr *Trigger) Input() int           { return tr.input }
func (tr *Trigger) TTL() time.Duration   { return tr.ttl }

func (tr *Trigger) Captured() []string {
	out := make([]string, len(tr.captures))
	for i, c := range tr.captures {
		out[i] = c.variable
	}
	return out
}

// Match returns a capture per output of tx that may be the input's coin, with the variables the
// rule captures in hex; the caller checks that the template locks it. given holds the variables
// given at stream registration; decrypt opens a sealed variable that a requirement reads, which
// stands for its plaintext. A requirement naming a variable another rule captures is not checked
// here: it holds only once a group is complete.
func (tr *Trigger) Match(
	tx *psbt.Packet, keys TriggerKeys, given map[string][]byte,
	decrypt func([]byte) ([]byte, error),
) ([]Capture, error) {
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
	vars := map[string][]byte{}
	var tree string
	for _, c := range tr.captures {
		if c.source == outputTaptree {
			tree = c.variable
			continue
		}
		got, err := tr.captured(c, fields)
		if err == nil {
			err = asm.CanonicalBytes(c.typ, got)
			if tr.tmpl.sealed[c.variable] {
				err = nil // a ciphertext; its plaintext is checked when it is opened
			}
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrNoMatch, c.variable, err)
		}
		vars[c.variable] = got
	}
	known := map[string][]byte{}
	maps.Copy(known, given)
	maps.Copy(known, vars)
	value := func(name string) (asm.Value, bool, error) {
		raw, ok := known[name]
		if !ok {
			return asm.Value{}, false, nil
		}
		if tr.tmpl.sealed[name] {
			if decrypt == nil {
				return asm.Value{}, false, errors.New("no decryption for a sealed variable")
			}
			p, err := decrypt(raw)
			if err != nil {
				return asm.Value{}, false, fmt.Errorf("sealed %q: %v", name, err)
			}
			raw = p
		}
		return asm.Value{Type: tr.tmpl.variables[name], Raw: raw}, true, nil
	}
	for _, r := range tr.require {
		if err := r.check(tr, fields, keys, value); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrNoMatch, r.source, err)
		}
	}
	var group string
	if tr.group != "" {
		g, ok := fields[tr.group]
		if !ok {
			return nil, fmt.Errorf("%w: no %s", ErrNoMatch, tr.group)
		}
		group = hex.EncodeToString(g)
	}
	var out []Capture
	for i, o := range tx.UnsignedTx.TxOut {
		if o.Value < tr.minValue {
			continue
		}
		v := map[string]string{}
		for n, raw := range vars {
			v[n] = hex.EncodeToString(raw)
		}
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
		out = append(out, Capture{Output: i, Group: group, Variables: v})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: no candidate output", ErrNoMatch)
	}
	return out, nil
}

func (c *compiler) triggers() error {
	if c.doc.Delegation == nil || len(c.doc.Delegation.Trigger) == 0 {
		return nil
	}
	rules := c.doc.Delegation.Trigger
	if !c.t.ContextFree() {
		return bad("a trigger template is watched: its contract arguments must be context-free")
	}
	captured := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(rules)) {
		for v := range rules[name].Capture {
			if captured[v] {
				return bad("variable %q is captured twice", v)
			}
			captured[v] = true
		}
	}
	for _, name := range slices.Sorted(maps.Keys(rules)) {
		s := rules[name]
		slot, err := c.inputIndex(name, "trigger")
		if err != nil {
			return err
		}
		if c.t.inputs[slot].onchain {
			return bad("trigger of %q: a triggered input is offchain", name)
		}
		tr := &Trigger{
			tmpl: c.t, input: slot, packet: uint8(s.Packet), raw: s.Decode == "raw",
			minValue: s.MinValue, group: s.Group, ttl: time.Duration(s.ExpiresAfter) * time.Second,
		}
		if tr.group != "" && !tr.isSource(tr.group) {
			return bad("trigger of %q: group %q does not fit the rule", name, tr.group)
		}
		fixed := false
		for _, src := range slices.Sorted(maps.Keys(s.Require)) {
			r, err := c.requirement(tr, src, s.Require[src])
			if err != nil {
				return fmt.Errorf("trigger of %q: %w", name, err)
			}
			fixed = fixed || r.key != "" || r.lit != nil ||
				r.variable != "" && !captured[r.variable]
			tr.require = append(tr.require, r)
		}
		if !fixed {
			return bad("trigger of %q: no requirement is fixed before a transaction arrives", name)
		}
		for _, v := range slices.Sorted(maps.Keys(s.Capture)) {
			cp, err := c.capture(tr, v, s.Capture[v])
			if err != nil {
				return fmt.Errorf("trigger of %q: %w", name, err)
			}
			tr.captures = append(tr.captures, cp)
		}
		c.t.triggers = append(c.t.triggers, tr)
	}
	slices.SortFunc(c.t.triggers, func(a, b *Trigger) int { return a.input - b.input })
	return nil
}

func (c *compiler) requirement(tr *Trigger, src, value string) (requirement, error) {
	if !tr.isSource(src) {
		return requirement{}, bad("source %q does not fit the rule", src)
	}
	r := requirement{source: src}
	m := asm.Placeholder.FindStringSubmatch(value)
	switch {
	case asm.HexTok.MatchString(value):
		r.lit, _ = hex.DecodeString(value[2:])
	case m != nil && serviceKeys[m[1]] != nil:
		r.key = m[1]
	case m != nil:
		if _, ok := c.t.variables[m[1]]; !ok {
			return r, bad("require %q names undeclared variable %q", src, m[1])
		}
		r.variable = m[1]
	default:
		expr, err := c.triggerExpr(tr, value, true)
		if err != nil {
			return r, fmt.Errorf("require %q: %w", src, err)
		}
		r.expr = expr
	}
	return r, nil
}

func (c *compiler) capture(tr *Trigger, v, value string) (captureRule, error) {
	typ, ok := c.t.variables[v]
	if !ok {
		return captureRule{}, bad("captures undeclared variable %q", v)
	}
	cp := captureRule{variable: v, typ: typ}
	switch {
	case value == outputTaptree:
		if typ != "bytes" {
			return cp, bad("captures a taptree into %s variable %q", typ, v)
		}
		cp.source = value
	case tr.isSource(value):
		cp.source = value
	default:
		expr, err := c.triggerExpr(tr, value, false)
		if err != nil {
			return cp, fmt.Errorf("capture of %q: %w", v, err)
		}
		cp.expr = expr
	}
	return cp, nil
}

func (c *compiler) triggerExpr(tr *Trigger, value string, variables bool) ([]string, error) {
	body, ok := strings.CutPrefix(value, "$(")
	body, closed := strings.CutSuffix(body, ")")
	if !ok || !closed || body == "" || strings.ContainsAny(body, "$()") ||
		strings.HasPrefix(
			body, " ",
		) || strings.HasSuffix(body, " ") || strings.Contains(body, "  ") {
		return nil, bad("%q is not a literal, a key, a variable, a source or an expression", value)
	}
	expr := strings.Split(body, " ")
	for _, tok := range expr {
		if !strings.HasPrefix(tok, "<") {
			continue
		}
		if !strings.HasSuffix(tok, ">") {
			return nil, bad("bad placeholder %q", tok)
		}
		if tr.isSource(tok[1 : len(tok)-1]) {
			continue
		}
		if !variables {
			return nil, bad("a capture expression names no variable: %s", tok)
		}
		if _, ok := c.t.variables[tokenName(tok)]; !ok {
			return nil, bad("undeclared name %q", tokenName(tok))
		}
	}
	if err := c.checkExpression(expr); err != nil {
		return nil, err
	}
	if !asm.ContextFree(expr) {
		return nil, bad("trigger expression %q is not context-free", value)
	}
	return expr, nil
}

func (tr *Trigger) isSource(src string) bool {
	if tr.raw {
		return src == "raw"
	}
	n, ok := strings.CutPrefix(src, "tlv:")
	i, err := strconv.Atoi(n)
	return ok && err == nil && i >= 0 && i <= math.MaxUint8 && strconv.Itoa(i) == n
}

func (tr *Trigger) captured(c captureRule, fields map[string][]byte) ([]byte, error) {
	if c.expr == nil {
		got, ok := fields[c.source]
		if !ok {
			return nil, fmt.Errorf("no %s", c.source)
		}
		return got, nil
	}
	return evalFree(c.expr, func(n string) (asm.Value, error) {
		if raw, ok := fields[n]; ok {
			return asm.Value{Type: "bytes", Raw: raw}, nil
		}
		return asm.Value{}, fmt.Errorf("no %s", n)
	})
}

func (r requirement) check(
	tr *Trigger, fields map[string][]byte, keys TriggerKeys, value valueOf,
) error {
	got, present := fields[r.source]
	if !present {
		return errors.New("absent")
	}
	var want []byte
	switch {
	case r.key != "":
		pk := serviceKeys[r.key](keys)
		if pk == nil {
			return fmt.Errorf("no %s", r.key)
		}
		want = pk.SerializeCompressed()
	case r.lit != nil:
		want = r.lit
	case r.variable != "":
		v, ok, err := value(r.variable)
		if err != nil || !ok {
			return err // not known yet: deferred to the complete group
		}
		want = v.Raw
	default:
		vals := map[string]asm.Value{}
		for _, tok := range r.expr {
			if !strings.HasPrefix(tok, "<") {
				continue
			}
			if n := tok[1 : len(tok)-1]; tr.isSource(n) {
				raw, ok := fields[n]
				if !ok {
					return fmt.Errorf("no %s", n)
				}
				vals[n] = asm.Value{Type: "bytes", Raw: raw}
				continue
			}
			v, ok, err := value(tokenName(tok))
			if err != nil || !ok {
				return err // not known yet: deferred to the complete group
			}
			vals[tokenName(tok)] = v
		}
		res, err := evalFree(r.expr, func(n string) (asm.Value, error) { return vals[n], nil })
		if err != nil {
			return err
		}
		want, got = []byte{1}, res
	}
	if !bytes.Equal(want, got) {
		return errors.New("differs")
	}
	return nil
}

func evalFree(tokens []string, lookup asm.Lookup) ([]byte, error) {
	d := newDraft(Virtual, []*Source{{}})
	d.contextFree = true
	return d.eval(tokens, 0, lookup)
}

// decodeTLV reads tag[1] || length[2, big-endian] || value records; a repeated tag keeps the last
// value.
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

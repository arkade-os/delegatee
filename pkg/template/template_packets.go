package template

import (
	"encoding/hex"
	"math"
	"slices"

	"github.com/arkade-os/delegatee/pkg/template/packets"
)

func (p *parser) packets(m map[string]any) error {
	if m["packets"] == nil {
		delete(m, "packets")
		for _, in := range p.t.inputs {
			if f, _ := in.contract.def.function(in.function); f.Arkade != nil {
				return bad("input %q runs a covenant and needs packets", in.name)
			}
		}
		return nil
	}
	pm, err := object(ErrInvalidTemplate, m["packets"], "packets", []string{"output_index"}, "unmatched", "rules", "advertise")
	if err != nil {
		return err
	}
	idx, err := integer(pm["output_index"], "output_index", 0, math.MaxUint16)
	if err != nil {
		return err
	}
	ps := &packetSpec{index: uint16(idx)}
	if raw, ok := pm["unmatched"]; ok {
		switch raw {
		case "reject":
			delete(pm, "unmatched")
		case "drop":
			ps.drop = true
		default:
			return bad("unmatched must be reject or drop")
		}
	}
	rules, err := list(pm, "rules")
	if err != nil {
		return err
	}
	if len(rules) > maxSlots {
		return bad("more than %d packet rules", maxSlots)
	}
	for _, r := range rules {
		x, err := p.rule(r)
		if err != nil {
			return err
		}
		for _, o := range ps.rules {
			if o.typ != x.typ {
				continue
			}
			if o.action == "emit" && x.action == "emit" {
				return bad("two emit rules for packet type %d", x.typ)
			}
			// the extension holds one packet per type: a copy combines only with an identical copy or a drop
			c, other := o, x
			if other.action == "copy" {
				c, other = other, c
			}
			if c.action == "copy" && (other.action == "emit" ||
				other.action == "copy" && other.from != c.from ||
				other.action == "drop" && other.from == c.from) {
				return bad("copy conflicts with another rule for packet type %d", x.typ)
			}
		}
		ps.rules = append(ps.rules, x)
	}
	ads, err := list(pm, "advertise")
	if err != nil {
		return err
	}
	if len(ads) > maxSlots {
		return bad("more than %d advertisements", maxSlots)
	}
	for _, a := range ads {
		ad, err := p.advert(a, ps.adverts)
		if err != nil {
			return err
		}
		ps.adverts = append(ps.adverts, ad)
	}
	if len(ps.adverts) > 0 {
		if _, err := packets.EncodeAdvertisement(ps.records(p.t, [32]byte{})); err != nil {
			return bad("%v", err)
		}
	}
	p.t.packets = ps
	return nil
}

// self stands for id
func (ps *packetSpec) records(t *Template, id [32]byte) []packets.Record {
	out := make([]packets.Record, 0, len(ps.adverts))
	for _, ad := range ps.adverts {
		r := packets.Record{Template: ad.target}
		if ad.self {
			r.Template = id
		}
		for _, k := range ad.outputs {
			r.Outputs = append(r.Outputs, t.outputs[k].index)
		}
		out = append(out, r)
	}
	return out
}

func (p *parser) rule(v any) (rule, error) {
	r := rule{}
	m, err := object(ErrInvalidTemplate, v, "rule", []string{"type", "action", "from"}, "data")
	if err != nil {
		return r, err
	}
	typ, err := integer(m["type"], "rule type", 2, math.MaxUint8)
	if err != nil {
		return r, err
	}
	if typ == 5 {
		return r, bad("packet type 5 is reserved")
	}
	r.typ = uint8(typ)
	r.action, _ = m["action"].(string)
	if !slices.Contains([]string{"copy", "drop", "emit"}, r.action) {
		return r, bad("unknown rule action %v", m["action"])
	}
	if r.from, err = p.inputIndex(m["from"], "rule"); err != nil {
		return r, err
	}
	raw, hasData := m["data"]
	if hasData != (r.action == "emit") {
		return r, bad("data goes with emit and only with emit")
	}
	if hasData {
		r.data, err = p.bind(raw, "", true)
	}
	return r, err
}

func (p *parser) advert(v any, prev []advert) (advert, error) {
	ad := advert{}
	m, err := object(ErrInvalidTemplate, v, "advertisement", []string{"template", "outputs"})
	if err != nil {
		return ad, err
	}
	switch target, _ := m["template"].(string); {
	case target == "self":
		ad.self = true
	case idHex.MatchString(target):
		_, _ = hex.Decode(ad.target[:], []byte(target))
	default:
		return ad, bad("bad advertisement target %v", m["template"])
	}
	outs, _ := m["outputs"].([]any)
	if len(outs) == 0 {
		return ad, bad("an advertisement needs outputs")
	}
	for _, o := range outs {
		i := slices.IndexFunc(p.t.outputs, func(x output) bool { return x.name == o })
		if i < 0 {
			return ad, bad("advertisement names no output: %v", o)
		}
		if slices.Contains(ad.outputs, i) || slices.ContainsFunc(prev, func(a advert) bool { return slices.Contains(a.outputs, i) }) {
			return ad, bad("output %q is advertised twice", p.t.outputs[i].name)
		}
		if p.t.typ == Intent && p.t.outputs[i].onchain {
			return ad, bad("an intent advertises only offchain outputs")
		}
		ad.outputs = append(ad.outputs, i)
	}
	if ad.self && len(ad.outputs) != len(p.t.inputs) {
		return ad, bad("advertising self takes one output per input")
	}
	for slot, i := range ad.outputs {
		if ad.self && p.t.outputs[i].onchain != p.t.inputs[slot].onchain {
			return ad, bad("output %q does not match the type of input slot %q", p.t.outputs[i].name, p.t.inputs[slot].name)
		}
	}
	if ad.self && len(p.t.variables) > 0 {
		return ad, bad("a template with variables cannot advertise itself")
	}
	return ad, nil
}

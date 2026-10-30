package template

import (
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/delegatee/pkg/template/internal/schema"
	"github.com/arkade-os/delegatee/pkg/template/packets"
	"github.com/arkade-os/emulator/pkg/arkade"
)

type rule struct {
	typ    uint8
	action string // copy | drop | emit
	from   int
	data   byteTemplate
}

type advert struct {
	self    bool
	target  [32]byte
	outputs []int // output positions in t.outputs, in the target's slot order
}

type packetSpec struct {
	index   uint16
	drop    bool // unmatched source packets are dropped, not rejected
	rules   []rule
	adverts []advert
}

func (c *compiler) packets() error {
	s := c.doc.Packets
	if s == nil {
		for _, in := range c.t.inputs {
			if f := in.contract.def.FindFunction(in.function); f.Arkade != nil {
				return bad("input %q runs a covenant and needs packets", in.name)
			}
		}
		return nil
	}
	ps := &packetSpec{index: uint16(s.OutputIndex), drop: s.Unmatched == "drop"}
	for i := range s.Rules {
		x, err := c.rule(&s.Rules[i])
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
			cp, other := o, x
			if other.action == "copy" {
				cp, other = other, cp
			}
			if cp.action == "copy" && (other.action == "emit" ||
				other.action == "copy" && other.from != cp.from ||
				other.action == "drop" && other.from == cp.from) {
				return bad("copy conflicts with another rule for packet type %d", x.typ)
			}
		}
		ps.rules = append(ps.rules, x)
	}
	for i := range s.Advertise {
		ad, err := c.advert(&s.Advertise[i], ps.adverts)
		if err != nil {
			return err
		}
		ps.adverts = append(ps.adverts, ad)
	}
	if len(ps.adverts) > 0 {
		if _, err := packets.EncodeAdvertisement(ps.records(c.t, [32]byte{})); err != nil {
			return bad("%v", err)
		}
	}
	c.t.packets = ps
	return nil
}

// records lists the advertisements, self standing for id.
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

func (c *compiler) rule(s *schema.Rule) (rule, error) {
	r := rule{typ: uint8(s.Type), action: s.Action}
	var err error
	if r.from, err = c.inputIndex(s.From, "rule"); err != nil {
		return r, err
	}
	if s.Data != nil {
		r.data, err = c.bind(*s.Data, "", true)
	}
	return r, err
}

func (c *compiler) advert(s *schema.Advert, prev []advert) (advert, error) {
	ad := advert{self: s.Template == "self"}
	if !ad.self {
		_, _ = hex.Decode(ad.target[:], []byte(s.Template))
	}
	for _, name := range s.Outputs {
		i := c.t.output(name)
		if i < 0 {
			return ad, bad("advertisement names no output: %q", name)
		}
		if slices.Contains(ad.outputs, i) || slices.ContainsFunc(prev, func(a advert) bool { return slices.Contains(a.outputs, i) }) {
			return ad, bad("output %q is advertised twice", name)
		}
		if c.t.typ == Intent && c.t.outputs[i].onchain {
			return ad, bad("an intent advertises only offchain outputs")
		}
		ad.outputs = append(ad.outputs, i)
	}
	if ad.self && len(ad.outputs) != len(c.t.inputs) {
		return ad, bad("advertising self takes one output per input")
	}
	for slot, i := range ad.outputs {
		if ad.self && c.t.outputs[i].onchain != c.t.inputs[slot].onchain {
			return ad, bad("output %q does not match the type of input slot %q", c.t.outputs[i].name, c.t.inputs[slot].name)
		}
	}
	if ad.self && len(c.t.variables) > 0 {
		return ad, bad("a template with variables cannot advertise itself")
	}
	return ad, nil
}

// packets are in ascending type
func (i *Instance) extension(d *draft, sources []*Source, a *allocation, spends []spending) (extension.Extension, error) {
	t := i.tmpl
	var ext extension.Extension
	assets, err := assetPacket(t, sources, a)
	if err != nil {
		return nil, err
	}
	if assets != nil {
		ext = append(ext, assets)
	}
	var entries []arkade.EmulatorEntry
	for _, s := range spends {
		if s.entry != nil {
			entries = append(entries, *s.entry)
		}
	}
	if len(entries) > 0 {
		emu, err := arkade.NewPacket(entries...)
		if err != nil {
			return nil, fmt.Errorf("%w: emulator packet: %v", ErrIneligible, err)
		}
		ext = append(ext, emu)
	}
	if t.packets == nil {
		if len(ext) > 0 {
			return nil, fmt.Errorf("%w: assets or a covenant need packets", ErrInvalidTemplate)
		}
		return nil, unmatched(sources, nil, false)
	}

	emitted := map[uint8]extension.Packet{}
	handled := map[handledKey]bool{}
	for _, r := range t.packets.rules {
		src := sources[r.from]
		handled[handledKey{src.Outpoint.Hash, r.typ}] = true
		switch r.action {
		case "copy":
			body, ok := packets.Find(src.Tx, r.typ)
			if !ok {
				return nil, fmt.Errorf("%w: input %q has no packet %d to copy", ErrIneligible, t.inputs[r.from].name, r.typ)
			}
			emitted[r.typ] = packets.Raw(r.typ, body)
		case "emit":
			body, err := i.resolve(r.data, d, d.index(r.from))
			if err != nil {
				return nil, fmt.Errorf("packet %d: %w", r.typ, err)
			}
			if len(body) == 0 {
				return nil, fmt.Errorf("%w: packet %d is empty", ErrIneligible, r.typ)
			}
			emitted[r.typ] = packets.Raw(r.typ, body)
		}
	}
	if err := unmatched(sources, handled, t.packets.drop); err != nil {
		return nil, err
	}
	for _, typ := range slices.Sorted(maps.Keys(emitted)) {
		ext = append(ext, emitted[typ])
	}

	if len(t.packets.adverts) > 0 {
		var id [32]byte
		_, _ = hex.Decode(id[:], []byte(t.id))
		body, err := packets.EncodeAdvertisement(t.packets.records(t, id))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidTemplate, err)
		}
		ext = append(ext, packets.Raw(packets.TypeAdvertisement, body))
	}
	return ext, nil
}

type handledKey struct {
	tx  [32]byte
	typ uint8
}

// unmatched fails on a source application packet no rule handles, unless drop.
func unmatched(sources []*Source, handled map[handledKey]bool, drop bool) error {
	for _, s := range sources {
		ext, err := extension.NewExtensionFromTx(s.Tx)
		if errors.Is(err, extension.ErrExtensionNotFound) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: source %s: malformed extension: %v", ErrIneligible, s.Outpoint, err)
		}
		for _, p := range ext {
			typ := p.Type()
			generated := typ == asset.PacketType || typ == arkade.PacketType || typ == packets.TypeAdvertisement
			if !generated && !drop && !handled[handledKey{s.Outpoint.Hash, typ}] {
				return fmt.Errorf("%w: source %s carries packet %d that no rule handles", ErrIneligible, s.Outpoint, typ)
			}
		}
	}
	return nil
}

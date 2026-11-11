package template

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/arkade-os/arkd/pkg/ark-lib/asset"
	"github.com/arkade-os/arkd/pkg/ark-lib/extension"
	"github.com/arkade-os/executor/pkg/template/internal/schema"
)

type assetRoute struct {
	from   int
	asset  []byte       // 34 bytes, nil for catch-all
	amount byteTemplate // nil for the remainder
}

func (c *compiler) route(s *schema.AssetRoute) (assetRoute, error) {
	r := assetRoute{}
	var err error
	if r.from, err = c.inputIndex(s.From, "asset route"); err != nil {
		return r, err
	}
	if c.t.inputs[r.from].onchain {
		return r, bad("onchain input %q carries no assets", c.t.inputs[r.from].name)
	}
	if s.Asset != "" {
		r.asset, _ = hex.DecodeString(s.Asset)
	}
	if s.Amount != nil {
		r.amount, err = c.amount(*s.Amount)
	}
	return r, err
}

func (r assetRoute) sameAsset(x assetRoute) bool {
	return r.from == x.from && bytes.Equal(r.asset, x.asset)
}

// routeAssets credits fixed amounts, then named remainders, then the catch-all; what stays in held has no route.
func (i *Instance) routeAssets(d *draft, slot int, held map[string]uint64, a *allocation) error {
	for pass := range 3 {
		for k, o := range i.tmpl.outputs {
			for _, r := range o.assets {
				if r.from != slot || pass != routePass(r) {
					continue
				}
				key := hex.EncodeToString(r.asset)
				var err error
				switch pass {
				case 0:
					var n uint64
					if n, err = i.fixedAmount(r.amount, d, o.from); err != nil {
						return fmt.Errorf("output %q asset %s: %w", o.name, key, err)
					}
					if n > held[key] {
						return fmt.Errorf("%w: output %q draws %d of asset %s, input %q holds %d", ErrIneligible, o.name, n, key, i.tmpl.inputs[slot].name, held[key])
					}
					held[key] -= n
					err = credit(a.assets[k], key, n)
				case 1:
					err = credit(a.assets[k], key, held[key])
					delete(held, key)
				case 2:
					for key, n := range held {
						if err = credit(a.assets[k], key, n); err != nil {
							break
						}
					}
					clear(held)
				}
				if err != nil {
					return fmt.Errorf("output %q: %w", o.name, err)
				}
			}
		}
	}
	return nil
}

func routePass(r assetRoute) int {
	switch {
	case r.amount != nil:
		return 0
	case r.asset != nil:
		return 1
	}
	return 2
}

// assetPacket is nil when no asset moves.
func assetPacket(t *Template, sources []*Source, a *allocation) (extension.Packet, error) {
	ids := map[string]bool{}
	for _, m := range a.assets {
		for id := range m {
			ids[id] = true
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	var groups []asset.AssetGroup
	for _, id := range slices.Sorted(maps.Keys(ids)) {
		g, err := assetGroup(t, sources, a, id)
		if err != nil {
			return nil, fmt.Errorf("%w: asset %s: %v", ErrIneligible, id, err)
		}
		groups = append(groups, *g)
	}
	p, err := asset.NewPacket(groups)
	if err != nil {
		return nil, fmt.Errorf("%w: assets packet: %v", ErrIneligible, err)
	}
	return p, nil
}

func assetGroup(t *Template, sources []*Source, a *allocation, id string) (*asset.AssetGroup, error) {
	var ins []asset.AssetInput
	for slot, s := range sources {
		held := uint64(0)
		for _, as := range s.Assets {
			if hex.EncodeToString(as.ID) == id {
				held += as.Amount
			}
		}
		if held == 0 {
			continue
		}
		in, err := asset.NewAssetInput(uint16(slot), held)
		if err != nil {
			return nil, err
		}
		ins = append(ins, *in)
	}
	var outs []asset.AssetOutput
	for k, o := range t.outputs {
		if n := a.assets[k][id]; n > 0 {
			out, err := asset.NewAssetOutput(o.index, n)
			if err != nil {
				return nil, err
			}
			outs = append(outs, *out)
		}
	}
	aid, err := asset.NewAssetIdFromString(id)
	if err != nil {
		return nil, err
	}
	return asset.NewAssetGroup(aid, nil, ins, outs, nil)
}

package template

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// Keys are the service keys a contract is resolved under; Delegate is the daemon's cosigner.
type Keys struct{ Server, Emulator, Delegate *btcec.PublicKey }

type contract struct {
	tapscripts []string // hex leaves, function then leaf order
	pkScript   []byte
	covenants  map[string][]byte                        // function name -> arkade script
	proofs     map[[2]string]*psbt.TaprootTapLeafScript // {function, leaf} -> leaf with control block
}

func build(def *Definition, args map[string]value, keys Keys) (*contract, error) {
	field := func(name string) (value, error) {
		v, ok := args[name]
		if !ok {
			return value{}, fmt.Errorf("unknown constructor value %q", name)
		}
		return v, nil
	}
	// covenants and leaves both see a pubkey as the x-only key taproot uses
	keyField := func(name string) (value, error) {
		v, err := field(name)
		if err != nil || v.typ != "pubkey" {
			return v, err
		}
		pk, err := btcec.ParsePubKey(v.raw)
		if err != nil {
			return value{}, err
		}
		return value{"bytes32", schnorr.SerializePubKey(pk)}, nil
	}

	delegate := func() (*btcec.PublicKey, error) {
		if keys.Delegate == nil {
			return nil, fmt.Errorf("%w: no delegate key", ErrUnsupported)
		}
		return keys.Delegate, nil
	}
	// intent messages spell cosigner keys in hex
	covenantLookup := func(name string) (value, error) {
		if name != "DELEGATE_KEY" {
			return keyField(name)
		}
		pk, err := delegate()
		if err != nil {
			return value{}, err
		}
		return value{"bytes", []byte(hex.EncodeToString(pk.SerializeCompressed()))}, nil
	}

	c := &contract{covenants: map[string][]byte{}, proofs: map[[2]string]*psbt.TaprootTapLeafScript{}}
	for _, fn := range def.Functions {
		if fn.Arkade == nil {
			continue
		}
		s, err := assemble(fn.Arkade.Asm, covenantLookup)
		if err != nil {
			return nil, fmt.Errorf("%w: function %q: %v", ErrInvalidTemplate, fn.Name, err)
		}
		c.covenants[fn.Name] = s
	}

	tweak := func(key *btcec.PublicKey, fn string) (value, error) {
		cov, ok := c.covenants[fn]
		if !ok {
			return value{}, fmt.Errorf("function %q has no covenant", fn)
		}
		t := arkade.ComputeArkadeScriptPublicKey(key, arkade.ArkadeScriptHash(cov))
		return value{"bytes32", schnorr.SerializePubKey(t)}, nil
	}
	leafLookup := func(name string) (value, error) {
		parts := strings.Split(name, ":")
		switch {
		case name == "SERVER_KEY":
			return value{"bytes32", schnorr.SerializePubKey(keys.Server)}, nil
		case name == "DELEGATE_KEY":
			pk, err := delegate()
			if err != nil {
				return value{}, err
			}
			return value{"bytes32", schnorr.SerializePubKey(pk)}, nil
		case len(parts) == 2 && parts[0] == "EMULATOR_KEY":
			return tweak(keys.Emulator, parts[1])
		case len(parts) == 3 && parts[0] == "TWEAK":
			v, err := field(parts[1])
			if err != nil {
				return value{}, err
			}
			pk, err := btcec.ParsePubKey(v.raw)
			if err != nil {
				return value{}, err
			}
			return tweak(pk, parts[2])
		}
		return keyField(name)
	}

	var leaves []txscript.TapLeaf
	var names [][2]string
	seen := map[string]bool{}
	for _, fn := range def.Functions {
		for _, l := range fn.Leaves {
			s, err := assemble(l.Asm, leafLookup)
			if err != nil {
				return nil, fmt.Errorf("%w: leaf %s/%s: %v", ErrInvalidTemplate, fn.Name, l.Name, err)
			}
			h := hex.EncodeToString(s)
			if seen[h] {
				return nil, fmt.Errorf("%w: duplicate leaf %s/%s", ErrInvalidTemplate, fn.Name, l.Name)
			}
			seen[h] = true
			c.tapscripts = append(c.tapscripts, h)
			names = append(names, [2]string{fn.Name, l.Name})
			leaves = append(leaves, txscript.NewBaseTapLeaf(s))
		}
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("%w: no leaves", ErrInvalidTemplate)
	}

	tree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tree.RootNode.TapHash()
	internal := script.UnspendableKey()
	var err error
	if c.pkScript, err = script.P2TRScript(txscript.ComputeTaprootOutputKey(internal, root[:])); err != nil {
		return nil, err
	}
	for i, l := range leaves {
		proof := tree.LeafMerkleProofs[tree.LeafProofIndex[l.TapHash()]]
		control := proof.ToControlBlock(internal)
		cb, err := control.ToBytes()
		if err != nil {
			return nil, err
		}
		c.proofs[names[i]] = &psbt.TaprootTapLeafScript{
			ControlBlock: cb,
			Script:       proof.Script,
			LeafVersion:  txscript.BaseLeafVersion,
		}
	}
	return c, nil
}

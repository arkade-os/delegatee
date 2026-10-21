package template

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// Keys are the service keys a contract is resolved under; Delegate is the daemon's cosigner.
type Keys struct{ Server, Emulator, Delegate *btcec.PublicKey }

type contract struct {
	tapscripts []string // hex leaves; the given tree's order if any, else function then leaf order
	pkScript   []byte
	covenants  map[string][]byte                        // function name -> arkade script
	proofs     map[[2]string]*psbt.TaprootTapLeafScript // {function, leaf} -> leaf with control block
}

func build(def *Definition, args map[string]value, keys Keys) (*contract, error) {
	return buildTree(def, args, keys, nil)
}

func field(args map[string]value, name string) (value, error) {
	v, ok := args[name]
	if !ok {
		return value{}, fmt.Errorf("unknown constructor value %q", name)
	}
	return v, nil
}

func keyField(args map[string]value, name string) (value, error) {
	v, err := field(args, name)
	if err != nil || v.typ != "pubkey" {
		return v, err
	}
	pk, err := btcec.ParsePubKey(v.raw)
	if err != nil {
		return value{}, err
	}
	return value{"bytes32", schnorr.SerializePubKey(pk)}, nil
}

func delegate(keys Keys) (*btcec.PublicKey, error) {
	if keys.Delegate == nil {
		return nil, fmt.Errorf("%w: no delegate key", ErrUnsupported)
	}
	return keys.Delegate, nil
}

func covenantLookup(keys Keys, args map[string]value, name string) (value, error) {
	if name != "DELEGATE_KEY" {
		return keyField(args, name)
	}
	pk, err := delegate(keys)
	if err != nil {
		return value{}, err
	}
	return value{"bytes", []byte(hex.EncodeToString(pk.SerializeCompressed()))}, nil
}

func tweak(c *contract, key *btcec.PublicKey, fn string) (value, error) {
	cov, ok := c.covenants[fn]
	if !ok {
		return value{}, fmt.Errorf("function %q has no covenant", fn)
	}
	t := arkade.ComputeArkadeScriptPublicKey(key, arkade.ArkadeScriptHash(cov))
	return value{"bytes32", schnorr.SerializePubKey(t)}, nil
}

// buildTree checks the declared leaves against taptree when it is given, and takes the tree's leaves and key.
func buildTree(def *Definition, args map[string]value, keys Keys, taptree []byte) (*contract, error) {
	c := &contract{
		covenants: map[string][]byte{},
		proofs:    map[[2]string]*psbt.TaprootTapLeafScript{},
	}

	for _, fn := range def.Functions {
		if fn.Arkade == nil {
			continue
		}
		s, err := assemble(fn.Arkade.Asm, func(name string) (value, error) {
			return covenantLookup(keys, args, name)
		})
		if err != nil {
			return nil, fmt.Errorf("%w: function %q: %v", ErrInvalidTemplate, fn.Name, err)
		}
		c.covenants[fn.Name] = s
	}

	leafLookup := func(name string) (value, error) {
		parts := strings.Split(name, ":")
		switch {
		case name == "SERVER_KEY":
			return value{"bytes32", schnorr.SerializePubKey(keys.Server)}, nil
		case name == "DELEGATE_KEY":
			pk, err := delegate(keys)
			if err != nil {
				return value{}, err
			}
			return value{"bytes32", schnorr.SerializePubKey(pk)}, nil
		case len(parts) == 2 && parts[0] == "EMULATOR_KEY":
			return tweak(c, keys.Emulator, parts[1])
		case len(parts) == 3 && parts[0] == "TWEAK":
			v, err := field(args, parts[1])
			if err != nil {
				return value{}, err
			}
			pk, err := btcec.ParsePubKey(v.raw)
			if err != nil {
				return value{}, err
			}
			return tweak(c, pk, parts[2])
		}
		return keyField(args, name)
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

	var err error
	if taptree != nil {
		if leaves, names, c.tapscripts, err = fromTree(taptree, leaves, names); err != nil {
			return nil, err
		}
	}

	tree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tree.RootNode.TapHash()
	internal := script.UnspendableKey()
	if c.pkScript, err = script.P2TRScript(txscript.ComputeTaprootOutputKey(internal, root[:])); err != nil {
		return nil, err
	}
	for i, l := range leaves {
		if names[i] == ([2]string{}) {
			continue
		}
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

const maxTaptreeBytes = 8 << 10

// decodeTaptree returns the leaves of a BIP-371 tree whose every leaf is a closure arkd accepts.
func decodeTaptree(raw []byte) ([]string, error) {
	if len(raw) > maxTaptreeBytes {
		return nil, fmt.Errorf("%w: taptree of %d bytes exceeds %d", ErrIneligible, len(raw), maxTaptreeBytes)
	}
	scripts, err := txutils.DecodeTapTree(raw)
	if err == nil && len(scripts) == 0 {
		err = errors.New("no leaf")
	}
	if err == nil {
		err = (&script.TapscriptsVtxoScript{}).Decode(scripts)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: taptree: %v", ErrIneligible, err)
	}
	return scripts, nil
}

func tapLeaves(scripts []string) []txscript.TapLeaf {
	leaves := make([]txscript.TapLeaf, len(scripts))
	for i, h := range scripts {
		s, _ := hex.DecodeString(h) // DecodeTapTree hex-encodes
		leaves[i] = txscript.NewBaseTapLeaf(s)
	}
	return leaves
}

func taptreeScript(raw []byte) ([]byte, error) {
	scripts, err := decodeTaptree(raw)
	if err != nil {
		return nil, err
	}
	root := txscript.AssembleTaprootScriptTree(tapLeaves(scripts)...).RootNode.TapHash()
	return script.P2TRScript(txscript.ComputeTaprootOutputKey(script.UnspendableKey(), root[:]))
}

// fromTree swaps the declared leaves for the tree's, which must hold each of them.
func fromTree(raw []byte, declared []txscript.TapLeaf, names [][2]string) ([]txscript.TapLeaf, [][2]string, []string, error) {
	scripts, err := decodeTaptree(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	at := make(map[string]int, len(scripts))
	for i, h := range scripts {
		at[h] = i
	}
	treeNames := make([][2]string, len(scripts))
	for i, l := range declared {
		j, ok := at[hex.EncodeToString(l.Script)]
		if !ok {
			return nil, nil, nil, fmt.Errorf("%w: leaf %s/%s is not in the taptree", ErrIneligible, names[i][0], names[i][1])
		}
		treeNames[j] = names[i]
	}
	return tapLeaves(scripts), treeNames, scripts, nil
}

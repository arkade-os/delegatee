// Package contract builds the taproot output of a contract definition bound to its arguments and
// keys.
package contract

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/arkade-os/arkd/pkg/ark-lib/script"
	"github.com/arkade-os/arkd/pkg/ark-lib/txutils"
	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/arkade-os/executor/pkg/template/internal/asm"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
)

// Keys are the service keys a contract is resolved under; Cosigner is the daemon's cosigner.
type Keys struct{ Server, Emulator, Cosigner *btcec.PublicKey }

// Contract is a built taproot output and the proofs of its leaves.
type Contract struct {
	Tapscripts []string // hex leaves; the given tree's order if any, else function then leaf order
	PkScript   []byte
	Covenants  map[string][]byte                        // function name -> arkade script
	Proofs     map[[2]string]*psbt.TaprootTapLeafScript // {function, leaf} -> leaf with control block
}

// maxTaptreeBytes bounds a given taptree.
const maxTaptreeBytes = 8 << 10

// Build assembles the covenants and leaves of def with args and keys. When taptree is given, the
// declared leaves must be in it, and the tree's leaves and key are taken.
func Build(
	def *artifact.Definition, args map[string]asm.Value, keys Keys, taptree []byte,
) (*Contract, error) {
	c := &Contract{
		Covenants: map[string][]byte{},
		Proofs:    map[[2]string]*psbt.TaprootTapLeafScript{},
	}

	for _, fn := range def.Functions {
		if fn.Arkade == nil {
			continue
		}
		s, err := asm.Assemble(fn.Arkade.Asm, func(name string) (asm.Value, error) {
			return covenantLookup(keys, args, name)
		})
		if err != nil {
			return nil, fmt.Errorf("%w: function %q: %v", ErrBadLeaf, fn.Name, err)
		}
		c.Covenants[fn.Name] = s
	}

	leafLookup := func(name string) (asm.Value, error) {
		parts := strings.Split(name, ":")
		switch {
		case name == "SERVER_KEY":
			return asm.Value{Type: "bytes32", Raw: schnorr.SerializePubKey(keys.Server)}, nil
		case name == "COSIGNER_KEY":
			pk, err := cosigner(keys)
			if err != nil {
				return asm.Value{}, err
			}
			return asm.Value{Type: "bytes32", Raw: schnorr.SerializePubKey(pk)}, nil
		case len(parts) == 2 && parts[0] == "EMULATOR_KEY":
			return tweak(c, keys.Emulator, parts[1])
		case len(parts) == 3 && parts[0] == "TWEAK":
			v, err := field(args, parts[1])
			if err != nil {
				return asm.Value{}, err
			}
			pk, err := btcec.ParsePubKey(v.Raw)
			if err != nil {
				return asm.Value{}, err
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
			s, err := asm.Assemble(l.Asm, leafLookup)
			if err != nil {
				return nil, fmt.Errorf("%w: leaf %s/%s: %v", ErrBadLeaf, fn.Name, l.Name, err)
			}
			h := hex.EncodeToString(s)
			if seen[h] {
				return nil, fmt.Errorf("%w: duplicate leaf %s/%s", ErrBadLeaf, fn.Name, l.Name)
			}
			seen[h] = true
			c.Tapscripts = append(c.Tapscripts, h)
			names = append(names, [2]string{fn.Name, l.Name})
			leaves = append(leaves, txscript.NewBaseTapLeaf(s))
		}
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("%w: no leaves", ErrBadLeaf)
	}

	var err error
	if taptree != nil {
		if leaves, names, c.Tapscripts, err = fromTree(taptree, leaves, names); err != nil {
			return nil, err
		}
	}

	tree := txscript.AssembleTaprootScriptTree(leaves...)
	root := tree.RootNode.TapHash()
	internal := script.UnspendableKey()
	if c.PkScript, err = script.P2TRScript(
		txscript.ComputeTaprootOutputKey(internal, root[:]),
	); err != nil {
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
		c.Proofs[names[i]] = &psbt.TaprootTapLeafScript{
			ControlBlock: cb, Script: proof.Script, LeafVersion: txscript.BaseLeafVersion,
		}
	}
	return c, nil
}

// TaptreeScript is the P2TR script of a given tree.
func TaptreeScript(raw []byte) ([]byte, error) {
	scripts, err := decodeTaptree(raw)
	if err != nil {
		return nil, err
	}
	root := txscript.AssembleTaprootScriptTree(tapLeaves(scripts)...).RootNode.TapHash()
	return script.P2TRScript(txscript.ComputeTaprootOutputKey(script.UnspendableKey(), root[:]))
}

func field(args map[string]asm.Value, name string) (asm.Value, error) {
	v, ok := args[name]
	if !ok {
		return asm.Value{}, fmt.Errorf("unknown constructor value %q", name)
	}
	return v, nil
}

func keyField(args map[string]asm.Value, name string) (asm.Value, error) {
	v, err := field(args, name)
	if err != nil || v.Type != "pubkey" {
		return v, err
	}
	pk, err := btcec.ParsePubKey(v.Raw)
	if err != nil {
		return asm.Value{}, err
	}
	return asm.Value{Type: "bytes32", Raw: schnorr.SerializePubKey(pk)}, nil
}

func cosigner(keys Keys) (*btcec.PublicKey, error) {
	if keys.Cosigner == nil {
		return nil, ErrNoCosigner
	}
	return keys.Cosigner, nil
}

func covenantLookup(keys Keys, args map[string]asm.Value, name string) (asm.Value, error) {
	if name != "COSIGNER_KEY" {
		return keyField(args, name)
	}
	pk, err := cosigner(keys)
	if err != nil {
		return asm.Value{}, err
	}
	return asm.Value{Type: "bytes", Raw: []byte(hex.EncodeToString(pk.SerializeCompressed()))}, nil
}

func tweak(c *Contract, key *btcec.PublicKey, fn string) (asm.Value, error) {
	cov, ok := c.Covenants[fn]
	if !ok {
		return asm.Value{}, fmt.Errorf("function %q has no covenant", fn)
	}
	t := arkade.ComputeArkadeScriptPublicKey(key, arkade.ArkadeScriptHash(cov))
	return asm.Value{Type: "bytes32", Raw: schnorr.SerializePubKey(t)}, nil
}

// decodeTaptree returns the leaves of a BIP-371 tree whose every leaf is a closure arkd accepts.
func decodeTaptree(raw []byte) ([]string, error) {
	if len(raw) > maxTaptreeBytes {
		return nil, fmt.Errorf(
			"%w: taptree of %d bytes exceeds %d", ErrBadTree, len(raw), maxTaptreeBytes,
		)
	}
	scripts, err := txutils.DecodeTapTree(raw)
	if err == nil && len(scripts) == 0 {
		err = errors.New("no leaf")
	}
	if err == nil {
		err = (&script.TapscriptsVtxoScript{}).Decode(scripts)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadTree, err)
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

// fromTree swaps the declared leaves for the tree's, which must hold each of them.
func fromTree(
	raw []byte, declared []txscript.TapLeaf, names [][2]string,
) ([]txscript.TapLeaf, [][2]string, []string, error) {
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
			return nil, nil, nil, fmt.Errorf(
				"%w: leaf %s/%s is not in the taptree", ErrBadTree, names[i][0], names[i][1],
			)
		}
		treeNames[j] = names[i]
	}
	return tapLeaves(scripts), treeNames, scripts, nil
}

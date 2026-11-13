package asm

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript/v2"
)

var (
	forbiddenPrefixes = []string{
		"OP_INSPECTOUTPUT", "OP_INSPECTOUTASSET", "OP_INSPECTASSETGROUP", "OP_INSPECTINPUTARKADE",
		"OP_INSPECTINASSET",
	}
	forbiddenOps = []string{
		"OP_INSPECTNUMOUTPUTS", "OP_TUNNEL", "OP_INSPECTPACKET", "OP_INSPECTNUMASSETGROUPS",
		"OP_FINDASSETGROUPBYASSETID", "OP_INSPECTINTENTMESSAGE", "OP_TXID", "OP_TXWEIGHT",
		"OP_SIGHASH", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKSIGADD",
	}
	contextOps = []string{
		"OP_PUSHCURRENTINPUTINDEX", "OP_PUSHEXPIRY", "OP_CHECKTIME", "OP_INSPECTVERSION",
		"OP_INSPECTLOCKTIME", "OP_INSPECTNUMINPUTS", "OP_CHECKLOCKTIMEVERIFY", "OP_NOP2",
		"OP_CHECKSEQUENCEVERIFY", "OP_NOP3",
	}
)

var opNames = map[byte][]string{}

func init() {
	for name, op := range arkade.OpcodeByName {
		opNames[op] = append(opNames[op], name)
	}
}

// ContextFree reports whether tokens read neither the transaction, a source, an expiry, nor the
// clock.
func ContextFree(tokens []string) bool {
	return !slices.ContainsFunc(tokens, func(tok string) bool {
		return forbidden(tok) || strings.HasPrefix(tok, "OP_INSPECTINPUT") ||
			slices.Contains(contextOps, tok)
	})
}

// CheckExpression refuses opcodes observing the transaction being built or exceeding the emulator's
// compute limits.
func CheckExpression(tokens []string) error {
	if i := slices.IndexFunc(tokens, forbidden); i >= 0 {
		return fmt.Errorf("%w: forbidden opcode %s", ErrBadExpression, tokens[i])
	}
	// script has no loops: counting every occurrence bounds execution
	limits := arkade.DefaultComputeLimits()
	counts := map[byte]int{}
	for _, tok := range tokens {
		if DecimalTok.MatchString(tok) || HexTok.MatchString(tok) || Placeholder.MatchString(tok) ||
			Splice.MatchString(tok) {
			continue
		}
		op, err := Opcode(tok)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBadExpression, err)
		}
		counts[op]++
		if limit, ok := limits[op]; ok && counts[op] > limit {
			return fmt.Errorf("%w: %s exceeds its limit of %d", ErrBadExpression, tok, limit)
		}
	}
	return nil
}

// Program parses a spliced program: serialized script of opcodes and minimal pushes.
func Program(raw []byte) error {
	tok := txscript.MakeScriptTokenizer(0, raw)
	for start := 0; tok.Next(); start = int(tok.ByteIndex()) {
		op := tok.Opcode()
		if op == txscript.OP_0 || op > txscript.OP_PUSHDATA4 {
			continue
		}
		minimal, err := txscript.NewScriptBuilder().AddData(tok.Data()).Script()
		if data := tok.Data(); len(data) == 1 && data[0] == 0 {
			minimal = []byte{txscript.OP_DATA_1, 0} // how addData pushes a zero byte
		}
		if err != nil || !bytes.Equal(raw[start:tok.ByteIndex()], minimal) {
			return fmt.Errorf("%w: non-minimal push", ErrBadExpression)
		}
	}
	if err := tok.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrBadExpression, err)
	}
	return nil
}

func CheckScript(script []byte, contextFree bool) error {
	if err := Program(script); err != nil {
		return err
	}
	limits := arkade.DefaultComputeLimits()
	counts := map[byte]int{}
	tok := txscript.MakeScriptTokenizer(0, script)
	for tok.Next() {
		op := tok.Opcode()
		if op <= txscript.OP_PUSHDATA4 {
			continue
		}
		names := opNames[op]
		if len(names) == 0 {
			return fmt.Errorf("%w: unknown opcode 0x%02x", ErrBadExpression, op)
		}
		if slices.ContainsFunc(names, forbidden) {
			return fmt.Errorf("%w: forbidden opcode %s", ErrBadExpression, names[0])
		}
		if contextFree && !ContextFree(names) {
			return fmt.Errorf("%w: %s is not context-free", ErrBadExpression, names[0])
		}
		counts[op]++
		if limit, ok := limits[op]; ok && counts[op] > limit {
			return fmt.Errorf("%w: %s exceeds its limit of %d", ErrBadExpression, names[0], limit)
		}
	}
	return nil
}

// forbidden reports whether tok observes outputs, assets or signatures.
func forbidden(tok string) bool {
	return slices.Contains(forbiddenOps, tok) ||
		slices.ContainsFunc(
			forbiddenPrefixes, func(p string) bool { return strings.HasPrefix(tok, p) },
		)
}

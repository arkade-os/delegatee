package asm

import (
	"fmt"
	"slices"
	"strings"

	"github.com/arkade-os/emulator/pkg/arkade"
)

var (
	forbiddenPrefixes = []string{"OP_INSPECTOUTPUT", "OP_INSPECTOUTASSET", "OP_INSPECTASSETGROUP", "OP_INSPECTINPUTARKADE", "OP_INSPECTINASSET"}
	forbiddenOps      = []string{
		"OP_INSPECTNUMOUTPUTS", "OP_TUNNEL", "OP_INSPECTPACKET", "OP_INSPECTNUMASSETGROUPS", "OP_FINDASSETGROUPBYASSETID",
		"OP_INSPECTINTENTMESSAGE", "OP_TXID", "OP_TXWEIGHT", "OP_SIGHASH", "OP_CHECKSIG", "OP_CHECKSIGVERIFY", "OP_CHECKSIGADD",
	}
	contextOps = []string{
		"OP_PUSHCURRENTINPUTINDEX", "OP_PUSHEXPIRY", "OP_CHECKTIME", "OP_INSPECTVERSION", "OP_INSPECTLOCKTIME", "OP_INSPECTNUMINPUTS",
		"OP_CHECKLOCKTIMEVERIFY", "OP_NOP2", "OP_CHECKSEQUENCEVERIFY", "OP_NOP3",
	}
)

// ContextFree reports whether tokens read neither the transaction, a source, an expiry, nor the clock.
func ContextFree(tokens []string) bool {
	return !slices.ContainsFunc(tokens, func(tok string) bool {
		return forbidden(tok) || strings.HasPrefix(tok, "OP_INSPECTINPUT") || slices.Contains(contextOps, tok)
	})
}

// CheckExpression refuses opcodes observing the transaction being built or exceeding the emulator's compute limits.
func CheckExpression(tokens []string) error {
	if i := slices.IndexFunc(tokens, forbidden); i >= 0 {
		return fmt.Errorf("%w: forbidden opcode %s", ErrBadExpression, tokens[i])
	}
	// script has no loops: counting every occurrence bounds execution
	limits := arkade.DefaultComputeLimits()
	counts := map[byte]int{}
	for _, tok := range tokens {
		if DecimalTok.MatchString(tok) || HexTok.MatchString(tok) || Placeholder.MatchString(tok) {
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

// forbidden reports whether tok observes outputs, assets or signatures.
func forbidden(tok string) bool {
	return slices.Contains(forbiddenOps, tok) || slices.ContainsFunc(forbiddenPrefixes, func(p string) bool { return strings.HasPrefix(tok, p) })
}

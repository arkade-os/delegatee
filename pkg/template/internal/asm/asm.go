// Package asm assembles the script mini-language of templates and types its scalar values.
package asm

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript/v2"
)

// maxPushSize is the largest data push a script accepts.
const maxPushSize = 520

// Value is a resolved scalar; int values are pushed as Script numbers.
type Value struct {
	Type string
	Raw  []byte
}

// Lookup resolves the text between the <...> brackets of a placeholder.
type Lookup func(name string) (Value, error)

// Assemble turns tokens into a script: opcodes, decimals, 0x hex pushes and <placeholders>.
func Assemble(tokens []string, lookup Lookup) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	for _, tok := range tokens {
		if err := addToken(b, tok, lookup); err != nil {
			return nil, err
		}
	}
	return b.Script()
}

func addToken(b *txscript.ScriptBuilder, tok string, lookup Lookup) error {
	switch {
	case strings.HasPrefix(tok, "OP_"):
		op, err := Opcode(tok)
		if err != nil {
			return err
		}
		b.AddOp(op)
	case DecimalTok.MatchString(tok):
		n, err := ParseDecimal(tok)
		if err != nil {
			return err
		}
		b.AddInt64(n)
	case HexTok.MatchString(tok):
		raw, _ := hex.DecodeString(tok[2:])
		return addData(b, tok, raw)
	case Placeholder.MatchString(tok):
		if lookup == nil {
			return fmt.Errorf("%s: no lookup", tok)
		}
		v, err := lookup(tok[1 : len(tok)-1])
		if err != nil {
			return fmt.Errorf("%s: %w", tok, err)
		}
		if v.Type != "int" {
			return addData(b, tok, v.Raw)
		}
		n, err := ParseScriptNum(v.Raw)
		if err != nil {
			return fmt.Errorf("%s: %w", tok, err)
		}
		b.AddInt64(n)
	default:
		return fmt.Errorf("unsupported token %q", tok)
	}
	return nil
}

// Opcode returns the byte of an OP_ token; push opcodes are refused, they would run the next token's data as code.
func Opcode(tok string) (byte, error) {
	op, ok := arkade.OpcodeByName[tok]
	if !ok {
		return 0, fmt.Errorf("unknown opcode %q", tok)
	}
	if op >= txscript.OP_DATA_1 && op <= txscript.OP_PUSHDATA4 {
		return 0, fmt.Errorf("push opcode %q", tok)
	}
	return op, nil
}

func addData(b *txscript.ScriptBuilder, tok string, raw []byte) error {
	if len(raw) > maxPushSize {
		return fmt.Errorf("%s: push of %d bytes exceeds %d", tok, len(raw), maxPushSize)
	}
	if len(raw) == 1 && raw[0] == 0 {
		b.AddOps([]byte{txscript.OP_DATA_1, 0}) // AddData would emit OP_0
	} else {
		b.AddData(raw)
	}
	return nil
}

// ParseDecimal parses a decimal token with magnitude up to 2^53-1.
func ParseDecimal(tok string) (int64, error) {
	n, err := strconv.ParseInt(tok, 10, 64)
	if err != nil || n > MaxScriptNum || n < -MaxScriptNum {
		return 0, fmt.Errorf("number %q out of range", tok)
	}
	return n, nil
}

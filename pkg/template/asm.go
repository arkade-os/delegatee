package template

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript/v2"
)

const maxPushSize = 520

// value is a resolved scalar; int values are pushed as Script numbers.
type value struct {
	typ string
	raw []byte
}

// lookup receives the text between the <...> brackets
func assemble(tokens []string, lookup func(name string) (value, error)) ([]byte, error) {
	b := txscript.NewScriptBuilder()
	for _, tok := range tokens {
		if err := addToken(b, tok, lookup); err != nil {
			return nil, err
		}
	}
	return b.Script()
}

func addToken(b *txscript.ScriptBuilder, tok string, lookup func(string) (value, error)) error {
	switch {
	case strings.HasPrefix(tok, "OP_"):
		op, err := opcode(tok)
		if err != nil {
			return err
		}
		b.AddOp(op)
	case decimalTok.MatchString(tok):
		n, err := parseDecimal(tok)
		if err != nil {
			return err
		}
		b.AddInt64(n)
	case hexTok.MatchString(tok):
		raw, _ := hex.DecodeString(tok[2:])
		return addData(b, tok, raw)
	case placeholder.MatchString(tok):
		v, err := lookup(tok[1 : len(tok)-1])
		if err != nil {
			return fmt.Errorf("%s: %w", tok, err)
		}
		if v.typ != "int" {
			return addData(b, tok, v.raw)
		}
		n, err := parseScriptNum(v.raw)
		if err != nil {
			return fmt.Errorf("%s: %w", tok, err)
		}
		b.AddInt64(n)
	default:
		return fmt.Errorf("unsupported token %q", tok)
	}
	return nil
}

// push opcodes are refused: they would run the next token's data as code
func opcode(tok string) (byte, error) {
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

// parseDecimal parses a decimal token with magnitude up to 2^53-1.
func parseDecimal(tok string) (int64, error) {
	n, err := strconv.ParseInt(tok, 10, 64)
	if err != nil || n > maxScriptNum || n < -maxScriptNum {
		return 0, fmt.Errorf("number %q out of range", tok)
	}
	return n, nil
}

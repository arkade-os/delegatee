package template

import (
	"bytes"
	"fmt"

	"github.com/arkade-os/emulator/pkg/arkade"
	"github.com/btcsuite/btcd/txscript/v2"
)

func (i *Instance) predicates(d *draft) error {
	programs := make([][]byte, len(i.tmpl.inputs))
	total := map[byte]int{}
	for slot, in := range i.tmpl.inputs {
		if in.predicate == nil {
			continue
		}
		program, err := i.resolve(*in.predicate, d, d.index(slot))
		if err != nil {
			return fmt.Errorf("%w: input %q predicate binding failed", ErrIneligible, in.name)
		}
		if err := checkPredicate(program, total); err != nil {
			return err
		}
		programs[slot] = program
	}
	for slot, program := range programs {
		if program == nil {
			continue
		}
		index := d.index(slot)
		vm, err := arkade.NewEngine(program, d.tx, index, nil, nil, int64(d.sources[index].Amount), d)
		if err != nil {
			return predicateError(err)
		}
		if expiry := d.sources[index].Expiry; !expiry.IsZero() {
			arkade.WithExpiry(expiry.Unix())(vm)
		}
		for steps, done := 0, false; !done; steps++ {
			if steps >= len(program) {
				return fmt.Errorf("%w: predicate step limit", ErrIneligible)
			}
			if done, err = vm.Step(); err != nil {
				return predicateError(err)
			}
		}
		stack := vm.GetStack()
		if len(stack) != 1 || !bytes.Equal(stack[0], []byte{1}) {
			return fmt.Errorf("%w: predicate must return one canonical true", ErrIneligible)
		}
	}
	return nil
}

func predicateError(err error) error {
	return fmt.Errorf("%w: predicate: %s", ErrIneligible, vmError(err))
}

func checkPredicate(program []byte, total map[byte]int) error {
	if len(program) < 1 || len(program) > 520 {
		return fmt.Errorf("%w: predicate size outside 1..520", ErrIneligible)
	}
	counts := map[byte]int{}
	// Raw engines have no taproot context: the pinned VM's compute budget does not charge them.
	// Loopless programs permit conservative counting of every branch before any predicate runs.
	ops := 0
	tokens := txscript.MakeScriptTokenizer(0, program)
	for tokens.Next() {
		op := tokens.Opcode()
		if op <= txscript.OP_PUSHDATA4 {
			if !minimalPredicatePush(op, tokens.Data()) {
				return fmt.Errorf("%w: predicate nonminimal push", ErrIneligible)
			}
			continue
		}
		if !predicateOpcode(op) {
			return fmt.Errorf("%w: predicate forbidden opcode", ErrIneligible)
		}
		if op > txscript.OP_16 {
			ops++
		}
		if ops > 201 {
			return fmt.Errorf("%w: predicate opcode limit", ErrIneligible)
		}
		counts[op]++
		total[op]++
		limit := predicateComputeLimit(op)
		if limit > 0 && counts[op] > limit {
			return fmt.Errorf("%w: predicate compute limit", ErrIneligible)
		}
		if limit > 0 && total[op] > 4*limit {
			return fmt.Errorf("%w: predicate aggregate compute limit", ErrIneligible)
		}
	}
	if err := tokens.Err(); err != nil {
		return predicateError(err)
	}
	return nil
}

func predicateComputeLimit(op byte) int {
	switch op {
	case arkade.OP_CHECKSIGFROMSTACK, arkade.OP_ECMUL, arkade.OP_ECMULSCALARVERIFY, arkade.OP_TWEAKVERIFY:
		return 50
	case arkade.OP_ECADD:
		return 1000
	case arkade.OP_ECPAIRING:
		return 2
	case arkade.OP_MODEXP:
		return 64
	}
	return 0
}

func minimalPredicatePush(op byte, data []byte) bool {
	switch n := len(data); {
	case n == 0:
		return op == txscript.OP_0
	case n == 1 && data[0] >= 1 && data[0] <= 16:
		return false
	case n == 1 && data[0] == 0x81:
		return false
	case n <= 75:
		return int(op) == n
	case n <= 255:
		return op == txscript.OP_PUSHDATA1
	default:
		return op == txscript.OP_PUSHDATA2
	}
}

func predicateOpcode(op byte) bool {
	if op == txscript.OP_1NEGATE || op >= txscript.OP_1 && op <= txscript.OP_16 {
		return true
	}
	switch op {
	case arkade.OP_NOP, arkade.OP_IF, arkade.OP_NOTIF, arkade.OP_ELSE, arkade.OP_ENDIF, arkade.OP_VERIFY, arkade.OP_RETURN,
		arkade.OP_TOALTSTACK, arkade.OP_FROMALTSTACK, arkade.OP_2DROP, arkade.OP_2DUP, arkade.OP_3DUP, arkade.OP_2OVER,
		arkade.OP_2ROT, arkade.OP_2SWAP, arkade.OP_IFDUP, arkade.OP_DEPTH, arkade.OP_DROP, arkade.OP_DUP, arkade.OP_NIP,
		arkade.OP_OVER, arkade.OP_PICK, arkade.OP_ROLL, arkade.OP_ROT, arkade.OP_SWAP, arkade.OP_TUCK,
		arkade.OP_CAT, arkade.OP_SUBSTR, arkade.OP_LEFT, arkade.OP_RIGHT, arkade.OP_SIZE,
		arkade.OP_INVERT, arkade.OP_AND, arkade.OP_OR, arkade.OP_XOR, arkade.OP_EQUAL, arkade.OP_EQUALVERIFY,
		arkade.OP_1ADD, arkade.OP_1SUB, arkade.OP_2MUL, arkade.OP_2DIV, arkade.OP_NEGATE, arkade.OP_ABS, arkade.OP_NOT,
		arkade.OP_0NOTEQUAL, arkade.OP_ADD, arkade.OP_SUB, arkade.OP_MUL, arkade.OP_DIV, arkade.OP_MOD,
		arkade.OP_LSHIFT, arkade.OP_RSHIFT, arkade.OP_BOOLAND, arkade.OP_BOOLOR, arkade.OP_NUMEQUAL, arkade.OP_NUMEQUALVERIFY,
		arkade.OP_NUMNOTEQUAL, arkade.OP_LESSTHAN, arkade.OP_GREATERTHAN, arkade.OP_LESSTHANOREQUAL, arkade.OP_GREATERTHANOREQUAL,
		arkade.OP_MIN, arkade.OP_MAX, arkade.OP_WITHIN, arkade.OP_RIPEMD160, arkade.OP_SHA1, arkade.OP_SHA256, arkade.OP_HASH160, arkade.OP_HASH256,
		arkade.OP_CHECKLOCKTIMEVERIFY, arkade.OP_CHECKSEQUENCEVERIFY, arkade.OP_CHECKSIGFROMSTACK,
		arkade.OP_INSPECTINPUTOUTPOINT, arkade.OP_INSPECTINPUTVALUE, arkade.OP_INSPECTINPUTSCRIPTPUBKEY, arkade.OP_INSPECTINPUTSEQUENCE,
		arkade.OP_PUSHCURRENTINPUTINDEX, arkade.OP_INSPECTVERSION, arkade.OP_INSPECTLOCKTIME, arkade.OP_INSPECTNUMINPUTS,
		arkade.OP_NUM2BIN, arkade.OP_BIN2NUM, arkade.OP_REVERSEBYTES, arkade.OP_MODEXP, arkade.OP_PUSHEXPIRY, arkade.OP_CHECKTIME,
		arkade.OP_ECADD, arkade.OP_ECMUL, arkade.OP_ECPAIRING, arkade.OP_ECMULSCALARVERIFY, arkade.OP_TWEAKVERIFY, arkade.OP_INSPECTINPUTPACKET:
		return true
	}
	return false
}

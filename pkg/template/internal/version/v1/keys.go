package v1

import (
	"fmt"
	"strings"
)

type keyRequirements uint8

const (
	serverKey keyRequirements = 1 << iota
	emulatorKey
	cosignerKey
)

func (t *Template) checkKeys(keys Keys) error {
	switch {
	case t.requiredKeys&serverKey != 0 && keys.Server == nil:
		return fmt.Errorf("%w: missing server key", ErrUnsupported)
	case t.requiredKeys&emulatorKey != 0 && keys.Emulator == nil:
		return fmt.Errorf("%w: missing emulator key", ErrUnsupported)
	case t.requiredKeys&cosignerKey != 0 && keys.Cosigner == nil:
		return fmt.Errorf("%w: missing cosigner key", ErrUnsupported)
	}
	return nil
}

// keysRequired records service placeholders while compiling. Construction builds
// the entire contract tree, including unselected leaves.
func keysRequired(def *Definition) keyRequirements {
	var required keyRequirements
	tokens := func(asm []string) {
		for _, tok := range asm {
			switch {
			case tok == "<SERVER_KEY>":
				required |= serverKey
			case tok == "<COSIGNER_KEY>":
				required |= cosignerKey
			case strings.HasPrefix(tok, "<EMULATOR_KEY:"):
				required |= emulatorKey
			}
		}
	}
	for _, fn := range def.Functions {
		if fn.Arkade != nil {
			tokens(fn.Arkade.Asm)
		}
		for _, leaf := range fn.Leaves {
			tokens(leaf.Asm)
		}
	}
	return required
}

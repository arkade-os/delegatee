package template

import (
	"github.com/arkade-os/delegatee/pkg/template/internal/abi"
)

// Field is a named, typed value: a constructor input, a struct field or a covenant input.
type Field = abi.Field

// Struct is a user-defined constructor type.
type Struct = abi.Struct

// WitnessItem is a stack item a leaf's spender provides; Injected signatures are added by someone else.
type WitnessItem = abi.WitnessItem

// Leaf is one tapscript of a function.
type Leaf = abi.Leaf

// Covenant is the emulator script a function runs, with its inputs in declaration order.
type Covenant = abi.Covenant

// Function is a spending path of a contract: its tapscript leaves and, optionally, a covenant.
type Function = abi.Function

// Definition is a contract as a compiler emits it, without metadata.
type Definition = abi.Definition

// Artifact is a parsed contract definition and its content id.
type Artifact = abi.Artifact

// ParseArtifact parses a compiler artifact, dropping its metadata, and derives its id.
func ParseArtifact(doc []byte) (*Artifact, error) { return abi.Parse(doc) }

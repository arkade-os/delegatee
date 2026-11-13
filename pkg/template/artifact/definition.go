package artifact

import (
	"maps"
	"slices"

	v1 "github.com/arkade-os/executor/pkg/template/artifact/internal/v1"
)

// ParseDefinitionV1 validates a v1 inline definition. Template versions select
// this interpretation explicitly rather than relying on a changing default.
func ParseDefinitionV1(value any) (*Definition, error) { return v1.ParseDefinition(value) }

// IsArrayType reports whether a type uses v1's bounded scalar-array syntax.
func IsArrayType(typ string) bool              { return v1.ArrayType.MatchString(typ) }
func sortedIDs[T any](m map[string]T) []string { return slices.Sorted(maps.Keys(m)) }

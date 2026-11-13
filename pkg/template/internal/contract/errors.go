package contract

import "errors"

var (
	// ErrNoCosigner marks a script naming COSIGNER_KEY when no cosigner key is given.
	ErrNoCosigner = errors.New("no cosigner key")
	// ErrBadTree marks a given taptree that does not decode or misses a declared leaf.
	ErrBadTree = errors.New("bad taptree")
	// ErrBadLeaf marks a leaf or covenant that does not assemble, is duplicated, or a definition
	// without leaves.
	ErrBadLeaf = errors.New("bad leaf")
)

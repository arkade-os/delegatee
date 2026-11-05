package jcs

import "errors"

var (
	// ErrInvalid marks a document this package refuses.
	ErrInvalid = errors.New("invalid json")
)

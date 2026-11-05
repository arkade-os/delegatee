package schema

import "errors"

var (
	// ErrInvalid marks a malformed template document.
	ErrInvalid = errors.New("invalid template")
)

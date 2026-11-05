package abi

import "errors"

var (
	// ErrInvalid marks a malformed compiler artifact.
	ErrInvalid = errors.New("invalid artifact")
)

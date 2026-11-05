package asm

import "errors"

var (
	// ErrBadExpression marks an expression a template may not run.
	ErrBadExpression = errors.New("bad expression")
	// ErrBadValue marks bytes that are not the canonical encoding of their type.
	ErrBadValue = errors.New("bad value")
)

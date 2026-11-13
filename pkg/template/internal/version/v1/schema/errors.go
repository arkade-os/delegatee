package schema

import "github.com/arkade-os/executor/pkg/template/internal/failure"

var (
	// ErrInvalid marks a malformed template document.
	ErrInvalid = failure.ErrInvalidTemplate
)

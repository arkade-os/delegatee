package v1

import "github.com/arkade-os/executor/pkg/template/internal/failure"

var (
	// ErrInvalid marks a malformed compiler artifact.
	ErrInvalid = failure.ErrInvalidArtifact
)

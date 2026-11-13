package v1

import (
	"github.com/arkade-os/executor/pkg/template/internal/failure"

	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/arkade-os/executor/pkg/template/internal/version/v1/schema"
)

var (
	ErrInvalidArtifact = artifact.ErrInvalid
	ErrInvalidTemplate = schema.ErrInvalid
	// ErrUnsupported marks a valid template that this package cannot run in the requested mode.
	ErrUnsupported = failure.ErrUnsupported
	// ErrInvalidVariables marks variables missing, extra or not in the canonical encoding of their
	// type.
	ErrInvalidVariables = failure.ErrInvalidVariables
	// ErrIneligible marks sources the template cannot spend as given.
	ErrIneligible = failure.ErrIneligible
	// ErrUnaffordable marks an ineligible source that fees or dust refuse, not a broken template.
	ErrUnaffordable = failure.ErrUnaffordable
	ErrNoMatch      = failure.ErrNoMatch
)

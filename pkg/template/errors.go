package template

import "errors"

var (
	// ErrInvalidArtifact marks a malformed compiler artifact.
	ErrInvalidArtifact = errors.New("invalid artifact")
	// ErrInvalidTemplate marks a malformed template document.
	ErrInvalidTemplate = errors.New("invalid template")
	// ErrUnsupported marks a valid template that this package cannot run in the requested mode.
	ErrUnsupported = errors.New("unsupported")
	// ErrInvalidVariables marks variables missing, extra or not in the canonical encoding of their type.
	ErrInvalidVariables = errors.New("invalid variables")
	// ErrIneligible marks sources the template cannot spend as given.
	ErrIneligible = errors.New("ineligible")
)

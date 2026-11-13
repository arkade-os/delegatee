// Package failure holds the error identities shared across packages.
package failure

import "errors"

var (
	ErrInvalidTemplate    = errors.New("invalid template")
	ErrUnsupported        = errors.New("unsupported")
	ErrInvalidVariables   = errors.New("invalid variables")
	ErrIneligible         = errors.New("ineligible")
	ErrUnaffordable       = errors.New("unaffordable")
	ErrNoMatch            = errors.New("transaction does not match the trigger")
	ErrUnsupportedVersion = errors.New("unsupported template version")

	ErrInvalidArtifact            = errors.New("invalid artifact")
	ErrUnsupportedArtifactVersion = errors.New("unsupported artifact version")
)

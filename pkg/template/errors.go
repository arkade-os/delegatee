package template

import (
	"errors"

	"github.com/arkade-os/delegatee/pkg/template/internal/abi"
	"github.com/arkade-os/delegatee/pkg/template/internal/schema"
)

var (
	// ErrInvalidArtifact marks a malformed compiler artifact.
	ErrInvalidArtifact = abi.ErrInvalid
	// ErrInvalidTemplate marks a malformed template document.
	ErrInvalidTemplate = schema.ErrInvalid
	// ErrUnsupported marks a valid template that this package cannot run in the requested mode.
	ErrUnsupported = errors.New("unsupported")
	// ErrInvalidVariables marks variables missing, extra or not in the canonical encoding of their type.
	ErrInvalidVariables = errors.New("invalid variables")
	// ErrIneligible marks sources the template cannot spend as given.
	ErrIneligible = errors.New("ineligible")
	// ErrUnaffordable marks an ineligible source that fees or dust refuse, not a broken template.
	ErrUnaffordable = errors.New("unaffordable")
	ErrNoMatch      = errors.New("transaction does not match the trigger")
)

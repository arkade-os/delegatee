package template

import (
	"errors"
	"fmt"

	"github.com/arkade-os/executor/pkg/template/artifact"
	"github.com/arkade-os/executor/pkg/template/internal/failure"
)

var (
	ErrInvalidArtifact    = artifact.ErrInvalid
	ErrInvalidTemplate    = failure.ErrInvalidTemplate
	ErrUnsupported        = failure.ErrUnsupported
	ErrInvalidVariables   = failure.ErrInvalidVariables
	ErrIneligible         = failure.ErrIneligible
	ErrUnaffordable       = failure.ErrUnaffordable
	ErrNoMatch            = failure.ErrNoMatch
	ErrUnsupportedVersion = failure.ErrUnsupportedVersion
)

// Error provides stable categories without requiring callers to parse its message.
// Path is a JSON Pointer when the decoder can identify a particular field.
// The original category remains available through errors.Is and errors.As.
type Error struct {
	Stage, Code, Path string
	Cause             error
}

// UnsupportedVersionError reports the exact unsupported discriminator.
type UnsupportedVersionError struct{ Version string }

func (e *Error) Error() string { return e.Stage + ": " + e.Cause.Error() }
func (e *Error) Unwrap() error { return e.Cause }

func (e *UnsupportedVersionError) Error() string {
	return fmt.Sprintf("unsupported template version %q", e.Version)
}

func (e *UnsupportedVersionError) Unwrap() error { return ErrUnsupportedVersion }

func diagnostic(stage string, kind error, message string) error {
	return wrap(stage, fmt.Errorf("%w: %s", kind, message))
}

func wrap(stage string, err error) error {
	if err == nil {
		return nil
	}
	e := &Error{Stage: stage, Code: "internal", Cause: err}
	for _, c := range []struct {
		err  error
		code string
	}{
		{ErrUnsupportedVersion, "unsupported_version"},
		{ErrInvalidArtifact, "invalid_artifact"},
		{ErrInvalidTemplate, "invalid_template"},
		{ErrInvalidVariables, "invalid_variables"},
		{ErrUnsupported, "unsupported"},
		{ErrUnaffordable, "unaffordable"},
		{ErrIneligible, "ineligible"},
		{ErrNoMatch, "no_match"},
	} {
		if errors.Is(err, c.err) {
			e.Code = c.code
			break
		}
	}
	var path interface{ JSONPointer() string }
	if errors.As(err, &path) {
		e.Path = path.JSONPointer()
	}
	return e
}

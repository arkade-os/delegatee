package registry

import "errors"

var (
	ErrInvalidDocument  = errors.New("invalid document")
	ErrArtifactNotFound = errors.New("artifact not found")
	ErrArtifactInUse    = errors.New("artifact in use")
	ErrCapReached       = errors.New("cap reached")
	ErrTemplateNotFound = errors.New("template not found")
	ErrTemplateInUse    = errors.New("template in use")
	ErrTemplateDisabled = errors.New("template disabled")
	ErrInvalidStatus    = errors.New("invalid status")
	ErrUnsupported      = errors.New("unsupported template")
)

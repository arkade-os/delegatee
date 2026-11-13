package delegation

import "errors"

var (
	ErrDelegationNotFound = errors.New("delegation not found")
	ErrInvalidArgs        = errors.New("invalid arguments")
	ErrStreamOnly         = errors.New(
		"a template with a trigger is run by a stream, not registered by clients",
	)
	ErrNoEncryptionKey = errors.New("template secrets need an encryption key")
	ErrCosignerKeyLeaf = errors.New("a template leaf may not name the cosigner key")
	ErrBlocked         = errors.New(
		"an operator cancelled this delegation: registering it again needs the operator to resume it",
	)
	ErrCapReached      = errors.New("cap reached")
	ErrNotActive       = errors.New("delegation is not active")
	ErrNotCancelled    = errors.New("delegation is not cancelled")
	ErrIneligible      = errors.New("the streamed output is not locked by the template")
	ErrNotStream       = errors.New("template has no trigger")
	ErrStreamNotFound  = errors.New("stream not found")
	ErrAttemptNotFound = errors.New("attempt not found")
	errAttemptState    = errors.New("attempt is not in that state")
	errNotOwned        = errors.New("coin is not the delegation's")
)

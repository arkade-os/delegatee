package packets

import "errors"

var (
	// ErrInvalidAdvertisement marks a malformed packet 5 body.
	ErrInvalidAdvertisement = errors.New("packets: invalid advertisement")
)

package publicip

import "errors"

var (
	// ErrNoIPDiscovered is returned when no IP could be discovered using any method
	ErrNoIPDiscovered = errors.New("no public IP could be discovered")
	// ErrUnsupportedMethod is returned when trying to use an unsupported discovery method
	ErrUnsupportedMethod = errors.New("unsupported discovery method")
	// ErrUnsupportedIPVersion is returned when the requested IP version is not supported
	ErrUnsupportedIPVersion = errors.New("unsupported IP version")
	// ErrTimeout is returned when the discovery process times out
	ErrTimeout = errors.New("discovery timed out")
)

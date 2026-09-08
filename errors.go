package publicip

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrNotFound reports that no public address could be discovered. Unwrap the
	// returned error (errors.Is) to test for it; a *DiscoveryError carries the
	// per-target detail.
	ErrNotFound = errors.New("no public IP could be discovered")

	// ErrTimeout reports that the caller's context ran out of time. It is wrapped
	// alongside ErrNotFound when a discovery call is cut short, so a caller can tell
	// "nothing answered" from "you did not give anything long enough to answer".
	ErrTimeout = errors.New("discovery timed out")

	// ErrUnsupportedMethod is returned by DiscoverWithMethod for a Method the client
	// has no discoverer for.
	ErrUnsupportedMethod = errors.New("unsupported discovery method")
)

// Failure records why one target did not produce an address.
type Failure struct {
	Method Method
	Target string // the server or endpoint that was tried
	Family string // "4" or "6"
	Err    error
}

// String renders the failure as one clause, for error messages and for the CLI's
// verbose output.
func (f Failure) String() string {
	return fmt.Sprintf("%s %s (ipv%s): %v", f.Method, f.target(), f.Family, f.Err)
}

func (f Failure) target() string {
	if f.Target == "" {
		return "<no target>"
	}
	return f.Target
}

// DiscoveryError is returned when a discovery call does not find an address. It wraps
// ErrNotFound (and ErrTimeout when the budget ran out) together with the error from
// every target that was tried, so the caller can see why each one failed instead of
// receiving a bare sentinel.
//
// Matching is done with errors.Is:
//
//	errors.Is(err, publicip.ErrNotFound)  // nothing was found
//	errors.Is(err, publicip.ErrTimeout)   // and time ran out doing it
type DiscoveryError struct {
	failures []Failure
	timedOut bool
}

// Error summarises the failure. Long cause lists are truncated to keep the message
// usable in a one-line CLI error; Failures has all of them.
func (e *DiscoveryError) Error() string {
	base := ErrNotFound.Error()
	if e.timedOut {
		base = base + " (the context deadline was reached)"
	}
	switch len(e.failures) {
	case 0:
		return base
	case 1:
		return fmt.Sprintf("%s: %s", base, e.failures[0])
	default:
		rest := len(e.failures) - 1
		return fmt.Sprintf("%s: %s (+%d more attempts)", base, e.failures[0], rest)
	}
}

// Unwrap lets errors.Is reach the sentinels and every underlying cause. The slice form
// requires Go 1.20 semantics, which the module's floor allows.
func (e *DiscoveryError) Unwrap() []error {
	out := make([]error, 0, len(e.failures)+2)
	out = append(out, ErrNotFound)
	if e.timedOut {
		out = append(out, ErrTimeout)
	}
	for _, f := range e.failures {
		if f.Err != nil {
			out = append(out, f.Err)
		}
	}
	return out
}

// Failures returns why each attempted target failed, in the order they were tried.
func (e *DiscoveryError) Failures() []Failure { return append([]Failure(nil), e.failures...) }

// TimedOut reports whether the caller's context ran out during the call.
func (e *DiscoveryError) TimedOut() bool { return e.timedOut }

// Detail renders every failure on its own line, for callers that want the whole picture
// rather than the one-line summary Error() gives - a CLI's verbose flag, or a log line
// when a user reports that discovery failed on their network.
func (e *DiscoveryError) Detail() string {
	var b strings.Builder
	for _, f := range e.failures {
		b.WriteString("  ")
		b.WriteString(f.String())
		b.WriteByte('\n')
	}
	return b.String()
}

// discoveryError builds the error for one finished discovery pass.
func discoveryError(ctx context.Context, failures []Failure) *DiscoveryError {
	return &DiscoveryError{failures: failures, timedOut: errors.Is(ctx.Err(), context.DeadlineExceeded)}
}

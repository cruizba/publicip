package publicip

import (
	"context"
	"time"
)

// attemptBudget reports how long a single network attempt is allowed to take, and
// whether there is any time left in ctx to make one at all.
//
// Config.RequestTimeout bounds one attempt, but a discovery run makes one attempt
// per server per address family. Applying RequestTimeout verbatim therefore lets
// the run outlive the caller's context, and a single slow attempt - typically an
// IPv6 dial to a server without an AAAA record - can consume the whole budget
// before IPv4, or another method, is ever tried. Clamping each attempt to the time
// that is actually left keeps the operation inside the deadline the caller asked
// for.
//
// A context cancelled without a deadline is only observed before an attempt
// starts: a read that is already blocked waits for its own deadline.
func attemptBudget(ctx context.Context, configured time.Duration) (time.Duration, bool) {
	if ctx.Err() != nil {
		return 0, false
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, false
		}
		if remaining < configured {
			return remaining, true
		}
	}
	return configured, true
}

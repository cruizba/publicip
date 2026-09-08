package publicip

import (
	"context"
	"time"
)

// attempt is one network try: a target plus the address family to force.
type attempt struct {
	target string
	family string // "4" or "6"
}

// attemptBudget reports how long the next attempt may take, and whether there is any
// time left in ctx to make one at all.
//
// Two rules bound an attempt. Config.RequestTimeout is the per-attempt ceiling the
// caller configured. attemptsLeft is the fair share of the time remaining in ctx:
// handing the entire remainder to whichever attempt runs first is what starved the
// rest of the list, so a single stalled server - typically one whose hostname has to
// be resolved, or one with no AAAA record on an IPv6 attempt - could consume a whole
// discovery run and leave every healthy server untried.
func attemptBudget(ctx context.Context, configured time.Duration, attemptsLeft int) (time.Duration, bool) {
	if ctx.Err() != nil {
		return 0, false
	}

	// configured <= 0 means the caller set no per-attempt ceiling, so only the context
	// and the fair share bound an attempt.
	budget := time.Duration(0)
	if configured > 0 {
		budget = configured
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, false
		}
		if attemptsLeft < 1 {
			attemptsLeft = 1
		}
		// remaining > 0 and attemptsLeft >= 1, so the share is always positive: a
		// further "is the budget still positive" check here could not fire.
		if share := remaining / time.Duration(attemptsLeft); budget == 0 || share < budget {
			budget = share
		}
	}
	if budget <= 0 {
		// Neither a deadline nor a ceiling: without some floor a black-holed server
		// would block forever, so the default attempt timeout applies.
		budget = defaultAttemptTimeout
	}
	return budget, true
}

// noBudgetError explains why an attempt was refused. It is the caller's cancellation,
// not a fabricated deadline, so a caller who gave up is not reported as having timed
// out.
func noBudgetError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// The deadline has passed but the context has not noticed yet; that is the only way
	// attemptBudget can refuse with a nil ctx.Err().
	return context.DeadlineExceeded
}

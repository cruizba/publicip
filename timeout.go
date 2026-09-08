package publicip

import (
	"context"
	"time"
)

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

// methodContext bounds one method of a multi-method call. The total budget belongs to
// the whole call, not to whichever method runs first, so each method in turn gets a fair
// share of what is left: without this, two black-holed methods could consume a cap of
// three seconds and leave the healthy third one never attempted.
//
// Two cases pass the context through unchanged, with a cancel that does nothing: a context
// without a deadline has nothing to divide, and a method that is the last one able to run
// already owns the whole remainder. Each method then runs to its own pace, bounded by
// attemptBudget.
//
// methodsLeft counts the current method plus those still to run, so the divisor is always
// at least two.
func methodContext(ctx context.Context, methodsLeft int) (context.Context, context.CancelFunc) {
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline || methodsLeft < 2 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, time.Until(deadline)/time.Duration(methodsLeft))
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

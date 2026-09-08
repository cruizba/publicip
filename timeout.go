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

// attemptPlan lists the attempts a discoverer makes for a target list, in the order
// v1 has always used them: every target over IPv6 first, then every target over IPv4.
// Listing them up front is what lets each attempt know how many of its siblings are
// still waiting.
func attemptPlan(targets []string, version IPVersion) []attempt {
	var families []string
	if version == Any || version == IPv6Only {
		families = append(families, "6")
	}
	if version == Any || version == IPv4Only {
		families = append(families, "4")
	}

	plan := make([]attempt, 0, len(families)*len(targets))
	for _, family := range families {
		for _, target := range targets {
			plan = append(plan, attempt{target: target, family: family})
		}
	}
	return plan
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

	budget := configured
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return 0, false
		}
		if attemptsLeft < 1 {
			attemptsLeft = 1
		}
		if share := remaining / time.Duration(attemptsLeft); share < budget {
			budget = share
		}
		if budget <= 0 {
			return 0, false
		}
	}
	return budget, true
}

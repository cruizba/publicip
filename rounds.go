package publicip

import (
	"context"
	"net"
	"sync"
	"time"
)

// attemptFunc performs one network try against one target under a deadline chosen by
// the round runner.
type attemptFunc func(ctx context.Context, target attempt, timeout time.Duration) (net.IP, error)

// attemptRounds groups targets into rounds that run concurrently, IPv6 first then IPv4.
//
// Families stay sequential because preferring IPv6 is observable behaviour: with both
// running at once, a fast IPv4 echo service would win on a dual-stack host and callers
// would silently get a different address than v1 returned. Within a family the attempts
// are concurrent, which is where the latency was: eight DNS servers in series meant
// eight timeouts before the first useful question was even asked.
func attemptRounds(targets []string, version IPVersion) [][]attempt {
	families := []string{"6", "4"}
	if version == IPv4Only {
		families = []string{"4"}
	}
	if version == IPv6Only {
		families = []string{"6"}
	}

	rounds := make([][]attempt, 0, len(families))
	for _, family := range families {
		round := make([]attempt, 0, len(targets))
		for _, target := range targets {
			round = append(round, attempt{target: target, family: family})
		}
		if len(round) > 0 {
			rounds = append(rounds, round)
		}
	}
	return rounds
}

// run executes a method's attempts: one concurrent round per family, each round bounded
// by a fair share of the time the call has left, so a round that stalls cannot starve
// the family behind it.
func (c *config) run(ctx context.Context, method Method, targets []string, version IPVersion, try attemptFunc) (Result, error) {
	rounds := attemptRounds(targets, version)
	var failures []Failure

	for i, round := range rounds {
		budget, ok := attemptBudget(ctx, c.attemptTimeout, len(rounds)-i)
		if !ok {
			c.logger.Debug("aborting: no time budget left", "method", string(method), "family", round[0].family)
			for _, target := range round {
				failures = append(failures, Failure{
					Method: method, Target: target.target, Family: target.family,
					Err: noBudgetError(ctx),
				})
			}
			break
		}

		ip, roundFailures := c.runRound(ctx, method, round, budget, try)
		if ip != nil {
			return Result{IP: ip, Method: method, Version: versionOf(ip)}, nil
		}
		failures = append(failures, roundFailures...)
	}

	c.logger.Debug("method exhausted", "attempts", len(failures))
	return Result{}, discoveryError(ctx, failures)
}

// runRound issues every attempt of a round at once and returns the first address that
// answers. The rest are cancelled: an unanswered STUN probe still holding a socket open
// after the answer arrived would be a leak, not a backup.
func (c *config) runRound(ctx context.Context, method Method, round []attempt, budget time.Duration, try attemptFunc) (net.IP, []Failure) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	type outcome struct {
		target attempt
		ip     net.IP
		err    error
	}

	results := make(chan outcome, len(round))
	var wg sync.WaitGroup
	for _, target := range round {
		wg.Add(1)
		go func(target attempt) {
			defer wg.Done()
			ip, err := try(ctx, target, budget)
			results <- outcome{target: target, ip: ip, err: err}
		}(target)
	}
	go func() { wg.Wait(); close(results) }()

	var failures []Failure
	for o := range results {
		if o.ip != nil {
			return o.ip, nil
		}
		err := o.err
		if err == nil {
			err = context.DeadlineExceeded
		}
		failures = append(failures, Failure{
			Method: method, Target: o.target.target, Family: o.target.family, Err: err,
		})
		c.logger.Debug("attempt failed", "method", string(method), "family", o.target.family, "target", o.target.target, "error", err)
	}
	return nil, failures
}

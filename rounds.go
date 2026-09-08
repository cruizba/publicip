package publicip

import (
	"context"
	"net"
	"sync"
	"time"
)

// round is one attempt: a target and the address family to force for it.
type round[T any] struct {
	target T
	family string // "4" or "6"
}

// identity describes a plain string target, which is what the STUN and HTTP lists hold.
func identity(target string) string { return target }

// attemptRounds groups targets into rounds that run concurrently, IPv6 first then IPv4.
//
// Families stay sequential because preferring IPv6 is observable behaviour: with both
// running at once, a fast IPv4 echo service would win on a dual-stack host and callers
// would silently get a different address than v1 returned. Within a family the attempts
// are concurrent, which is where the latency was: four DNS servers in series meant four
// timeouts before the first useful question was even asked.
func attemptRounds[T any](targets []T, version IPVersion) [][]round[T] {
	families := []string{"6", "4"}
	if version == IPv4Only {
		families = []string{"4"}
	}
	if version == IPv6Only {
		families = []string{"6"}
	}

	rounds := make([][]round[T], 0, len(families))
	for _, family := range families {
		r := make([]round[T], 0, len(targets))
		for _, target := range targets {
			r = append(r, round[T]{target: target, family: family})
		}
		if len(r) > 0 {
			rounds = append(rounds, r)
		}
	}
	return rounds
}

// run executes a method's attempts: one concurrent round per family, each round bounded
// by a fair share of the time the call has left, so a round that stalls cannot starve
// the family behind it.
//
// describe renders a target for the failure report, because "192.0.2.1:53" is only half
// of what a DNS service is.
//
// These are generic functions rather than methods on config because generic methods need
// Go 1.27, and the module's language floor is go 1.23.
func run[T any](
	cfg *config,
	ctx context.Context,
	method Method,
	targets []T,
	version IPVersion,
	try func(ctx context.Context, target T, family string, timeout time.Duration) (net.IP, error),
	describe func(target T) string,
) (Result, error) {
	rounds := attemptRounds(targets, version)
	var failures []Failure

	for i, r := range rounds {
		budget, ok := attemptBudget(ctx, cfg.attemptTimeout, len(rounds)-i)
		if !ok {
			cfg.logger.Debug("aborting: no time budget left", "method", string(method), "family", r[0].family)
			for _, target := range r {
				failures = append(failures, Failure{
					Method: method, Target: describe(target.target), Family: target.family,
					Err: noBudgetError(ctx),
				})
			}
			break
		}

		ip, roundFailures := runRound(cfg, ctx, method, r, budget, try, describe)
		if ip != nil {
			return Result{IP: ip, Method: method, Version: versionOf(ip)}, nil
		}
		failures = append(failures, roundFailures...)
	}

	cfg.logger.Debug("method exhausted", "method", string(method), "attempts", len(failures))
	return Result{}, discoveryError(ctx, failures)
}

// runRound issues every attempt of a round at once and returns the first address that
// answers. The rest are cancelled: an unanswered STUN probe still holding a socket open
// after the answer arrived would be a leak, not a backup.
func runRound[T any](
	cfg *config,
	ctx context.Context,
	method Method,
	r []round[T],
	budget time.Duration,
	try func(ctx context.Context, target T, family string, timeout time.Duration) (net.IP, error),
	describe func(target T) string,
) (net.IP, []Failure) {
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	type outcome struct {
		target round[T]
		ip     net.IP
		err    error
	}

	results := make(chan outcome, len(r))
	var wg sync.WaitGroup
	for _, target := range r {
		wg.Add(1)
		go func(target round[T]) {
			defer wg.Done()
			ip, err := try(ctx, target.target, target.family, budget)
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
			// A nil error with a nil address is a broken implementation, not a
			// success: report it as having found nothing.
			err = ErrNotFound
		}
		failures = append(failures, Failure{
			Method: method, Target: describe(o.target.target), Family: o.target.family, Err: err,
		})
		cfg.logger.Debug("attempt failed",
			"method", string(method), "family", o.target.family,
			"target", describe(o.target.target), "error", err)
	}
	return nil, failures
}

package publicip

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// attempt pairs a target with the family it was tried under, for test bookkeeping.
type attempt struct {
	target string
	family string // "4" or "6"
}

// stubAttempt is an attempt function a test controls: it records which targets ran and
// can answer, stall, or honour cancellation on demand.
type stubAttempt struct {
	mu        sync.Mutex
	ran       []attempt
	per       time.Duration
	answers   map[string]net.IP
	behaviour func(ctx context.Context, target, family string) (net.IP, error)
}

func (s *stubAttempt) call(ctx context.Context, target, family string, _ time.Duration) (net.IP, error) {
	s.mu.Lock()
	s.ran = append(s.ran, attempt{target: target, family: family})
	s.mu.Unlock()

	if s.behaviour != nil {
		return s.behaviour(ctx, target, family)
	}
	if s.per > 0 {
		select {
		case <-time.After(s.per):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if ip, ok := s.answers[family+":"+target]; ok {
		return ip, nil
	}
	return nil, errors.New("no answer")
}

func (s *stubAttempt) targets() []attempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]attempt(nil), s.ran...)
}

func cfgFor(opts ...Option) *config {
	cfg := defaultConfig()
	for _, o := range opts {
		o(&cfg)
	}
	return &cfg
}

func TestRoundRunsItsAttemptsConcurrently(t *testing.T) {
	// Three targets that each take 300 ms: serially that is 900 ms, concurrently about
	// one. This is the whole point of the change - v1 walked the list one server at a
	// time, so eight DNS servers meant eight timeouts.
	stub := &stubAttempt{per: 300 * time.Millisecond}
	cfg := cfgFor(WithAttemptTimeout(2 * time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	run(cfg, ctx, STUN, []string{"127.0.0.1:1", "127.0.0.2:1", "127.0.0.3:1"}, IPv4Only, stub.call, identity)
	elapsed := time.Since(start)

	if len(stub.targets()) != 3 {
		t.Fatalf("only %d attempts ran, want all 3", len(stub.targets()))
	}
	if elapsed > 800*time.Millisecond {
		t.Errorf("round took %v for three 300ms attempts, want the concurrent ~300ms", elapsed)
	}
}

func TestFirstAnswerCancelsTheRest(t *testing.T) {
	// A slow server must not keep a socket and a goroutine alive after the address is
	// already known: the losers must observe the cancellation, not run to their own
	// timeout.
	var running sync.WaitGroup
	running.Add(2)
	stub := &stubAttempt{behaviour: func(ctx context.Context, target, family string) (net.IP, error) {
		if target == "fast" {
			return net.ParseIP("203.0.113.5"), nil
		}
		<-ctx.Done()
		running.Done()
		return nil, ctx.Err()
	}}
	cfg := cfgFor()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := run(cfg, ctx, STUN, []string{"fast", "slow1", "slow2"}, IPv4Only, stub.call, identity)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if res.IP.String() != "203.0.113.5" {
		t.Errorf("run() = %v, want the fast answer", res.IP)
	}

	waited := make(chan struct{})
	go func() { running.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(2 * time.Second):
		t.Fatal("the losing attempts never saw the cancellation")
	}
}

func TestIPv6RoundWinsAndSkipsIPv4(t *testing.T) {
	stub := &stubAttempt{answers: map[string]net.IP{
		"6:v6": net.ParseIP("2001:db8::1"),
		"4:v4": net.ParseIP("203.0.113.9"),
	}}
	cfg := cfgFor()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Both names are offered to both families; the IPv6 round must be the one that
	// answers, and the IPv4 round must never start.
	res, err := run(cfg, ctx, DNS, []string{"v6", "v4"}, Any, stub.call, identity)
	if err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if res.Version != IPv6Only {
		t.Errorf("Result.Version = %v, want IPv6Only", res.Version)
	}
	for _, ran := range stub.targets() {
		if ran.family == "4" {
			t.Fatalf("the IPv4 round ran (%+v) even though IPv6 answered", ran)
		}
	}
}

func TestIPv4IsTriedWhenIPv6FailsEverywhere(t *testing.T) {
	stub := &stubAttempt{answers: map[string]net.IP{
		// Answered only over IPv4, the shape of api.ipify.org: no AAAA, so the IPv6
		// round has nothing to succeed with.
		"4:only-v4": net.ParseIP("198.51.100.20"),
	}}
	cfg := cfgFor(WithAttemptTimeout(time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := run(cfg, ctx, HTTP, []string{"only-v4"}, Any, stub.call, identity)
	if err != nil {
		t.Fatalf("run() error = %v (the IPv6 round failing must not abort the method)", err)
	}
	if res.IP.String() != "198.51.100.20" || res.Version != IPv4Only {
		t.Errorf("run() = %v (%v), want 198.51.100.20 as IPv4", res.IP, res.Version)
	}

	var saw6, saw4 bool
	for _, ran := range stub.targets() {
		switch ran.family {
		case "6":
			saw6 = true
		case "4":
			saw4 = true
		}
	}
	if !saw6 || !saw4 {
		t.Errorf("attempts = %v, want the target tried over both families", stub.targets())
	}
}

func TestRunReportsEveryFailedTarget(t *testing.T) {
	stub := &stubAttempt{}
	cfg := cfgFor(WithAttemptTimeout(time.Second))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := run(cfg, ctx, STUN, []string{"127.0.0.1:1", "127.0.0.2:1"}, Any, stub.call, identity)

	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatalf("want a *DiscoveryError, got %T", err)
	}
	// Two targets x two families.
	if len(de.Failures()) != 4 {
		t.Errorf("Failures() = %d, want 4 (two targets over each family)", len(de.Failures()))
	}
	for _, f := range de.Failures() {
		if f.Method != STUN || f.Err == nil {
			t.Errorf("failure %+v, want a STUN failure carrying an error", f)
		}
	}
}

func TestRunLeaksNoGoroutines(t *testing.T) {
	before := runtime.NumGoroutine()
	stub := &stubAttempt{per: 20 * time.Millisecond}
	cfg := cfgFor(WithAttemptTimeout(200 * time.Millisecond))

	for i := 0; i < 5; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		//nolint:errcheck // the outcome is not what this test asserts
		run(cfg, ctx, STUN, []string{"127.0.0.1:1", "127.0.0.2:1", "127.0.0.3:1"}, Any, stub.call, identity)
		cancel()
	}

	// Give the stragglers a moment, then require the count back near where it started.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && runtime.NumGoroutine() > before+5 {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before+5 {
		t.Errorf("goroutines went from %d to %d, want the round runners to be gone", before, after)
	}
}

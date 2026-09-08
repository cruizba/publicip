package publicip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// Tests for the v1.2.2 fix: Config.RequestTimeout bounds one attempt, but it must
// never outlive the caller's context. They are separated from the behavioural tests
// because they describe the fix, not the codec.

func TestSTUNExpiredContextStopsImmediately(t *testing.T) {
	// A silent server would take one read timeout per attempt if the discoverer
	// kept trying. The whole call must finish well inside a single attempt.
	addr := startStunServer(t, "udp4", silentServer)
	d := stunClient(addr, 10*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := d.Discover(ctx, IPv4Only)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	if elapsed > time.Second {
		t.Errorf("Discover() took %v with an already-cancelled context; it must not wait for the request timeout", elapsed)
	}
}

func TestSTUNAttemptNeverOutlivesContext(t *testing.T) {
	addr := startStunServer(t, "udp4", silentServer)
	d := stunClient(addr, time.Hour) // per-attempt timeout far beyond the context

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := d.Discover(ctx, IPv4Only)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Discover() took %v; the context deadline must bound the attempt, not RequestTimeout", elapsed)
	}
}

func TestSTUNNoBudgetLeftStopsBeforeDialing(t *testing.T) {
	dialed := make(chan struct{}, 1)
	addr := startStunServer(t, "udp4", func(conn *net.UDPConn, from *net.UDPAddr, req []byte) {
		select {
		case dialed <- struct{}{}:
		default:
		}
		answeringServer(net.IPv4(1, 1, 1, 1))(conn, from, req)
	})
	d := stunClient(addr, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(10 * time.Millisecond) // let the deadline pass

	if _, err := d.Discover(ctx, IPv4Only); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	select {
	case <-dialed:
		t.Error("a request reached the server even though the context had no budget left")
	default:
	}
}

func TestDNSAttemptBudget(t *testing.T) {
	d := dnsClient([]DNSServer{{Addr: "127.0.0.1:1", QueryName: dnsQueryName}}, time.Hour, nil)

	// An expired context must return before the configured per-attempt timeout.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := d.Discover(ctx, Any)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	if elapsed > 5*time.Second {
		t.Errorf("Discover() took %v; the context deadline must bound the attempt", elapsed)
	}
}

func TestHTTPTimeoutIsBoundedByContext(t *testing.T) {
	// A listener that accepts and never answers would otherwise hold the request
	// open for the whole configured timeout.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	hung := make(chan struct{})
	go func() {
		defer close(hung)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c // accepted, never answered
		}
	}()

	d := httpClient([]string{"http://" + ln.Addr().String()}, time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = d.Discover(ctx, IPv4Only)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("Discover() took %v; the context deadline must bound the attempt, not RequestTimeout", elapsed)
	}
}

func TestHTTPExpiredContextStopsBeforeRequest(t *testing.T) {
	srv := httptest.NewServer(stubIP("192.0.2.11"))
	defer srv.Close()

	d := httpClient([]string{srv.URL}, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	if _, err := d.Discover(ctx, IPv4Only); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Discover() took %v with an already-cancelled context", elapsed)
	}
}

// TestAttemptBudget covers the budgeting rules directly: the configured per-attempt
// ceiling, the clamp to the caller's deadline, the fair share between the attempts
// still waiting, and the two ways an attempt is refused outright.
func TestAttemptBudget(t *testing.T) {
	const configured = 5 * time.Second

	tests := []struct {
		name         string
		ctx          func() (context.Context, context.CancelFunc)
		configured   time.Duration
		attemptsLeft int
		wantBudget   time.Duration
		wantExact    bool
		wantOK       bool
	}{
		{
			name: "no deadline uses the configured timeout",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.Background(), func() {}
			},
			configured: configured, attemptsLeft: 8,
			wantBudget: configured, wantExact: true, wantOK: true,
		},
		{
			name: "deadline far away keeps the configured timeout",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Minute)
			},
			configured: configured, attemptsLeft: 8,
			wantBudget: configured, wantExact: true, wantOK: true,
		},
		{
			name: "fair share of the remainder when it is the tighter bound",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Second)
			},
			configured: configured, attemptsLeft: 4,
			wantBudget: 250 * time.Millisecond, wantExact: false, wantOK: true,
		},
		{
			name: "a single remaining attempt may use all of it",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Second)
			},
			configured: configured, attemptsLeft: 1,
			wantBudget: time.Second, wantExact: false, wantOK: true,
		},
		{
			name: "expired deadline is refused",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
				time.Sleep(10 * time.Millisecond)
				return ctx, cancel
			},
			configured: configured, attemptsLeft: 4,
			wantBudget: 0, wantOK: false,
		},
		{
			name: "cancelled context is refused",
			ctx: func() (context.Context, context.CancelFunc) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx, cancel
			},
			configured: configured, attemptsLeft: 4,
			wantBudget: 0, wantOK: false,
		},
		{
			// Zero now means "unset", so the internal floor applies instead of an
			// attempt that could block forever on a server that swallows packets.
			name: "unset ceiling falls back to the default attempt timeout",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.Background(), func() {}
			},
			configured: 0, attemptsLeft: 4,
			wantBudget: defaultAttemptTimeout, wantExact: true, wantOK: true,
		},
		{
			name: "unset ceiling still respects the fair share of a deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Second)
			},
			configured: 0, attemptsLeft: 4,
			wantBudget: 250 * time.Millisecond, wantExact: false, wantOK: true,
		},
		{
			// A caller that has already consumed its slot passes 0; dividing by it would
			// panic, so it is treated as a single remaining attempt.
			name: "zero attempts left is treated as one",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Second)
			},
			configured: 5 * time.Second, attemptsLeft: 0,
			wantBudget: time.Second, wantExact: false, wantOK: true,
		},
		{
			name: "negative attempts left is treated as one",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), time.Second)
			},
			configured: 0, attemptsLeft: -3,
			wantBudget: time.Second, wantExact: false, wantOK: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := tt.ctx()
			defer cancel()

			got, ok := attemptBudget(ctx, tt.configured, tt.attemptsLeft)
			if ok != tt.wantOK {
				t.Fatalf("attemptBudget() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				if got != 0 {
					t.Errorf("attemptBudget() = %v, want 0 when refused", got)
				}
				return
			}
			if tt.wantExact && got != tt.wantBudget {
				t.Errorf("attemptBudget() = %v, want exactly %v", got, tt.wantBudget)
				return
			}
			if !tt.wantExact {
				// The fair share is measured from the moment the call is made, so it
				// sits just under the ideal value but never above the bound.
				if got > tt.wantBudget {
					t.Errorf("attemptBudget() = %v, want at most %v", got, tt.wantBudget)
				}
				// Nine tenths, not a coin flip: the share is measured from the moment of
				// the call, so it sits just under the ideal, and a mutant that halves it
				// has to die here.
				if got < tt.wantBudget-tt.wantBudget/10 {
					t.Errorf("attemptBudget() = %v, want at least 90%% of %v", got, tt.wantBudget)
				}
			}
		})
	}
}

// staleDeadlineContext reports a deadline that has already passed while Err stays nil,
// which is the window between a context's deadline elapsing and its cancellation
// propagating. attemptBudget must refuse an attempt there rather than fall through to
// the default ceiling, and no real context can be timed to hit that window reliably, so
// the test supplies one.
type staleDeadlineContext struct {
	context.Context
}

func (staleDeadlineContext) Deadline() (time.Time, bool) {
	return time.Now().Add(-time.Second), true
}

func (staleDeadlineContext) Err() error { return nil }

func TestAttemptBudgetRefusesAStaleDeadline(t *testing.T) {
	ctx := staleDeadlineContext{Context: context.Background()}

	// Both shapes matter: an explicit ceiling and none at all. Without the guard, the
	// second one would fall through to defaultAttemptTimeout and dial anyway.
	for _, ceiling := range []time.Duration{5 * time.Second, 0} {
		if got, ok := attemptBudget(ctx, ceiling, 3); ok || got != 0 {
			t.Errorf("attemptBudget(ceiling=%v) = %v, %v; want 0, false", ceiling, got, ok)
		}
	}
}

// TestAttemptRoundsOrder pins the traversal: every target over IPv6 first, then IPv4.
// Callers cannot see the rounds, but reordering them changes which server answers, so it
// is a v2 decision rather than a v1 refactor.
func TestAttemptRoundsOrder(t *testing.T) {
	targets := []string{"a", "b", "c"}

	got := attemptRounds(targets, Any)
	want := [][]round[string]{
		{{"a", "6"}, {"b", "6"}, {"c", "6"}},
		{{"a", "4"}, {"b", "4"}, {"c", "4"}},
	}
	if len(got) != len(want) {
		t.Fatalf("attemptRounds(Any) = %d rounds, want %d: %v", len(got), len(want), got)
	}
	for r := range want {
		if len(got[r]) != len(want[r]) {
			t.Fatalf("round %d has %d attempts, want %d", r, len(got[r]), len(want[r]))
		}
		for i := range want[r] {
			if got[r][i] != want[r][i] {
				t.Errorf("attemptRounds(Any)[%d][%d] = %v, want %v", r, i, got[r][i], want[r][i])
			}
		}
	}

	if only6 := attemptRounds(targets, IPv6Only); len(only6) != 1 || only6[0][0].family != "6" {
		t.Errorf("attemptRounds(IPv6Only) = %v, want one round of family 6", only6)
	}
	if only4 := attemptRounds(targets, IPv4Only); len(only4) != 1 || only4[0][0].family != "4" {
		t.Errorf("attemptRounds(IPv4Only) = %v, want one round of family 4", only4)
	}
	if empty := attemptRounds[string](nil, Any); len(empty) != 0 {
		t.Errorf("attemptRounds(nil) = %v, want no rounds", empty)
	}
}

func TestClientStopsTryingWhenBudgetIsExhausted(t *testing.T) {
	var calls []string
	slow := blockingDiscoverer{name: STUN, calls: &calls}
	c := clientWith(map[Method]discoverer{
		STUN: slow,
		DNS:  fakeDiscoverer{name: DNS, err: errors.New("nope"), calls: &calls},
		HTTP: fakeDiscoverer{name: HTTP, err: errors.New("nope"), calls: &calls},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := c.Discover(ctx)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	// The blocking discoverer never returns before the deadline, so the call is
	// bounded by its own attempt timeout, which the fix clamps to the context.
	if elapsed > 5*time.Second {
		t.Errorf("Discover() took %v; a 150ms context must bound the run", elapsed)
	}
}

//
// blockingDiscoverer waits until the context is done, then reports the failure a
// real discoverer would report once its attempt is cut short.

type blockingDiscoverer struct {
	name  Method
	calls *[]string
}

func (b blockingDiscoverer) Discover(ctx context.Context, _ IPVersion) (Result, error) {
	if b.calls != nil {
		*b.calls = append(*b.calls, string(b.name))
	}
	<-ctx.Done()
	return Result{}, ctx.Err()
}

// TestSTUNSlowFirstServerStarvesTheRest is the shape of the remaining bug: with one
// attempt that burns the whole context, the healthy servers behind it never get
// dialed. attemptBudget clamps an attempt to the time left, which stops a single
// attempt from outliving the context, but it hands the *entire* remainder to the
// first server. A fair share of what is left is what makes the list traversal work.
func TestSTUNSlowFirstServerStarvesTheRest(t *testing.T) {
	// The first server accepts requests and never answers; the second answers well.
	slow := startStunServer(t, "udp4", silentServer)
	good := startStunServer(t, "udp4", answeringServer(net.IPv4(192, 0, 2, 99)))

	d := newSTUNDiscoverer(testConfig(WithSTUNServers(slow, good), attemptTimeout(time.Hour)))

	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()

	res, err := d.Discover(ctx, IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v; the second server was never given a chance because "+
			"the first attempt consumed the whole %v budget", err, 1200*time.Millisecond)
	}
	if got := res.IP.String(); got != "192.0.2.99" {
		t.Errorf("Discover() = %v, want 192.0.2.99", got)
	}
}

// TestMethodContextDividesWhatIsLeft pins the arithmetic of the per-method share: the
// division is over the time left when the method starts, so a method that finishes early
// hands its unused slice to the ones behind it.
func TestMethodContextDividesWhatIsLeft(t *testing.T) {
	tests := []struct {
		name        string
		parent      time.Duration // zero means a context with no deadline
		methodsLeft int
		wantShare   time.Duration // zero means the parent must pass through unchanged
	}{
		{
			name: "no deadline passes the parent through", parent: 0, methodsLeft: 3, wantShare: 0,
		},
		{
			name: "three methods each get a third", parent: 900 * time.Millisecond, methodsLeft: 3,
			wantShare: 300 * time.Millisecond,
		},
		{
			// The last method owns the whole remainder already, so it gets the parent
			// rather than a copy of its deadline truncated to the nanosecond.
			name: "the last method keeps the parent", parent: 900 * time.Millisecond, methodsLeft: 1,
			wantShare: 0,
		},
		{
			name: "nothing to divide for a count below two", parent: 600 * time.Millisecond, methodsLeft: 0,
			wantShare: 0,
		},
		{
			name: "a negative count divides nothing", parent: 600 * time.Millisecond, methodsLeft: -2,
			wantShare: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parent := context.Background()
			if tt.parent > 0 {
				ctx, cancel := context.WithTimeout(parent, tt.parent)
				defer cancel()
				parent = ctx
			}

			mctx, cancel := methodContext(parent, tt.methodsLeft)
			defer cancel()

			if tt.wantShare == 0 {
				if mctx != parent {
					t.Errorf("methodContext() = %v, want the parent context unchanged", mctx)
				}
				if _, ok := mctx.Deadline(); ok != (tt.parent > 0) {
					t.Errorf("methodContext() deadline = %v, want %v", ok, tt.parent > 0)
				}
				return
			}

			deadline, ok := mctx.Deadline()
			if !ok {
				t.Fatal("methodContext() = no deadline, want a share of the parent's")
			}
			parentDeadline, _ := parent.Deadline()
			share := time.Until(deadline)
			if share > tt.wantShare {
				t.Errorf("share = %v, want at most %v", share, tt.wantShare)
			}
			if share < tt.wantShare-tt.wantShare/10 {
				t.Errorf("share = %v, want at least 90%% of %v", share, tt.wantShare)
			}
			if deadline.After(parentDeadline) {
				t.Errorf("share ends at %v, past the parent deadline %v", deadline, parentDeadline)
			}
		})
	}
}

// TestGlobalCapReachesTheLastMethod is the corporate-network shape from issue 8: outbound
// UDP is black-holed, so STUN and DNS answer nothing and HTTP would answer at once. The
// cap is the budget of the whole call, and a method that consumes it before HTTP runs is
// a bug, not a timeout.
func TestGlobalCapReachesTheLastMethod(t *testing.T) {
	// The two black-holed discoverers return only when their context is done, so they
	// stand in for a server that swallows packets until the cap says otherwise.
	discoverers := map[Method]discoverer{
		STUN: blockingDiscoverer{name: STUN},
		DNS:  blockingDiscoverer{name: DNS},
		HTTP: fakeDiscoverer{name: HTTP, ip: "203.0.113.9"},
	}

	for _, tt := range []struct {
		name string
		opts []Option
		ctx  func() (context.Context, context.CancelFunc)
	}{
		{
			name: "caller context deadline",
			ctx: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 900*time.Millisecond)
			},
		},
		{
			name: "client side cap",
			opts: []Option{WithTimeout(900 * time.Millisecond)},
			ctx:  func() (context.Context, context.CancelFunc) { return context.Background(), func() {} },
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := clientWith(discoverers, tt.opts...)
			ctx, cancel := tt.ctx()
			defer cancel()

			start := time.Now()
			res, err := c.DiscoverWithIPVersion(ctx, IPv4Only)
			elapsed := time.Since(start)

			// Two methods burn their third each, so HTTP starts at ~600ms. Before the
			// cap was shared it never started at all.
			if err != nil {
				t.Fatalf("DiscoverWithIPVersion() error = %v, want the healthy method to answer", err)
			}
			if res.Method != HTTP {
				t.Errorf("method = %v, want http", res.Method)
			}
			if got := res.IP.String(); got != "203.0.113.9" {
				t.Errorf("IP = %v, want 203.0.113.9", got)
			}
			if elapsed > 900*time.Millisecond {
				t.Errorf("call took %v, past the 900ms cap", elapsed)
			}
		})
	}
}

// overrunDiscoverer ignores the context it is handed, which is what a custom source with
// an uncancelable call looks like. The client bounds each method with a share of the cap,
// but it cannot interrupt a discoverer that does not watch its context, so what it must
// still do is stop starting further methods once the cap has gone.
type overrunDiscoverer struct {
	name  Method
	calls *[]string
	delay time.Duration
}

func (o overrunDiscoverer) Discover(_ context.Context, _ IPVersion) (Result, error) {
	if o.calls != nil {
		*o.calls = append(*o.calls, string(o.name))
	}
	time.Sleep(o.delay)
	return Result{}, ErrNotFound
}

func TestCapExpiryStopsFurtherMethods(t *testing.T) {
	var calls []string
	c := clientWith(map[Method]discoverer{
		STUN: overrunDiscoverer{name: STUN, calls: &calls, delay: 300 * time.Millisecond},
		DNS:  fakeDiscoverer{name: DNS, err: ErrNotFound, calls: &calls},
		HTTP: fakeDiscoverer{name: HTTP, ip: "203.0.113.9", calls: &calls},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	_, err := c.DiscoverWithIPVersion(ctx, IPv4Only)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("DiscoverWithIPVersion() error = %v, want ErrNotFound", err)
	}
	if fmt.Sprint(calls) != "[stun]" {
		t.Errorf("methods run = %v, want [stun]: the cap expired during it", calls)
	}
}

// recordingDiscoverer hands back the context the client used for one method, so a test
// can see how that method's slice of the budget was bounded and released.
type recordingDiscoverer struct {
	name   Method
	ip     string
	captur *context.Context
}

func (r recordingDiscoverer) Discover(ctx context.Context, _ IPVersion) (Result, error) {
	if r.captur != nil {
		*r.captur = ctx
	}
	if r.ip == "" {
		return Result{}, ErrNotFound
	}
	return Result{IP: net.ParseIP(r.ip), Method: r.name, Version: versionOf(net.ParseIP(r.ip))}, nil
}

// TestUnusedSliceOfTheCapReachesTheLaterMethods pins the other half of the fair share: the
// division is over the time left when each method starts, so three black-holed methods
// together consume the cap they were given. Handing every method the same fraction of the
// *original* cap instead would return after roughly seven tenths of it with nothing tried.
func TestUnusedSliceOfTheCapReachesTheLaterMethods(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		discoverers map[Method]discoverer
		budget      time.Duration
	}{
		{
			name:   "three methods share the cap",
			budget: 1200 * time.Millisecond,
			discoverers: map[Method]discoverer{
				STUN: blockingDiscoverer{name: STUN},
				DNS:  blockingDiscoverer{name: DNS},
				HTTP: blockingDiscoverer{name: HTTP},
			},
		},
		{
			// A Method with no discoverer is skipped, so it must not be counted into the
			// division either: the time it never used would be lost for the others.
			name:        "an unconfigured method claims no share",
			opts:        []Option{WithMethods(Method("carrier-pigeon"), STUN, DNS)},
			budget:      1000 * time.Millisecond,
			discoverers: map[Method]discoverer{STUN: blockingDiscoverer{name: STUN}, DNS: blockingDiscoverer{name: DNS}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := clientWith(tt.discoverers, tt.opts...)

			ctx, cancel := context.WithTimeout(context.Background(), tt.budget)
			defer cancel()

			start := time.Now()
			_, err := c.DiscoverWithIPVersion(ctx, IPv4Only)
			elapsed := time.Since(start)

			if !errors.Is(err, ErrNotFound) || !errors.Is(err, ErrTimeout) {
				t.Fatalf("DiscoverWithIPVersion() error = %v, want both ErrNotFound and ErrTimeout", err)
			}
			if elapsed < tt.budget-tt.budget/6 {
				t.Errorf("call returned after %v, want at least five sixths of the %v cap used: "+
					"time a method did not need must reach the methods behind it", elapsed, tt.budget)
			}
			if elapsed > tt.budget+200*time.Millisecond {
				t.Errorf("call took %v, past the %v cap", elapsed, tt.budget)
			}
		})
	}
}

// TestMethodContextIsReleasedWhenTheMethodReturns: the sub-deadline exists only to bound
// one method, so the client must release it as soon as that method answers. Left attached,
// it would hold a timer on the caller's context for the rest of its share.
func TestMethodContextIsReleasedWhenTheMethodReturns(t *testing.T) {
	var captured context.Context
	c := clientWith(map[Method]discoverer{
		STUN: recordingDiscoverer{name: STUN, ip: "203.0.113.9", captur: &captured},
		DNS:  recordingDiscoverer{name: DNS},
		HTTP: recordingDiscoverer{name: HTTP},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if _, err := c.DiscoverWithIPVersion(ctx, IPv4Only); err != nil {
		t.Fatalf("DiscoverWithIPVersion() error = %v", err)
	}
	if captured == nil {
		t.Fatal("the discoverer never received a context")
	}
	if err := captured.Err(); !errors.Is(err, context.Canceled) {
		t.Errorf("method context after the call = %v, want context.Canceled: "+
			"the client released no slice of its budget", err)
	}
}

// TestTheLastMethodKeepsTheCallContext pins that a method with nobody behind it is not
// handed a truncated copy of the budget: it holds the call's own deadline, so the
// aggregated error reports the caller's expiry rather than one an invented share
// produced a microsecond earlier.
func TestTheLastMethodKeepsTheCallContext(t *testing.T) {
	var captured context.Context
	c := clientWith(map[Method]discoverer{
		STUN: recordingDiscoverer{name: STUN, captur: &captured},
	}, WithMethods(STUN))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if _, err := c.DiscoverWithIPVersion(ctx, IPv4Only); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DiscoverWithIPVersion() error = %v, want ErrNotFound", err)
	}
	if captured != ctx {
		t.Error("the only method received a derived context, want the call's own")
	}
}

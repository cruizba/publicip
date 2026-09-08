package publicip

import (
	"context"
	"errors"
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
	d := dnsClient([]string{"127.0.0.1:nothing"}, time.Hour)

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

func TestDNSExpiredContextStopsBeforeQuery(t *testing.T) {
	d := dnsClient([]string{"127.0.0.1:nothing"}, time.Hour)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := d.Discover(ctx, IPv4Only)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Discover() took %v with an already-cancelled context", elapsed)
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
				if got < tt.wantBudget/2 {
					t.Errorf("attemptBudget() = %v, want a share near %v", got, tt.wantBudget)
				}
			}
		})
	}
}

// TestAttemptPlanOrder pins the historical traversal: IPv6 across every target first,
// then IPv4. Callers cannot see the plan, but reordering it changes which server answers
// and is therefore a v2 decision, not a v1 refactor.
func TestAttemptPlanOrder(t *testing.T) {
	targets := []string{"a", "b", "c"}

	got := attemptPlan(targets, Any)
	want := []attempt{
		{"a", "6"}, {"b", "6"}, {"c", "6"},
		{"a", "4"}, {"b", "4"}, {"c", "4"},
	}
	if len(got) != len(want) {
		t.Fatalf("attemptPlan(Any) = %v, want %v entries", got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("attemptPlan(Any)[%d] = %v, want %v", i, got[i], want[i])
		}
	}

	if only6 := attemptPlan(targets, IPv6Only); len(only6) != 3 || only6[0].family != "6" {
		t.Errorf("attemptPlan(IPv6Only) = %v, want the three targets over family 6", only6)
	}
	if only4 := attemptPlan(targets, IPv4Only); len(only4) != 3 || only4[0].family != "4" {
		t.Errorf("attemptPlan(IPv4Only) = %v, want the three targets over family 4", only4)
	}
	if empty := attemptPlan(nil, Any); len(empty) != 0 {
		t.Errorf("attemptPlan(nil) = %v, want no attempts", empty)
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

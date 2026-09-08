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

	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
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

	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
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

	if _, err := d.Discover(ctx, IPv4Only); err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
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

	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
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
	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
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

	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
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
	if _, err := d.Discover(ctx, IPv4Only); err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Discover() took %v with an already-cancelled context", elapsed)
	}
}

func TestAttemptBudget(t *testing.T) {
	const configured = 5 * time.Second

	t.Run("no deadline uses the configured timeout", func(t *testing.T) {
		got, ok := attemptBudget(context.Background(), configured)
		if !ok || got != configured {
			t.Errorf("attemptBudget() = %v, %v; want %v, true", got, ok, configured)
		}
	})

	t.Run("long deadline keeps the configured timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		got, ok := attemptBudget(ctx, configured)
		if !ok || got != configured {
			t.Errorf("attemptBudget() = %v, %v; want %v, true", got, ok, configured)
		}
		if got < configured/2 {
			t.Errorf("attemptBudget() clamped %v well below the configured %v", got, configured)
		}
	})

	t.Run("short deadline clamps", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		got, ok := attemptBudget(ctx, configured)
		if !ok {
			t.Fatal("attemptBudget() reported no budget left")
		}
		if got >= configured {
			t.Errorf("attemptBudget() = %v, want it clamped below %v", got, configured)
		}
		if got <= 0 || got > 100*time.Millisecond {
			t.Errorf("attemptBudget() = %v, want it bounded by the remaining 100ms", got)
		}
	})

	t.Run("expired deadline reports no budget", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
		defer cancel()
		time.Sleep(10 * time.Millisecond)
		if got, ok := attemptBudget(ctx, configured); ok || got != 0 {
			t.Errorf("attemptBudget() = %v, %v; want 0, false", got, ok)
		}
	})

	t.Run("cancelled context reports no budget", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if got, ok := attemptBudget(ctx, configured); ok || got != 0 {
			t.Errorf("attemptBudget() = %v, %v; want 0, false", got, ok)
		}
	})

	t.Run("zero configured timeout is passed through", func(t *testing.T) {
		got, ok := attemptBudget(context.Background(), 0)
		if !ok || got != 0 {
			t.Errorf("attemptBudget() = %v, %v; want 0, true", got, ok)
		}
	})
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

	if err != ErrNoIPDiscovered {
		t.Fatalf("Discover() error = %v, want ErrNoIPDiscovered", err)
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

func (b blockingDiscoverer) Discover(ctx context.Context, _ IPVersion) (net.IP, error) {
	if b.calls != nil {
		*b.calls = append(*b.calls, string(b.name))
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

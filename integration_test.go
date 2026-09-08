//go:build integration

// This file is excluded from the unit suite on purpose. Everything in it contacts the
// shipped public services, which is the only way to learn that a STUN server was
// decommissioned, that a DNS query name stopped answering, or that the IPv6 paths are
// broken on a real dual-stack host. Those are the failures a loopback fixture cannot
// see, and they are also why the unit tests are held to a strict no-egress rule: the
// fast suite must never depend on somebody else's uptime.
//
// Run it with:
//
//	go test -tags integration -v ./...
//
// and on a host with a routable IPv6 address, which is the only place the v6 assertions
// below are more than a skip.
package publicip

import (
	"context"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

// ipv6Available reports whether the host can actually reach the outside over IPv6. The
// check asks a real endpoint rather than trusting that a ::1 loopback exists, because a
// container with loopback and no route is exactly the shape that would make a skipped
// test look like a passing one.
func ipv6Available(t *testing.T) bool {
	t.Helper()

	var hasRoutable bool
	addrs, err := net.Interfaces()
	if err != nil {
		t.Logf("interfaces: %v", err)
		return false
	}
	for _, iface := range addrs {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			t.Logf("%s: addrs: %v", iface.Name, err)
			continue
		}
		for _, addr := range ifaceAddrs {
			ip, _, _ := net.ParseCIDR(addr.String())
			if ip.To4() == nil && !ip.IsLinkLocalUnicast() {
				hasRoutable = true
			}
		}
	}
	if !hasRoutable {
		return false
	}

	// And confirm with a probe, because an address is not a route.
	d := New(WithSTUNServers("stun.l.google.com:19302"), WithAttemptTimeout(5*time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	res, err := d.DiscoverWithIPVersion(ctx, IPv6Only)
	if err != nil {
		t.Logf("IPv6 probe failed (%v); treating the host as single-stack", err)
		return false
	}
	t.Logf("IPv6 probe reached %s", res.IP)
	return true
}

func testLogger() *slog.Logger {
	if os.Getenv("PUBLICIP_INTEGRATION_LOG") == "" {
		return nil
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestIntegrationDefaultDiscovery(t *testing.T) {
	c := New(WithLogger(testLogger()))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := c.Discover(ctx)
	if err != nil {
		var de *DiscoveryError
		if ok := asDiscovery(err, &de); ok {
			t.Logf("failures:\n%s", de.Detail())
		}
		t.Fatalf("Discover() error = %v", err)
	}
	t.Logf("discovered %s", res)

	if res.IP == nil || res.IP.String() == "" {
		t.Fatal("empty address")
	}
	if res.Method == "" {
		t.Error("Result.Method is empty, want the method that answered")
	}
	if res.Version != IPv4Only && res.Version != IPv6Only {
		t.Errorf("Result.Version = %v, want a concrete family", res.Version)
	}
	if (res.Version == IPv6Only) != (res.IP.To4() == nil) {
		t.Errorf("Result.Version %v disagrees with the address %s", res.Version, res.IP)
	}
}

func TestIntegrationEachMethodAnswers(t *testing.T) {
	// Every shipped method must work on its own: a dead server list is a maintenance
	// bug that looks like a network problem from the outside.
	for _, method := range []Method{STUN, DNS, HTTP} {
		t.Run(string(method), func(t *testing.T) {
			c := New(WithLogger(testLogger()))

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			res, err := c.DiscoverWithMethod(ctx, method, IPv4Only)
			if err != nil {
				var de *DiscoveryError
				if asDiscovery(err, &de) {
					t.Logf("attempts:\n%s", de.Detail())
				}
				t.Fatalf("DiscoverWithMethod(%s) error = %v", method, err)
			}
			t.Logf("%s answered %s", method, res.IP)

			if res.Method != method {
				t.Errorf("Result.Method = %q, want %q", res.Method, method)
			}
			if res.Version != IPv4Only {
				t.Errorf("Result.Version = %v, want IPv4Only", res.Version)
			}
		})
	}
}

func TestIntegrationIPv6Paths(t *testing.T) {
	if !ipv6Available(t) {
		t.Skip("no routable IPv6 on this host; run the suite on a dual-stack machine")
	}

	// Each method over IPv6 specifically. A server without an AAAA record is expected to
	// fail over rather than answer, so only the aggregate is required to succeed.
	c := New(WithLogger(testLogger()))
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	res, err := c.DiscoverWithIPVersion(ctx, IPv6Only)
	if err != nil {
		var de *DiscoveryError
		if asDiscovery(err, &de) {
			t.Logf("attempts:\n%s", de.Detail())
		}
		t.Fatalf("DiscoverWithIPVersion(IPv6Only) error = %v", err)
	}
	if res.IP.To4() != nil {
		t.Fatalf("got an IPv4 address %s over an IPv6 request", res.IP)
	}
	t.Logf("IPv6 discovery reached %s via %s", res.IP, res.Method)
}

func TestIntegrationBudgetIsRespected(t *testing.T) {
	// The regression that started v1.2.3: one stalled server must not be able to
	// consume the whole call. A budget of two seconds has to produce an answer or a
	// failure inside about two seconds, never after twenty attempts of five.
	c := New()

	for _, budget := range []time.Duration{2 * time.Second, 5 * time.Second} {
		ctx, cancel := context.WithTimeout(context.Background(), budget)
		start := time.Now()
		_, err := c.DiscoverWithIPVersion(ctx, Any)
		elapsed := time.Since(start)
		cancel()

		overhead := 2 * time.Second
		if elapsed > budget+overhead {
			t.Errorf("budget %v took %v (err %v), want it bounded within the budget + %v",
				budget, elapsed, err, overhead)
		}
		t.Logf("budget %v finished in %v (err %v)", budget, elapsed.Round(time.Millisecond), err)
	}
}

func asDiscovery(err error, target **DiscoveryError) bool {
	for err != nil {
		if de, ok := err.(*DiscoveryError); ok {
			*target = de
			return true
		}
		un, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = un.Unwrap()
	}
	return false
}

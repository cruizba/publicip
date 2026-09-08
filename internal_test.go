package publicip

import (
	"context"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Unit tests for the unexported per-attempt helpers. They call the helpers
// directly because that is the only way to drive the address-family guard and the
// config-format guard without depending on which families the runner happens to
// have routed. As such they belong with the fix commit: the helpers take the
// clamped per-attempt timeout as an argument.

func TestDNSQueryErrorWrapsLookupFailure(t *testing.T) {
	d := dnsClient(nil, time.Second)

	_, err := d.tryQuery(context.Background(), attempt{target: "127.0.0.1", family: "4"}, time.Second)
	if err == nil || !strings.Contains(err.Error(), "expected server:domain") {
		t.Fatalf("tryQuery() error = %v, want the format error", err)
	}

	// 127.0.0.53 is the systemd-resolved stub address: dialing it is local and
	// never reaches a resolver, so the lookup fails without sending a DNS query.
	_, err = d.tryQuery(context.Background(), attempt{target: "127.0.0.53:my.query", family: "4"}, 250*time.Millisecond) // hermetic:allow
	if err == nil || !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Fatalf("tryQuery() error = %v, want a wrapped lookup failure", err)
	}
}

func TestHTTPEnforcesRequestedAddressFamily(t *testing.T) {
	// An IPv6 answer must not be reported when IPv4 was requested, and vice versa.
	v4Listener := httptest.NewServer(stubIP("2001:db8::1\n"))
	defer v4Listener.Close()

	d := httpClient(nil, 2*time.Second)
	if _, err := d.tryProtocol(context.Background(), attempt{target: v4Listener.URL, family: "4"}, time.Second); err == nil ||
		!strings.Contains(err.Error(), "IP version mismatch") {
		t.Errorf("tryProtocol(tcp4) with an IPv6 body: error = %v, want an address-family mismatch", err)
	}

	v6ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback on this host: %v", err)
	}
	srv := httptest.NewUnstartedServer(stubIP("203.0.113.8\n"))
	srv.Listener.Close()
	srv.Listener = v6ln
	srv.Start()
	defer srv.Close()

	if _, err := d.tryProtocol(context.Background(), attempt{target: srv.URL, family: "6"}, time.Second); err == nil ||
		!strings.Contains(err.Error(), "IP version mismatch") {
		t.Errorf("tryProtocol(tcp6) with an IPv4 body: error = %v, want an address-family mismatch", err)
	}
}

// TestHTTPStatusIsNotChecked documents v1 behaviour: any 2xx or 4xx body that
// parses as an IP is accepted. v2 is where this gets tightened, because changing
// it now would alter results for callers relying on lenient endpoints.

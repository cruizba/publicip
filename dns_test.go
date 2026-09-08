package publicip

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// dnsQueryName is a single-label name on purpose: the fixtures below are answered by a
// loopback fake, and the hermetic guard flags dotted names because those are what leak
// real DNS queries.

func dnsClient(servers []DNSServer, timeout time.Duration, lookup lookupFunc) *dnsDiscoverer {
	opts := []Option{WithDNSServers(servers...), attemptTimeout(timeout)}
	if lookup != nil {
		opts = append(opts, withLookup(lookup))
	}
	return newDNSDiscoverer(testConfig(opts...))
}

// --- DNSServer address handling --------------------------------------------

func TestDNSServerResolverDefaultsToPort53(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"bare hostname", "resolver.example", "resolver.example:53"}, // hermetic:allow
		{"ipv4 literal", "192.0.2.1", "192.0.2.1:53"},
		{"explicit port wins", "127.0.0.1:5300", "127.0.0.1:5300"},
		{"ipv6 literal", "2001:db8::1", "[2001:db8::1]:53"},
		{"ipv6 literal with port", "[2001:db8::1]:5300", "[2001:db8::1]:5300"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (DNSServer{Addr: tt.addr}).resolver(); got != tt.want {
				t.Errorf("resolver() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDNSServerString(t *testing.T) {
	got := DNSServer{Addr: "127.0.0.1:5300", QueryName: dnsQueryName}.String()
	if got != "127.0.0.1:5300 "+dnsQueryName {
		t.Errorf("String() = %q, want the resolver and the query name", got)
	}
	if got := (DNSServer{}).String(); got != "<empty DNS server>" {
		t.Errorf("String() of the zero value = %q", got)
	}
}

func TestDefaultDNSServersAreWellFormed(t *testing.T) {
	// Reads the shipped list without dialing: every entry needs both halves.
	for _, server := range defaultDNSServers {
		if server.Addr == "" || server.QueryName == "" {
			t.Errorf("default DNS server %+v is missing an address or a query name", server)
		}
	}
}

// --- tryQuery, with the lookup stubbed --------------------------------------

func TestDNSRejectsIncompleteServers(t *testing.T) {
	tests := []struct {
		name   string
		server DNSServer
	}{
		{"no address", DNSServer{QueryName: dnsQueryName}},
		{"no query name", DNSServer{Addr: "127.0.0.1:5300"}},
		{"both empty", DNSServer{}},
	}

	d := dnsClient(nil, time.Second, nil)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.tryQuery(context.Background(), tt.server, "4", time.Second)
			if err == nil || !strings.Contains(err.Error(), "both an address and a query name") {
				t.Errorf("tryQuery() error = %v, want the completeness error", err)
			}
		})
	}
}

func TestTryQueryUsesTheLookupResult(t *testing.T) {
	stub := func(ctx context.Context, network, resolver, name string) ([]string, error) {
		return []string{"203.0.113.77", "ignored-second-answer"}, nil
	}
	d := dnsClient([]DNSServer{{Addr: "127.0.0.1:5300", QueryName: dnsQueryName}}, time.Second, stub)

	ip, err := d.tryQuery(context.Background(), d.cfg.dnsServers[0], "4", time.Second)
	if err != nil {
		t.Fatalf("tryQuery() error = %v", err)
	}
	if got := ip.String(); got != "203.0.113.77" {
		t.Errorf("tryQuery() = %v, want the first answer", got)
	}
}

func TestTryQueryPropagatesLookupFailure(t *testing.T) {
	boom := errors.New("server misbehaving")
	d := dnsClient(nil, time.Second, func(context.Context, string, string, string) ([]string, error) {
		return nil, boom
	})

	_, err := d.tryQuery(context.Background(), DNSServer{Addr: "127.0.0.1:5300", QueryName: dnsQueryName}, "4", time.Second)
	if !errors.Is(err, boom) {
		t.Errorf("tryQuery() error = %v, want it to wrap the lookup failure", err)
	}
	if !strings.Contains(err.Error(), "DNS lookup failed") {
		t.Errorf("tryQuery() error = %q, want it to say which stage failed", err)
	}
}

func TestTryQueryHandlesEmptyAndGarbageAnswers(t *testing.T) {
	tests := []struct {
		name    string
		answers []string
		wantErr string
	}{
		{"no records", nil, "no IPs returned"},
		{"not an address", []string{"gateway.example"}, "invalid IP received"}, // hermetic:allow
		{"v6 asked, v4 answered", []string{"203.0.113.1"}, "IP version mismatch"},
		{"v4 asked, v6 answered", []string{"2001:db8::1"}, "IP version mismatch"},
	}

	for _, tt := range tests {
		for _, family := range familiesForError(tt.name) {
			t.Run(tt.name+"/"+family, func(t *testing.T) {
				answers := tt.answers
				d := dnsClient(nil, time.Second, func(context.Context, string, string, string) ([]string, error) {
					return answers, nil
				})
				_, err := d.tryQuery(context.Background(), DNSServer{
					Addr: "127.0.0.1:5300", QueryName: dnsQueryName,
				}, family, time.Second)
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("tryQuery() error = %v, want it to mention %q", err, tt.wantErr)
				}
			})
		}
	}
}

// familiesForError maps each fixture above onto the families it should be tested with.
func familiesForError(name string) []string {
	switch name {
	case "v6 asked, v4 answered":
		return []string{"6"}
	case "v4 asked, v6 answered":
		return []string{"4"}
	default:
		return []string{"4"}
	}
}

// --- the real resolver, against a loopback DNS server -----------------------

func TestSystemLookupAgainstFakeResolver(t *testing.T) {
	// This is the path v1 could never test: systemLookup dials the resolver address from
	// the config, and in v1 that address always ended in :53.
	addr := startFakeDNS(t, map[string][]net.IP{
		dnsQueryName: {net.ParseIP("198.51.100.44")},
	})

	ips, err := systemLookup(context.Background(), "udp4", addr, dnsQueryName)
	if err != nil {
		t.Fatalf("systemLookup() error = %v", err)
	}
	if len(ips) != 1 || ips[0] != "198.51.100.44" {
		t.Errorf("systemLookup() = %v, want [198.51.100.44]", ips)
	}
}

func TestSystemLookupTimesOutWhenNobodyAnswers(t *testing.T) {
	// A listener that accepts datagrams and never replies: the deadline has to come from
	// the context, not from any per-attempt default.
	ln, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, err := systemLookup(ctx, "udp4", ln.LocalAddr().String(), dnsQueryName); err == nil {
		t.Fatal("systemLookup() = nil error, want a timeout")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("systemLookup() took %v, want it bounded by the 200ms context", elapsed)
	}
}

func TestDNSDiscoverOverRealResolver(t *testing.T) {
	// One listener per family: the answers a resolver gives depend on the record asked
	// for, and the family that can be reached depends on the socket it listens on.
	v4 := startFakeDNSOn(t, "udp", net.IPv4(127, 0, 0, 1), map[string][]net.IP{
		dnsQueryName: {net.ParseIP("203.0.113.5")},
	})
	v6 := startFakeDNSOn(t, "udp6", net.IPv6loopback, map[string][]net.IP{
		dnsQueryName: {net.ParseIP("2001:db8::5")},
	})

	tests := []struct {
		name    string
		servers []DNSServer
		version IPVersion
		want    string
	}{
		{
			name:    "ipv4 asked",
			servers: []DNSServer{{Addr: v4, QueryName: dnsQueryName}},
			version: IPv4Only,
			want:    "203.0.113.5",
		},
		{
			name:    "ipv6 asked",
			servers: []DNSServer{{Addr: v6, QueryName: dnsQueryName}},
			version: IPv6Only,
			want:    "2001:db8::5",
		},
		{
			// Any tries IPv6 first, so the v6 listener wins although both would answer.
			name:    "any prefers ipv6",
			servers: []DNSServer{{Addr: v4, QueryName: dnsQueryName}, {Addr: v6, QueryName: dnsQueryName}},
			version: Any,
			want:    "2001:db8::5",
		},
		{
			// The v6 listener cannot answer an IPv4 attempt, so the other server must.
			name:    "any falls back when only one family is reachable",
			servers: []DNSServer{{Addr: v6, QueryName: dnsQueryName}, {Addr: v4, QueryName: dnsQueryName}},
			version: IPv4Only,
			want:    "203.0.113.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := dnsClient(tt.servers, 3*time.Second, nil)
			res, err := d.Discover(context.Background(), tt.version)
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if got := res.IP.String(); got != tt.want {
				t.Errorf("Discover() = %v, want %s", got, tt.want)
			}
			if res.Method != DNS {
				t.Errorf("Result.Method = %q, want dns", res.Method)
			}
			wantVersion := IPv4Only
			if strings.HasPrefix(tt.want, "2001") {
				wantVersion = IPv6Only
			}
			if res.Version != wantVersion {
				t.Errorf("Result.Version = %v, want %v", res.Version, wantVersion)
			}
		})
	}
}

func TestDNSDiscoverFallsThroughServerList(t *testing.T) {
	empty := startFakeDNS(t, map[string][]net.IP{}) // answers NOERROR/nothing
	good := startFakeDNS(t, map[string][]net.IP{
		dnsQueryName: {net.ParseIP("192.0.2.66")},
	})

	d := dnsClient([]DNSServer{
		{Addr: empty, QueryName: dnsQueryName},
		{Addr: "127.0.0.1:1", QueryName: dnsQueryName}, // nothing listening
		{Addr: good, QueryName: dnsQueryName},
	}, 3*time.Second, nil)

	res, err := d.Discover(context.Background(), IPv4Only)
	if err != nil {
		t.Fatalf("Discover() error = %v (the third server should have answered)", err)
	}
	if got := res.IP.String(); got != "192.0.2.66" {
		t.Errorf("Discover() = %v, want the third server's answer", got)
	}
}

func TestDNSDiscoverReportsEveryFailedServer(t *testing.T) {
	empty := startFakeDNS(t, map[string][]net.IP{})
	d := dnsClient([]DNSServer{
		{Addr: empty, QueryName: dnsQueryName},
		{Addr: "127.0.0.1:1", QueryName: dnsQueryName},
	}, time.Second, nil)

	_, err := d.Discover(context.Background(), IPv4Only)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Discover() error = %v, want ErrNotFound", err)
	}

	var de *DiscoveryError
	if !errors.As(err, &de) {
		t.Fatal("want a *DiscoveryError")
	}
	if len(de.Failures()) != 2 {
		t.Errorf("Failures() = %d, want one per server: %v", len(de.Failures()), de.Failures())
	}
	for _, f := range de.Failures() {
		if f.Method != DNS || f.Family != "4" {
			t.Errorf("failure %+v, want a DNS IPv4 failure", f)
		}
		if !strings.Contains(f.Target, dnsQueryName) {
			t.Errorf("failure target %q, want it to name the query as well as the resolver", f.Target)
		}
	}
}

func TestDNSExpiredContextStopsBeforeQuery(t *testing.T) {
	d := dnsClient([]DNSServer{{Addr: "127.0.0.1:1", QueryName: dnsQueryName}}, time.Hour, nil)

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

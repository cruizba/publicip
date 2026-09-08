package publicip_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	publicip "github.com/cruizba/publicip/v2"
)

// These examples are the README's snippets, compiled by the same go build that checks
// the library. A README that no tool verifies is how v1 ended up documenting
// Discover(ctx, Any) — a signature that never existed.

// stub answers with a fixed address so the examples stay runnable offline.
type stub struct {
	ip     string
	method publicip.Method
}

func (s stub) Discover(context.Context, publicip.IPVersion) (publicip.Result, error) {
	ip := net.ParseIP(s.ip)
	family := publicip.IPv6Only
	if ip.To4() != nil {
		family = publicip.IPv4Only
	}
	return publicip.Result{IP: ip, Method: s.method, Version: family}, nil
}

// Example is the README's entry point. hermetic:allow — see the note on the family
// example: the only discoverer is a stub.
func Example() {
	client := publicip.New(publicip.WithMethod("example", stub{ip: "203.0.113.9", method: "example"}),
		publicip.WithMethods("example"))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.Discover(ctx)
	if err != nil {
		return
	}

	fmt.Println(result.IP)
	fmt.Println(result)
	// Output:
	// 203.0.113.9
	// 203.0.113.9 (example/ipv4)
}

// ExampleClient_DiscoverWithIPVersion shows a family request. hermetic:allow — the
// client only has the stub method registered, so nothing can reach the shipped
// defaults.
func ExampleClient_DiscoverWithIPVersion() {
	client := publicip.New(publicip.WithMethod("example", stub{ip: "2001:db8::1", method: "example"}),
		publicip.WithMethods("example"))

	v6, err := client.DiscoverWithIPVersion(context.Background(), publicip.IPv6Only)
	if err != nil {
		return
	}
	fmt.Println("only IPv6 is honoured:", v6.IP)
	// Output:
	// only IPv6 is honoured: 2001:db8::1
}

func ExampleNew_options() {
	// Every knob is an option; a call with no options is the documented default.
	client := publicip.New(
		publicip.WithMethods(publicip.HTTP, publicip.DNS),
		publicip.WithSTUNServers("192.0.2.1:3478"),
		publicip.WithDNSServers(publicip.DNSServer{Addr: "192.0.2.53", QueryName: "1.2.3.4"}),
		publicip.WithHTTPEndpoints("https://203.0.113.9/ip"),
		publicip.WithAttemptTimeout(2*time.Second),
		publicip.WithTimeout(5*time.Second),
		publicip.WithLogger(slog.New(slog.NewTextHandler(discard{}, nil))),
	)

	fmt.Println("methods:", client.ConfiguredMethods())
	// Output:
	// methods: [http dns]
}

// ExampleDiscoveryError shows the failure report. hermetic:allow — the failing
// discoverer is the stub below, so no endpoint is contacted.
func ExampleDiscoveryError() {
	client := publicip.New(publicip.WithMethod("example", failingStub{}),
		publicip.WithMethods("example"))

	_, err := client.Discover(context.Background())
	if errors.Is(err, publicip.ErrNotFound) {
		var de *publicip.DiscoveryError
		if errors.As(err, &de) {
			for _, f := range de.Failures() {
				fmt.Printf("%s %s (ipv%s): %v\n", f.Method, f.Target, f.Family, f.Err)
			}
			fmt.Println("timed out:", de.TimedOut())
		}
	}
	// Output:
	// example 192.0.2.1:3478 (ipv6): no route to host
	// example 192.0.2.1:3478 (ipv4): no route to host
	// timed out: false
}

type failingStub struct{}

func (failingStub) Discover(context.Context, publicip.IPVersion) (publicip.Result, error) {
	return publicip.Result{}, publicip.NewDiscoveryError([]publicip.Failure{{
		Method: "example", Target: "192.0.2.1:3478", Family: "6", Err: errors.New("no route to host"),
	}, {
		Method: "example", Target: "192.0.2.1:3478", Family: "4", Err: errors.New("no route to host"),
	}}, false)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

# publicip

A small, dependency-free Go library (and CLI) for discovering your public IP address
over **STUN**, **DNS** and **HTTP**.

- Three independent methods, so a firewalled UDP port or a dead echo service does not
  break discovery.
- IPv4 and IPv6, with the family you asked for actually enforced.
- Every answer says how it was found: method, family, latency.
- Every failure says why: one error per target tried, not a shrug.
- No third-party dependencies. Not one. `go.mod` has no `require`.

```console
$ publicip -a
2001:db8::1234
203.0.113.9

$ publicip -m dns -v
resolving via dns …
found 203.0.113.9 (dns/ipv4) in 84ms
203.0.113.9
```

## Install

The library:

```bash
go get github.com/cruizba/publicip/v2
```

The CLI:

```bash
go install github.com/cruizba/publicip/v2/cmd/publicip@latest
```

Or grab a prebuilt binary from the [releases page](https://github.com/cruizba/publicip/releases/latest)
(linux/darwin/windows × amd64/arm64).

> Using v1? It is a frozen maintenance line: [`v1.2.4`](https://github.com/cruizba/publicip/releases/tag/v1.2.4),
> docs in the [`v1`](https://github.com/cruizba/publicip/tree/v1) branch,
> import path `github.com/cruizba/publicip` without the `/v2`.

## Library

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	publicip "github.com/cruizba/publicip/v2"
)

func main() {
	client := publicip.New()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := client.Discover(ctx)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(result.IP)      // 203.0.113.9
	fmt.Println(result)         // 203.0.113.9 (stun/ipv4)
	fmt.Println(result.Method)  // stun
	fmt.Println(result.Version) // 1
}
```

`Discover` tries each method in order — STUN, DNS, HTTP — preferring IPv6, and returns
the first address found. It is a `Result`, not a bare `net.IP`, because "which one of my
addresses, found how?" is usually the interesting part.

### Asking for a family, or a method

```go
// Only IPv6.
v6, err := client.DiscoverWithIPVersion(ctx, publicip.IPv6Only)

// Only HTTP, only IPv4.
v4, err := client.DiscoverWithMethod(ctx, publicip.HTTP, publicip.IPv4Only)
```

An address that does not match the requested family is rejected, whether it came from a
built-in method or from your own `Discoverer`. `publicip.IPv6Only` is a promise, not a
preference.

### Configuration

Configuration is a list of options. There is no config struct to fill in, and the zero
value of an option means "leave the default alone".

```go
client := publicip.New(
	publicip.WithMethods(publicip.HTTP, publicip.DNS), // order and subset
	publicip.WithSTUNServers("stun.l.google.com:19302"),
	publicip.WithDNSServers(publicip.DNSServer{
		Addr:      "resolver1.opendns.com", // a port is optional, defaults to :53
		QueryName: "myip.opendns.com",
	}),
	publicip.WithHTTPEndpoints("https://api.ipify.org"),
	publicip.WithAttemptTimeout(2*time.Second), // ceiling for one network attempt
	publicip.WithTimeout(5*time.Second),        // total budget for one call
	publicip.WithHTTPClient(myProxiedClient),
	publicip.WithLogger(slog.New(handler)),
)
```

On budgets: the **context you pass is the budget**. `WithTimeout` caps a call from the
client side for callers who would rather state it once; without it, a `context.Background()`
means "as long as each attempt needs, up to `WithAttemptTimeout`". Each attempt gets a
fair share of what is left, so one stalled server cannot starve the healthy ones behind it.

Defaults: `stun.l.google.com:19302`, `stun1.l.google.com:19302`,
`global.stun.twilio.com:3478`; the OpenDNS, Google and Akamai address services;
`api.ipify.org`, `ifconfig.me`, `icanhazip.com`; a 5-second per-attempt ceiling.

### Finding out why it failed

A failed call returns a `*DiscoveryError` that wraps `ErrNotFound` (and `ErrTimeout`
when the budget ran out) together with the error from every target it tried:

```go
_, err := client.Discover(ctx)

if errors.Is(err, publicip.ErrNotFound) {
	var de *publicip.DiscoveryError
	if errors.As(err, &de) {
		for _, f := range de.Failures() {
			fmt.Printf("%s %s (ipv%s): %v\n", f.Method, f.Target, f.Family, f.Err)
		}
		fmt.Println("timed out:", de.TimedOut())
	}
}
```

`err.Error()` stays a readable one-liner; `de.Detail()` is the full list. Matching is
done with `errors.Is`, so a wrapped sentinel stays a wrapped sentinel.

### Your own method

```go
type upnp struct{ client *routerpxml.Client }

func (u *upnp) Discover(ctx context.Context, v publicip.IPVersion) (publicip.Result, error) {
	ip, err := u.queryWANIPAddress(ctx)
	if err != nil {
		return publicip.Result{}, publicip.NewDiscoveryError([]publicip.Failure{{
			Method: "upnp", Target: u.host,
			Family: "4", // "4" or "6", the family this attempt was made over
			Err:    err,
		}}, false)
	}
	return publicip.Result{IP: ip, Method: "upnp"}, nil
}

client := publicip.New(
	publicip.WithMethod("upnp", &upnp{router}),
	publicip.WithMethods("upnp", publicip.STUN, publicip.DNS),
)
```

Registering under `publicip.DNS` replaces the built-in DNS rather than running beside it,
so an environment with its own resolver will not also leak queries to OpenDNS.

## CLI

```
  -i, --ip-version string   IP version to discover: 4 or 6
  -m, --method string       discovery method to use: stun, dns or http
  -a, --all                 try every method and family, print each distinct address
  -j, --json                print a JSON document instead of a bare address
  -v, --verbose             report how the address was found, and what failed
  -t, --timeout int         overall budget in seconds (default 10)
      --version             print the version and exit
  -h, --help                show this help
```

```console
$ publicip -i 4 -m stun
203.0.113.9

$ publicip -a -j
{
  "addresses": [
    { "ip": "2001:db8::1234", "method": "stun", "family": "ipv6", "latency": "41ms" },
    { "ip": "203.0.113.9", "method": "http", "family": "ipv4", "latency": "62ms" }
  ],
  "errors": [ "dns/ipv6: network is unreachable" ]
}
```

With `--all`, an address is attributed to the first method that reported it, in the
documented order, and each entry carries the latency of that probe.

stdout carries only addresses, one per line, so `publicip | while read ip; do …` keeps
working; diagnostics and `--verbose` output go to stderr. The exit status is `1` when no
address could be discovered and `0` otherwise.

v1's `-v` printed the version; that moved to `--version`, and `-v` now means verbose.

## Behaviour worth knowing

- **STUN reads the mapped address**, so it reports the address your NAT translated to,
  not the interface address. The codec is hand-rolled (RFC 5389 with the RFC 3489
  fallback), over UDP, with no dependency.
- **DNS asks services that answer with the caller's address.** The record types supported
  are the ones `net.Resolver` can ask for (A and AAAA); services that only answer `TXT`
  are out of reach without a DNS client of our own, which a zero-dependency library
  declines to be.
- **HTTP follows redirects** and accepts any body that parses as an address, bounded to
  128 bytes so a confused endpoint cannot make the caller allocate.
- **IPv6 is tried first** for every method, and a host without an IPv6 route fails over
  quickly. A service without an AAAA record still spends one IPv6 attempt on it; that is
  the cost of preferring the family that exists.

## Development

```bash
make            # gofmt, vet, tests
make cover      # coverage profile + total
make check-coverage   # the 100% gate
make fuzz FUZZTIME=30s
make integration      # against the real services, needs internet (and IPv6 for those paths)
```

`go-test-coverage` and `mutago` are installed on demand and never added to `go.mod`:
a dev tool is not a runtime dependency, and that distinction is the point of the module.

## License

Apache-2.0. See [LICENSE](LICENSE).

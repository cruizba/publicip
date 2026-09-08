# AGENTS.md

This file provides guidance to coding agents (pi, Claude Code, ...) when working
with code in this repository.

## Build Commands

```bash
# Build CLI tool
go build -o publicip ./cmd/publicip

# Run directly
go run ./cmd/publicip

# Cross-compile (the release workflow builds linux/darwin/windows x amd64/arm64)
GOOS=linux GOARCH=amd64 go build -o publicip-linux-amd64 ./cmd/publicip
GOOS=darwin GOARCH=arm64 go build -o publicip-darwin-arm64 ./cmd/publicip
GOOS=windows GOARCH=amd64 go build -o publicip-windows-amd64.exe ./cmd/publicip
```

The module is **dependency-free**: `go.mod` declares no requires and `go.sum` is
empty. Keep it that way unless there is a strong reason — it is the main selling
point of the library.

Formatting / static checks that are expected to pass:

```bash
gofmt -l .   # must print nothing
go vet ./...
```

## Testing

No tests exist yet. If added, run with:

```bash
go test ./...
go test -v -race ./...
```

The STUN codec (`buildBindingRequest`, `parseBindingResponse`,
`parseXORMappedAddress`, `parseMappedAddress`) is pure and testable offline —
prefer table-driven tests there. HTTP discovery can be tested with
`net/http/httptest`; STUN with a `net.ListenPacket("udp4", "127.0.0.1:0")` fake
server. Tests that hit real public servers are not appropriate for CI.

## Architecture

**publicip** is a Go library and CLI for discovering public IP addresses using
three methods: STUN, DNS, and HTTP. Everything lives in package `publicip` at
the repo root (no `internal/`, no subpackages except `cmd/` and `examples/`).

### Core Components

- **Client** (`publicip.go`) - entry point holding a `map[Method]discoverer`:
  - `Discover(ctx)` - any IP version
  - `DiscoverWithIpVersion(ctx, version)` - specific IP version, tries all methods
  - `DiscoverWithMethod(ctx, method, version)` - specific method and version
  - Note: the `discoverer` interface is **unexported**; `Method` and `IPVersion`
    are exported enums (`STUN`/`DNS`/`HTTP`, `Any`/`IPv4Only`/`IPv6Only`).

- **Implementations** (all take a per-request timeout plus their own config):
  - `stun.go` - hand-rolled STUN (RFC 5389) over UDP: builds a Binding Request,
    parses XOR-MAPPED-ADDRESS with the magic-cookie XOR, falls back to
    MAPPED-ADDRESS. No external STUN library.
  - `dns.go` - `net.Resolver` with `PreferGo: true` and a custom `Dial` pinned to
    `udp4`/`udp6`, querying `myip.opendns.com` / `o-o.myaddr.l.google.com` / etc.
  - `http.go` - HTTPS GET to plain-text IP echo services, TLS dialed with a
    network-pinned dialer.

- **Configuration** (`config.go`) - `Config{RequestTimeout, STUNConfig, DNSConfig,
  HTTPConfig}` via `DefaultConfig()`. `RequestTimeout` defaults to 5s.
  DNS entries use the `"resolver:query-name"` string format; `tryQuery` splits on
  `:` and rejects anything that is not exactly 2 parts (so IPv6-literal DNS
  servers are currently unsupported).

- **CLI** (`cmd/publicip/main.go`) - standard library `flag` package (Cobra was
  removed). Flags are registered twice (long + short) against the same variables:
  `-i/--ip-version`, `-m/--method`, `-t/--timeout` (seconds, default 10),
  `-v/--version`, `-h/--help`. No config-file or env-var overrides.

- **Version** (`version.go`) - `const version`, bumped automatically by the
  release workflow; exposed through `GetVersion()`.

### Fallback Strategy

`Discover(ctx)` calls `DiscoverWithIpVersion(ctx, Any)`, which walks
`[STUN, DNS, HTTP]`. Within **each** method, the discoverer tries IPv6 on every
server first, then IPv4 on every server, and returns the first success. So the
real order is STUN-v6 → STUN-v4 → DNS-v6 → DNS-v4 → HTTP-v6 → HTTP-v4 (not "all
IPv6 attempts across methods, then IPv4"). If everything fails it returns the
generic `ErrNoIPDiscovered`, discarding the underlying errors.

### Timeout Behaviour (gotcha)

`RequestTimeout` is per **attempt**, not per call, and `DiscoverWithIpVersion`
makes up to 20 attempts — worst case far exceeds the CLI's default 10s context.
Servers without an AAAA record (`api.ipify.org`, `ns1-1.akamaitech.net`) burn a
whole timeout on IPv6 name resolution before IPv4 is ever tried, which is why
`publicip -m dns -t 5` can fail while `-t 8` succeeds. Mind this when touching
the discover loops or the CLI timeout flags.

### Debug Logging

Set `PUBLIC_IP_AUTODISCOVERY_DEBUG=true` (**exactly** `true`; `1` does not
enable it) to write debug output to stderr. It is read once in `init()` from
`log.go` through a package-level global; there is no programmatic setter.

### Releasing

`.github/workflows/release.yml` is `workflow_dispatch` with a `version` input:
it seds `version.go`, commits and pushes to `main`, cross-compiles 6 binaries,
then creates the tag and assets with `gh release create --generate-notes`
(softprops/action-gh-release was dropped). There is **no CI workflow** running
tests or lint on PRs. Dependabot runs weekly for `gomod` and `github_actions`.

## Conventions

- Go code and comments in English.
- `errors.go` defines `ErrUnsupportedIPVersion` and `ErrTimeout` but nothing
  returns them today; if you add error paths, wire them up rather than adding
  more unused sentinels, and wrap underlying errors (`%w`) so callers can inspect
  them.

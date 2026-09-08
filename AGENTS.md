# AGENTS.md

This file provides guidance to coding agents (pi, Claude Code, ...) when working
with code in this repository.

> **Status: v2 migration in progress.** `main` is now the module
> `github.com/cruizba/publicip/v2`, and the redesign is landing commit by commit.
> Until this note is removed, the architecture and API described below document the
> **v1** shape (frozen on branch `v1`, tag `v1.2.3`) and parts of it are being replaced.
> If you change anything public, re-read the Versioning policy section first.

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

```bash
go test ./...
go test -v -race ./...
```

The STUN codec (`buildBindingRequest`, `parseBindingResponse`,
`parseXORMappedAddress`, `parseMappedAddress`) is pure and covered table-driven.
HTTP discovery is tested with `net/http/httptest`; STUN and DNS with fake servers
bound to loopback, and the client's fallback order with stub discoverers injected
into the unexported map (`clientWith` in `publicip_test.go`).

**Tests must never resolve a name.** An address fixture is a loopback literal or an
RFC 5737 documentation range address (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), never a hostname. `hermetic_test.go` enforces this by parsing the
test files, and the `Tests must not touch the network` CI job traces syscalls. Note
that running the suite in a network namespace is *not* a sufficient check: a fixture
that leaks a DNS query still passes there, because resolution failing is what the test
asserts. Real end-to-end checks against public servers live outside the unit suite.

Coverage is reported in CI but not gated (v1 is frozen); the 100 % mandate belongs to
v2, where the unexported rand/dial/lookup seams make the remaining branches
reachable.

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
makes up to 20 attempts (3 STUN + 4 DNS + 3 HTTP, each over IPv6 then IPv4). Since
v1.2.3, `attemptBudget()` bounds each attempt by the time left in the caller's
context *and* divides that remainder by the number of attempts still waiting, so a
single stalled server cannot starve the healthy ones behind it. `attemptPlan()` owns
the traversal order (IPv6 across all targets first, then IPv4) — changing it alters
which server answers and is therefore a v2 decision, not a v1 refactor.

Remaining, by design: a server without an AAAA record (`api.ipify.org`,
`ns1-1.akamaitech.net`) still spends one fair-share attempt failing over, and a slow
system resolver still dominates the DNS path because the server's own hostname is
resolved per attempt. v2 fixes both by resolving once and dialing the IPv4/v6
probes concurrently.

### Debug Logging

Set `PUBLIC_IP_AUTODISCOVERY_DEBUG=true` (**exactly** `true`; `1` does not
enable it) to write debug output to stderr. It is read once in `init()` from
`log.go` through a package-level global; there is no programmatic setter.

### Releasing

`.github/workflows/release.yml` is `workflow_dispatch` with a `version` input:
it seds `version.go`, commits and pushes to `main`, cross-compiles 6 binaries,
then creates the tag and assets. `--target` pins the tag to the commit built by
this job and the push uses an explicit refspec, both so that a release cut from the
`v1` maintenance branch does not land on main.

Release notes come from `scripts/release-notes.sh`, which groups the commit range by
Conventional Commit type. Do not switch back to `--generate-notes`: it derives its body
from merged pull requests, so on a repo where changes land as direct commits it
describes almost nothing.

`.github/workflows/ci.yml` runs on push to `main` and `v1` and on pull requests:
gofmt and vet, `-race` tests on the go.mod floor and current stable, the syscall-level
hermetic check, and all six cross-builds. Dependabot runs weekly for `gomod` and
`github_actions`.

## Versioning policy

- v1 is a frozen maintenance line: bug fixes only, no new exported symbols, no
  behavior changes visible to code that compiles today, no change to the `go`
  directive.
- All breaking changes (types, names, error semantics, discovery ordering) belong to
  v2 under module path `github.com/cruizba/publicip/v2`. Intentional breaks use
  `feat!`/`fix!` commit prefixes so release notes group them.

## Conventions

- Code, comments and documentation (README, AGENTS.md) are in English.
- `errors.go` defines `ErrUnsupportedIPVersion` and `ErrTimeout` but nothing
  returns them today; if you add error paths, wire them up rather than adding
  more unused sentinels, and wrap underlying errors (`%w`) so callers can inspect
  them.

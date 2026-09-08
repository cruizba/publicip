# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres to
[semantic versioning](https://semver.org/spec/v2.0.0.html) as interpreted by Go module
versioning: a change that breaks the compiled API gets a new major version and a new
import path.

## [Unreleased]

Nothing pending.

## [2.0.0] - unreleased

v2 is the breaking release: everything that changes a compiled API lives here, under the
module path `github.com/cruizba/publicip/v2`. v1 stays available and frozen.

### Added

- `Result` carries the address, the method that found it and the family it belongs to,
  with `Result.String()` rendering `203.0.113.9 (stun/ipv4)`.
- `DNSServer{Addr, QueryName}`: a resolver address that can name its own port, instead of
  a `host:query` string that could not.
- `Discoverer`, exported, with `WithMethod(name, d)` to register a source of your own or
  to replace a built-in one. `NewDiscoveryError` lets a custom source report failures in
  the same shape.
- `DiscoveryError` with `Failures()` and `Detail()`: one entry per target tried, reachable
  with `errors.Is`/`errors.As`.
- `ErrNotFound` and `ErrTimeout` as distinct sentinels, so "nothing answered" and "you ran
  out of budget" are no longer the same message.
- CLI: `--all` (every distinct address across methods and families), `--json`, `--verbose`.
- The requested address family is enforced by the client for every discoverer, built-in
  or supplied.
- Configuration through options: `WithTimeout`, `WithAttemptTimeout`, `WithMethods`,
  `WithSTUNServers`, `WithDNSServers`, `WithHTTPEndpoints`, `WithHTTPClient`,
  `WithLogger`, `WithMethod`.
- Attempt budgeting: attempts within a family run concurrently, each bounded by a fair
  share of what the call has left.
- HTTP: one client and connection pool per family, a 128-byte cap on responses, and a TLS
  handshake that honours the caller's context.
- `ConfiguredMethods()`, `Version()`.
- Development: `Makefile`, a 100%-statement coverage gate (`.testcoverage.yml`), mutation
  scoring with a committed baseline, fuzz targets for the STUN and HTTP parsers, and an
  `integration` build tag for the tests that contact the real services.

### Changed

- The module path is `github.com/cruizba/publicip/v2`; the CLI installs from
  `github.com/cruizba/publicip/v2/cmd/publicip`.
- The language floor is `go 1.23`.
- `New(opts ...Option)` is the constructor.
- Debug output goes through the `*slog.Logger` given to `WithLogger`.

### Removed

- `Config`, `DefaultConfig`, `NewClient`, `NewClientWithConfig`, and the
  `STUNConfig`/`DNSConfig`/`HTTPConfig` sections.
- `NewClient`, `GetVersion`, `DiscoverWithIpVersion`.
- `ErrNoIPDiscovered` (now `ErrNotFound`) and `ErrUnsupportedIPVersion`, which no code
  path could produce.
- The `PUBLIC_IP_AUTODISCOVERY_DEBUG` environment variable.

### Fixed

- A malformed STUN response whose final attribute is not padded to a 4-byte boundary
  panicked with a slice out of range; it is now reported as a failure. Found by fuzzing.
  (Backported to v1 as v1.2.4.)
- One stalled server could consume the whole call budget, so healthy servers behind it
  were never tried. (Backported to v1 as v1.2.2/v1.2.3.)

### Migration from v1

| v1 | v2 |
|---|---|
| `publicip.NewClient()` | `publicip.New()` |
| `publicip.NewClientWithConfig(cfg)` | `publicip.New(publicip.With…(…)…)` |
| `client.Discover(ctx) (net.IP, error)` | `client.Discover(ctx) (Result, error)` → `result.IP` |
| `client.DiscoverWithIpVersion(ctx, v)` | `client.DiscoverWithIPVersion(ctx, v)` |
| `client.DiscoverWithMethod(ctx, m, v) (net.IP, error)` | same name, returns `Result` |
| `errors.Is(err, publicip.ErrNoIPDiscovered)` | `errors.Is(err, publicip.ErrNotFound)` |
| `publicip.DefaultConfig()` + fields | `publicip.New(...)` with options |
| `config.DNSConfig.Servers = []string{"host:query"}` | `WithDNSServers(DNSServer{Addr: "host", QueryName: "query"})` |
| `publicip.GetVersion()` | `publicip.Version()` |
| `PUBLIC_IP_AUTODISCOVERY_DEBUG=true` | `WithLogger(slog.New(handler))` |

The import path changes from `github.com/cruizba/publicip` to
`github.com/cruizba/publicip/v2`, so `go mod tidy` and a recompile are the whole
mechanical part; the table above is the semantic part.

## [1.2.3] - 2026-09-08

### Fixed

- Each attempt now takes a fair share of the time the context has left. v1.2.2's clamp
  bounded an attempt by the deadline but handed the whole remainder to the first one, so
  a single stalled server still starved every healthy server behind it.

## [1.2.2] - 2026-09-08

### Fixed

- `RequestTimeout` is applied per attempt while a discovery run makes up to twenty of
  them; an attempt could outlive the caller's context and a stalled first server could
  consume the whole call. Each attempt is now clamped to the time the context has left and
  the loops stop before an attempt that would not fit. **Superseded by v1.2.3**: the clamp
  alone left the starvation in place.

### Added

- Tests (the STUN codec had none), a CI workflow, and a syscall-level check that the test
  suite never leaves loopback.

## [1.2.1] - 2026-07-06

Maintenance: Go 1.26.4, release automation.

## [1.2.0] - 2026-05-31

Release workflow switched to `gh` and Dependabot taught about GitHub Actions.

## [1.1.0] and earlier

- The STUN client stopped depending on `pion/stun` and the codec became part of this
  module, which is why the library has no dependencies.
- The CLI moved from Cobra to the standard library's `flag`.
- `Discover`, `DiscoverWithMethod` and `DiscoverWithIpVersion` over STUN, DNS and HTTP.

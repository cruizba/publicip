# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
line adheres to [semantic versioning](https://semver.org/spec/v2.0.0.html). v1 is a
frozen maintenance line: bug fixes only, no new exported symbols, no behaviour change
visible to code that compiles today. Breaking changes live in v2, under
`github.com/cruizba/publicip/v2`.

## [1.2.4] - 2026-09-08

### Fixed

- A malformed STUN response whose final attribute is not padded to a 4-byte boundary
  panicked with a slice index past the end of the buffer. Any server in the configured
  list could crash a caller with it; parsing now stops at the truncated attribute and
  keeps what it already decoded.

## [1.2.3] - 2026-09-08

### Fixed

- Each attempt now takes a fair share of the time the caller's context has left. The
  clamp added in 1.2.2 bounded an attempt by the deadline but handed the whole remainder
  to the first one, so a single stalled server still starved every healthy server behind
  it: `publicip -m dns -t 5` kept failing intermittently.

## [1.2.2] - 2026-09-08

### Fixed

- `RequestTimeout` bounds one attempt, while a discovery run makes up to twenty of them;
  an attempt could outlive the caller's context, and one slow server (typically a name
  that has to be resolved, or a host with no AAAA record on an IPv6 attempt) could
  consume the entire call before a working server was tried. Each attempt is now clamped
  to the time that is left, and the loops stop before an attempt that would not fit.

### Added

- Unit tests (the STUN codec had none), a CI workflow, and a syscall-level check that
  the test suite never leaves loopback.

## [1.2.1] - 2026-07-06

### Changed

- Go 1.26.4, and the release job now publishes with `gh` instead of a third-party action.

## [1.2.0] - 2026-05-31

### Added

- Dependabot for GitHub Actions.

## [1.1.0] and earlier

- STUN without the `pion/stun` dependency: the codec became part of this module, which is
  why the library has no dependencies.
- The CLI moved from Cobra to the standard library's `flag`.
- `Discover`, `DiscoverWithMethod` and `DiscoverWithIpVersion` over STUN, DNS and HTTP.

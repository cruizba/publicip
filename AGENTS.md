# AGENTS.md

This file provides guidance to coding agents (pi, Claude Code, ...) when working
with code in this repository.

## Build commands

```bash
make                    # gofmt check, go vet, tests
make test race cover    # individually
go build -o publicip ./cmd/publicip
go run ./cmd/publicip -m stun -i 4
```

The module is **dependency-free**: `go.mod` has no `require` and there is no `go.sum`.
Keep it that way — it is the library's main selling point. Dev tooling
(`go-test-coverage`, `mutago`) is `go install`ed in CI and in the Makefile, never added
to the module.

Language floor is `go 1.26` — the oldest line that still receives standard library
security fixes. For a dependency-free library that floor is a security decision, not a
compatibility courtesy: the stdlib *is* the attack surface, so a floor on an archived
release line would bless building with known-vulnerable packages. Nothing here may use a
newer language feature without
raising the floor deliberately, in its own `chore!` commit, because that changes what
consumers can compile against (generic methods, for instance, need 1.27 — which is why
`run`/`runRound` are generic *functions* taking `*config`).

## Testing

```bash
go test ./...
go test -race -count=1 ./...
go test -tags integration -v ./...   # contacts the real services
```

Layout: `*_test.go` in package `publicip` for internals (the wire codec, the round
engine, the budget math), `example_test.go` in `publicip_test` for the README's snippets,
`cmd/publicip/main_test.go` for the CLI.

**Coverage gate: 100 % of statements**, per file, package and total, from
`.testcoverage.yml`. `make check-coverage` runs it locally. Exclusions are
`examples/` (config) and `func main()` (a `// coverage-ignore` with a reason — the tool
requires the reason). New code ships with the tests that cover it; when a branch is
genuinely unreachable from a test, say why in the annotation rather than lowering the
number.

**Statements covered is not the same as tests that work.** `make fuzz` and the CI
mutation job measure the difference. The gate is `--min-covered-msi`, the one mutago
mechanism measured to actually fail the job (exit 4). Its baseline features are not used:
with 12 known escaped mutants in `dns.go`, `--fail-on-escaped` exited 0 with and without a
baseline file, and passing the baseline changed the reported covered-MSI not at all, so
nothing is tracked in the tree for it. `report.json`, uploaded by the CI job on every run,
is where survivors get reviewed — currently 95 of them, mostly equivalent mutants and
logging-only statements.

### The suite must not touch the network

- An address fixture is a loopback literal or an RFC 5737 documentation address
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). **Never a hostname**: it leaks
  a real query to whoever's resolver the developer uses.
- `hermetic_test.go` enforces this by parsing the test files, and CI runs the suite under
  `strace` and fails on any non-loopback destination.
- A test that builds a client and discovers must go through `newTestClient(t, …)`
  (sandboxed target lists) or `clientWith(…)`, because the shipped defaults are real
  public services. `// hermetic:allow` marks a deliberate exception, at the literal or
  at the function's doc comment.
- Running the suite inside a network namespace is **not** proof of hermeticity: a fixture
  that leaks a query still passes there, since resolution failing is what the test
  asserts. Use `strace`.
- Anything that deliberately reaches the internet lives in `integration_test.go` behind
  `//go:build integration`, which the hermetic checks skip on purpose.

## Architecture

Everything is package `publicip` at the repo root — no subpackages, because a
`publicip/` directory would make the import `…/v2/publicip`. `cmd/publicip` is the CLI,
`examples/` a compiled sample.

- **`publicip.go`** — `Client`, `New(opts...)`, `Discover`/`DiscoverWithIPVersion`/
  `DiscoverWithMethod`, `Result`, the exported `Discoverer`, `invoke` (the single place a
  discoverer's answer is checked, including its family), `callContext`.
- **`options.go`** — the unexported `config` and every `Option`. `WithTimeout` is the
  total budget of one call (default 0 = the caller's context decides);
  `WithAttemptTimeout` bounds one attempt (default 5s). Defaults are assembled in
  `defaultConfig()`, never from a package-level mutable var.
- **`defaults.go`** — the shipped server lists as unexported slices.
- **`rounds.go`** — the traversal both discoverers share: `attemptRounds` groups targets
  by family (IPv6 round first, then IPv4 — that order is observable and belongs to a
  major), `run` walks the rounds, `runRound` fires one round's attempts concurrently and
  cancels the losers.
- **`timeout.go`** — `attemptBudget` (per-attempt ceiling ∩ fair share of the remainder)
  and `noBudgetError`.
- **`errors.go`** — `Failure`, `DiscoveryError` (`Error()` is one line, `Detail()` is the
  list, `Unwrap() []error` exposes the sentinels and every cause), `NewDiscoveryError`.
- **`stun.go` / `dns.go` / `http.go`** — one method each: a `tryX(ctx, target, family,
  timeout) (net.IP, error)` plus a one-line `Discover` delegating to `run`. `stun.go`
  holds the hand-rolled RFC 5389 codec (with the RFC 3489 fallback); `dns.go` holds
  `DNSServer` and `familyMismatch`; `http.go` holds one `http.Client` per family and
  `parseAddressBody`.
- **Test seams, unexported on purpose** (`config` fields, set only from `helpers_test.go`):
  `lookup` (the DNS transport), `dial` (UDP/TCP establishment), `rand` (transaction-id
  entropy). Without them four branches are unreachable: a resolver that needs privileges
  on :53, a connection that fails mid-handshake, and a `crypto/rand` that never fails on
  demand.
- **`cmd/publicip`** — `cli{stdout, stderr, newClient}` with `run(args []string) error`;
  `main()` only wires the process. Flags: `-i/--ip-version`, `-m/--method`, `-a/--all`,
  `-j/--json`, `-v/--verbose`, `-t/--timeout`, `--version`, `-h/--help`. Addresses go to
  stdout, everything else to stderr.
- **Logging** — `log/slog` through the logger in `config`, which defaults to a discard
  handler. There is no global flag, no environment variable and no package-level writer.

## Versioning policy

- v1 is a **frozen maintenance line**: branch `v1`, the `v1.2.x` tags. Bug fixes only — no new
  exported symbols, no behaviour change visible to code that compiles today, no change to
  the `go` directive. Cut `v1.2.x` from it and nothing else.
- All breaking changes land in v2 under `github.com/cruizba/publicip/v2`. Prefix the commit
  `feat!`/`fix!`/`chore!` so release notes group it, and record it in `CHANGELOG.md`
  under a Migration table entry if it renames anything.
- Intentional breaks get **no** deprecated aliases here: the `/v2` path is the
  compatibility mechanism, and half-migrating would be the worst of both.
- Deprecations from here on are v2.x affairs: `// Deprecated:` plus a CHANGELOG note,
  removed at the next major.

## Releasing

`.github/workflows/release.yml`, `workflow_dispatch` with a `version` input: it seds
`version.go`, pushes to the branch the workflow ran on (`git push origin HEAD:<ref>`, so
a release from `v1` cannot land on `main`), cross-builds six binaries and creates the tag
with `gh release create --target <sha> --notes-file notes.md`.

Release notes come from `scripts/release-notes.sh`, which groups the commit range by
Conventional Commit type and **aborts if any commit in the range went unclassified**.
Do not reintroduce `--generate-notes`: it derives its body from merged pull requests, so
on a repository that commits directly to `main` it describes almost nothing — which is
how a release announced a Dependabot bump and omitted the fix.

The checkout needs `fetch-depth: 0` for that history. `version.go` is rewritten by the
workflow, so tests must never assert a literal version string — `version_test.go` matches
a `vMAJOR.MINOR.PATCH` pattern for that reason.

## CI

`ci.yml` on push to `main`/`v1` and on PRs: gofmt + vet; `-race` on the `go.mod` floor and
current stable (running on the floor is what proves the directive is honest); the syscall
hermetic check; the coverage gate; the mutation gate; six cross-builds.
`nightly.yml` fuzzes each wire parser and runs the integration suite.

Dependabot watches `gomod` (quiet while the module has no dependencies) and
`github_actions`.

## Conventions

- Code, comments and documentation (README, AGENTS.md, CHANGELOG.md) are in English.
- Commit subjects are Conventional Commits (`feat:`, `fix:`, `ci:`, `docs:`, `test:`,
  `refactor:`, `chore:`, `build:`): `scripts/release-notes.sh` rejects a subject with no
  recognised type, and a `!` in the subject commits the release to having a breakage
  section in `CHANGELOG.md`.
- Every commit ends with the `Assisted-by:` trailer from the global rules.
- `docs/v2-plan.md` is local-only (git-excluded) and holds the roadmap; it can disagree
  with the code, in which case the code is right and the plan is stale.

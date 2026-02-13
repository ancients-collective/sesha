# Contributing to sesha

Thanks for your interest in contributing! Whether you're writing new security
checks, fixing bugs, or improving documentation, every contribution helps make
Linux systems a little safer.

Please take a moment to read through this guide so your contribution lands
smoothly.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/sesha.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run tests: `go test ./... -race`
6. Run lints: `golangci-lint run` (optional)
7. Submit a pull request

### Development Requirements

- Go 1.24+
- Linux (for running checks — tests use temp files and mocks)
- [golangci-lint](https://golangci-lint.run/) (optional, for lint checks)

---

## Writing Checks

The easiest way to contribute is by writing new YAML checks — no Go code
required. The full guide is in [docs/writing-checks.md](docs/writing-checks.md),
but here's the short version.

Look at `checks/essentials/` for real examples.

### Check Requirements

- Each check must have a unique `id` — use `snake_case` by convention (e.g., `shadow_permissions`)
- IDs must match the regex `^[a-zA-Z0-9_-]+$`
- Every check needs: `id`, `name`, `description`, `severity`, `category`, `steps`, and `remediation`
- Steps must use one of the 13 built-in functions (see the [function reference](docs/writing-checks.md#built-in-functions))
- Always validate before submitting: `./sesha --validate ./checks`

### Check Quality

Good checks tell a story — *what* they verify, *why* it matters, and *how* to
fix a failure:

- Write a clear `description` explaining the security impact
- Provide actionable `remediation` steps (commands a user can copy-paste)
- Add `references` linking to relevant standards (CIS, STIG, etc.)
- Consider adding `impact`, `explain`, and `break_risk` for extra context
- Use `acceptable` blocks for checks that legitimately don't apply in some environments

---

## Code Contributions

### Project Layout

```text
cmd/sesha/         — CLI entry point
internal/
  types/           — Shared types (no business logic)
  engine/          — Execution engine, functions, security validation
  context/         — System detection (OS, distro, environment)
  loader/          — YAML check loading and validation
  output/          — Output formatters (text, JSON, JSONL)
checks/            — YAML check definitions
```

### Architecture Notes

The CLI follows a `Config` struct + `parseFlags` / `run` pattern:

- `parseFlags([]string) (*Config, error)` — parses arguments with a dedicated
  `flag.NewFlagSet`, keeping the global `flag.CommandLine` clean for tests
- `run(*Config) int` — all business logic, returns an exit code instead of
  calling `os.Exit`
- `main()` is a thin wrapper: parse → run → exit

This makes it straightforward to test flag parsing and execution logic
independently.

### Guidelines

- Keep the binary lean — sesha is a single-purpose tool
- No external service dependencies at runtime
- All command execution goes through the allowlist in `internal/engine/allowlist.go`
- Allowed commands are resolved via `exec.LookPath` at startup with hardcoded fallback paths
- Security validations live in `internal/engine/security.go`
- The loader rejects duplicate check IDs at load time — the second file is skipped with an error
- Tests use `t.TempDir()` for isolation — never touch real system files

### Running Tests

```bash
# Full suite with race detection
go test ./... -race

# Single package, verbose
go test ./internal/engine/ -v

# With coverage report
go test ./... -race -coverprofile=coverage.out
go tool cover -html=coverage.out
```

### Output Formatter Tests

JSON and JSONL formatters use golden files in `internal/output/testdata/`. If
you intentionally change the output format, regenerate them:

```bash
UPDATE_GOLDEN=1 go test ./internal/output/ -run TestJSON
```

Text formatter tests are behavioural — they assert on substrings and structural
properties rather than exact output, so they don't need golden files.

---

## Reporting Issues

When opening a GitHub Issue, please include:

- Your OS, Go version, and sesha version (`sesha --debug` prints this)
- The check ID and relevant system info (for check failures)
- Steps to reproduce the problem

For security vulnerabilities, **do not open a public issue** — see
[SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
[Apache License 2.0](LICENSE).

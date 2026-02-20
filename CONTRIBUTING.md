# Contributing to sesha

Thanks for your interest in contributing! Whether you're writing new security
checks, fixing bugs, or improving documentation, every contribution helps make
Linux systems a little safer.

Please take a moment to read through this guide so your contribution lands
smoothly.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/sesha.git`
3. Set up branches: `git fetch origin develop && git checkout develop`
4. Create a feature branch: `git checkout -b feat/my-feature`
5. Make your changes (one concern per branch — see below)
6. Commit using [Conventional Commits](#commit-messages) format
7. Run tests: `go test ./... -race`
8. Run lints: `golangci-lint run` (optional)
9. Submit a pull request **targeting `develop`**

### Development Requirements

- Go 1.24+
- Linux (for running checks — tests use temp files and mocks)
- [golangci-lint](https://golangci-lint.run/) (optional, for lint checks)

---

## Branching Model

This project uses a **Gitflow-lite** branching strategy:

```text
main          ← stable releases only (tagged)
  └── develop ← integration branch for all work
        ├── feat/...    ← new features
        ├── fix/...     ← bug fixes
        └── chore/...   ← tooling, docs, CI
```

| Branch type | Forks from | Merges to | Naming convention |
|-------------|------------|-----------|-------------------|
| Feature     | `develop`  | `develop` | `feat/short-desc` |
| Bug fix     | `develop`  | `develop` | `fix/short-desc` |
| Chore       | `develop`  | `develop` | `chore/short-desc` |
| Release     | `develop`  | `main` + `develop` | `release/x.y.z` |
| Hotfix      | `main`     | `main` + `develop` | `hotfix/short-desc` |

**Rules:**

- All feature/fix/chore PRs target `develop`, never `main` directly
- `main` only receives merges from `release/*` or `hotfix/*` branches
- Release branches are created when `develop` is ready for a release (see
  [docs/release-process.md](docs/release-process.md))
- Hotfix branches fork from `main` for urgent production fixes and merge back
  to both `main` and `develop`

---

## Commit Messages

All commits **must** follow [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
This is enforced by CI on every pull request.

```text
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Allowed types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`,
`build`, `perf`, `style`

**Optional scopes:** `engine`, `loader`, `output`, `context`, `cli`, `checks`,
`release`

**Examples:**

```text
feat(engine): add kernel_param_value function
fix(loader): reject checks with empty steps array
test(engine): add tests for kernel_param_value
chore(release): v1.0.11
docs: update writing-checks guide with new function
ci: add commit message linting workflow
```

**Bad examples** (CI will reject these):

```text
update stuff                    # no type prefix
feat: Add thing and fix bug     # two concerns in one commit
v1.0.11: release                # not conventional commits format
```

---

## One Concern Per PR

Each pull request must address **exactly one concern**. This means:

- **One feature** (e.g., a new check function) — may include its tests
- **One bug fix** (e.g., a loader edge case) — must include a regression test
- **One chore** (e.g., CI config change, dependency update)

**Do NOT mix** features with release tooling, bug fixes with refactors, or
multiple unrelated changes in a single PR. If a feature requires a refactor
first, submit the refactor as a separate PR.

This ensures:

- Reviews are focused and manageable
- Any single change can be reverted cleanly
- The git history tells a clear story

---

## Test Requirements

Every code change (`feat` or `fix`) **must include tests**. PRs without tests
for behavioural changes will be rejected.

### What to test

- **New functions**: unit tests with table-driven cases covering happy path,
  edge cases, and error conditions
- **Bug fixes**: a regression test that fails without the fix and passes with it
- **New checks (YAML)**: validated by the existing `check_library_test.go`
  integration test (just place the file in `checks/`)

### Testing patterns used in this project

- **Table-driven tests** with `t.Run()` subtests
- **`t.TempDir()`** for file isolation — never touch real system files
- **`testify/assert` + `testify/require`** for assertions
- **Golden files** for JSON/JSONL output (`UPDATE_GOLDEN=1`)
- **Behavioural assertions** (substring matching) for text output
- **External test packages** (`engine_test`, `loader_test`) for public API tests
- **Integration tests** wiring real components with zero mocks
- **Fuzz tests** for security-sensitive input parsing

### Example test structure

```go
func TestMyFunction(t *testing.T) {
    tests := []struct {
        name    string
        input   string
        want    string
        wantErr bool
    }{
        {"valid input", "foo", "bar", false},
        {"empty input", "", "", true},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := MyFunction(tt.input)
            if tt.wantErr {
                require.Error(t, err)
                return
            }
            require.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

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

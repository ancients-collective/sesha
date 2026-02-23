# Contributing to sesha

Thanks for your interest in contributing! Whether you're writing new security
checks, fixing bugs, or improving documentation, every contribution helps make
Linux systems a little safer.

Please take a moment to read through this guide so your contribution lands
smoothly.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/sesha.git`
3. Build the binary:
   ```bash
   cd sesha
   go build -o sesha ./cmd/sesha
   ```
4. Create a branch: `git checkout -b my-feature`
5. Make your changes
6. Validate locally — see [Before You Commit](#before-you-commit)
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

## Code Style

- All Go code must be formatted with `gofmt -s` — this is enforced in CI
- Cyclomatic complexity must stay at or below 15 (checked by `make lint`)
- Run `golangci-lint run` for the full linter suite — see
  [.golangci.yml](.golangci.yml) for the enabled linters
- Wrap errors with context: `fmt.Errorf("doing something: %w", err)` — do not
  discard or swallow errors
- No panics — return errors to the caller for graceful handling

---

## Before You Commit

Run these checks locally before committing to catch issues early:

```bash
gofmt -s -w .                          # auto-format all Go files
make lint                              # verify formatting + complexity
make test                              # run full test suite
golangci-lint run                      # full linter suite (optional but recommended)
./sesha --validate ./checks            # validate YAML checks (if changed)
```

For output format changes, update golden files first, then verify:

```bash
make update-golden                     # regenerate golden test files
make test                              # confirm tests pass with updated golden files
```

---

## Commit Messages

All commits must follow
[Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>[optional scope]: <description>
```

**Types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `build`,
`perf`, `style`

**Scopes:** `engine`, `loader`, `output`, `context`, `cli`, `checks`, `release`

Examples:

```text
feat(engine): add kernel_param_value function
fix(loader): reject checks with empty steps array
docs: update writing-checks guide with new function
chore(release): v1.0.11
```

---

## Pull Request Expectations

- **Single concern** — each PR addresses exactly one feature, one fix, or one
  chore. Do not mix unrelated changes. If a feature requires a prerequisite
  refactor, submit the refactor as a separate PR first.
- **Clean commit history** — PRs should be rebase-mergeable. Each commit must
  be a self-contained, logical unit of work with a meaningful message following
  [conventional commits](#commit-messages). Avoid `fixup!`, `squash!`, and WIP
  commits in the final PR — use `git rebase -i` to clean up your history before
  requesting review. The goal is a history that reads well on `main` without
  needing to squash.
- **Tests required** for all `feat` and `fix` changes — see
  [test coverage](#test-coverage) for full requirements.
- **CHANGELOG.md updated** for `feat` and `fix` changes.
- **`make test` must pass** before requesting review.
- Provide a clear description of what the PR does and how to verify it.

---

## Code Review Focus

Code style, formatting, linting, and unit test correctness are handled by
automated CI checks — PRs cannot merge until CI passes. Reviewers should not
comment on these areas.

When reviewing, focus on concrete issues that automation cannot catch. Do not
summarise, explain, or restate what the PR does — the author's description
covers that.

Reviewers should focus on four areas:

### Security

This is a security auditing tool. Changes must not weaken its own security:

- Modifications to the command allowlist (`internal/engine/allowlist.go`) that
  add commands or relax validation
- Path traversal risks — all file paths must be validated as absolute with no
  `..` components (`internal/engine/security.go`)
- Changes that raise file read limits (currently 10 MB) or regex length limits
  (currently 1024 chars)
- Command injection, shell expansion, or unsanitised input in check execution
  paths
- Hardcoded credentials, secrets, or sensitive paths in check definitions

### Maintainability

- Logical correctness — does the change do what it claims?
- Error values that are silently discarded or not wrapped with context
- Use of `panic` — errors must be returned to the caller
- Test code that touches real system files instead of using `t.TempDir()`
- Duplicate check IDs across YAML files in `checks/`

### Test coverage

- New features (`feat`) and bug fixes (`fix`) must include tests
- Tests should cover the happy path, edge cases, and error conditions
- New YAML checks must be validated by `check_library_test.go` and must include
  functional tests that verify the check behaves correctly when executed
- Overall repo test coverage must remain at or above 80%
- No Go files may be excluded from code coverage — do not use coverage skip
  directives or exclude lists

### Merge strategy

The preferred merge method is **rebase merge**, which preserves each commit as
a separate entry on `main`. Before approving, check that the commit history is
clean:

- Each commit is a self-contained, logical change
- Commit messages follow [conventional commits](#commit-messages)
- No `fixup!`, `squash!`, or WIP commits remain

If the branch contains fixup or WIP commits that the author has not cleaned up,
request that they rebase interactively (`git rebase -i`) to tidy the history.
If that is not practical (e.g., the author is unavailable or the PR is
time-sensitive), use **squash merge** instead to collapse the history into a
single clean commit.

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

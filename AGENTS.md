# Agents Guide

Sesha is a YAML-driven security auditing tool for Linux. Single Go binary,
zero runtime dependencies. See [README.md](README.md) for full project overview.

## Key Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) — code style, pre-commit validation,
  commit messages, PR expectations, review focus, project layout, architecture,
  test patterns
- [docs/writing-checks.md](docs/writing-checks.md) — YAML check schema,
  available functions, conditional steps, severity overrides
- [SECURITY.md](SECURITY.md) — vulnerability reporting policy

## Code Review

When reviewing pull requests, do not summarise or explain the PR. Only comment
on concrete issues. See [CONTRIBUTING.md](CONTRIBUTING.md#code-review-focus)
for what to flag, prioritised by security then maintainability.

## PR Review Checklist

See [CONTRIBUTING.md](CONTRIBUTING.md#pull-request-expectations) for full
expectations. When reviewing, check:

- [ ] Does the change address a single concern?
- [ ] Are there tests covering the new/changed behaviour?
- [ ] Do commit messages follow [conventional commits](CONTRIBUTING.md#commit-messages) format?
- [ ] For engine changes: are [security boundaries](CONTRIBUTING.md#security) respected?
- [ ] For new checks: does `./sesha --validate ./checks` pass?
- [ ] For output changes: are golden files updated (`make update-golden`)?
- [ ] Is CHANGELOG.md updated (for feat/fix)?
- [ ] Have [pre-commit checks](CONTRIBUTING.md#before-you-commit) been run?

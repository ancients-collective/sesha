## Description

<!-- What does this PR do and why? -->

## Type of change

<!-- Check the ONE that applies. Each PR should address a single concern. -->

- [ ] `feat` — new feature or check
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `chore` — tooling, CI, dependency updates
- [ ] `refactor` — code restructuring (no behaviour change)
- [ ] `test` — test-only changes
- [ ] `ci` — CI/CD workflow changes

## Pre-commit validation

<!-- See CONTRIBUTING.md for details: https://github.com/ancients-collective/sesha/blob/main/CONTRIBUTING.md#before-you-commit -->

- [ ] `gofmt -s -w .` — code is formatted
- [ ] `make lint` — formatting and complexity checks pass
- [ ] `make test` — all tests pass
- [ ] `./sesha --validate ./checks` — YAML checks are valid (if checks were changed)

## Checklist

- [ ] Single concern — one feature, one fix, or one chore
- [ ] Commits follow [conventional commits](https://www.conventionalcommits.org/en/v1.0.0/) format
- [ ] Tests added/updated for code changes (`feat` or `fix`)
- [ ] CHANGELOG.md updated (for `feat` or `fix`)
- [ ] Security boundaries respected — no changes to allowlist or path validation without justification (if applicable)
- [ ] Golden files updated via `make update-golden` (if output format changed)

## How to test

<!-- How can a reviewer verify this change works? -->

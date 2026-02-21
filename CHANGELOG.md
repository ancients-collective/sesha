# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `su_restricted` check — verify /etc/pam.d/su requires wheel/sudo group membership (CIS benchmark)

## [1.0.9] — 2026-02-13

### Added
- Build-from-source installation option on the website (git clone + go build), aligned with README

### Changed
- Bump version to 1.0.9

## [1.0.8] — 2026-02-13

### Fixed
- Replace dynamic shields.io GitHub-API badges with static badges to avoid token pool exhaustion errors

### Changed
- Bump version to 1.0.8
- Update Makefile release target to auto-update release badge on version bump

## [1.0.7] — 2026-02-13

### Fixed
- Replace LICENSE with canonical Apache 2.0 text so pkg.go.dev detects it correctly
  (prior version had 3 minor word deviations that caused `licensecheck` to report UNKNOWN)

## [1.0.6] — 2026-02-13

### Added
- CodeQL static analysis workflow (SAST) for Go
- Fuzz tests for allowlist validation, Levenshtein distance, and YAML check parsing
- SLSA build provenance attestation in release workflow

### Changed
- Pin remaining `github/codeql-action/upload-sarif` to full commit SHA in Scorecard workflow
- Restrict top-level `permissions` to `{}` in release workflow (least-privilege)
- Move `contents: write` to job-level permissions in release workflow

## [1.0.5] — 2026-02-13

### Added
- OpenSSF Scorecard workflow for supply-chain security analysis
- Dependabot configuration for Go modules and GitHub Actions
- OpenSSF Scorecard badge in README and docs site

### Changed
- Pin all GitHub Actions to full commit SHAs (Scorecard Pinned-Dependencies check)

## [1.0.4] — 2026-02-13

### Fixed
- Force alignment of VERSION file, GitHub Release, release badge, and Go Report Card

## [1.0.3] — 2026-02-13

### Added
- `VERSION` file as single source of truth for version strings
- `Makefile` with `build`, `test`, `lint`, `release`, `install`, and `update-golden` targets
- `CHANGELOG.md` (this file), back-filled for all releases
- GitHub Actions CI workflow (test, vet, gofmt on push/PR)
- GitHub Actions release workflow (auto-creates GitHub Releases from tags)
- `-ldflags` version injection at build time

### Changed
- Badge URL changed from `github/v/tag` to `github/v/release` for accurate release tracking
- Test fixtures decoupled from real version string (use `testVersion` constant)
- Golden files no longer need updating on version bumps

## [1.0.2] — 2026-02-13

### Changed
- Refactored `run()` from cyclomatic complexity 73 → 11 (extracted 10 helpers)
- Refactored `icon()` from dual switch (complexity 20) to map lookups
- Decomposed `detectVMWith()` (17) into 5 focused helpers
- Decomposed `VerifyChecksDirectory()` (16) into 3 focused helpers
- Applied `gofmt -s` project-wide
- Zero functions now exceed gocyclo threshold of 15

## [1.0.1] — 2026-02-13

### Fixed
- Path traversal gap in `readProcFileLimited` (filepath.Clean before prefix check)
- Unchecked type assertion in `GetFileOwnerIDs` (prevent panic)
- Capture `WalkDir` errors in `VerifyChecksDirectory`
- Use `defer conn.Close()` in `portListening`

### Added
- 1 MB size limit on YAML check files (prevent OOM)
- Error on non-string args in `command_output_contains`
- Output file path validation (reject writes to /etc, /proc, /sys, etc.)
- Bounded reads in `detect_linux.go`
- Reject empty args and null bytes in allowlist validator

### Changed
- Refined `IsDumbTerm`: only `TERM=dumb` is treated as dumb, not unset
- Standardized test packages to `engine_test`
- Derived `validWhenTokens` from shared constants
- Used `filepath.Join` in test helper
- Documented `Lstat`/`Stat` difference and bit-mask logic

## [1.0.0] — 2026-02-13

### Added
- Initial public release
- 13 built-in check functions
- YAML-driven declarative security checks
- Text, JSON, and JSONL output formats
- Profile-based filtering (server, workstation, container)
- Severity and tag-based filtering
- `--explain` mode with impact, break-risk, and remediation
- Risk-accepted allowlists
- Fuzzy `--id` matching with suggestions
- Checks directory integrity verification
- Linux and macOS system context detection
- GitHub Pages documentation site

# Release Process

This document describes the complete release workflow for sesha, including the
branching model, step-by-step release checklist, and hotfix procedures.

---

## Branching Model (Gitflow-lite)

```text
main              ← stable, tagged releases only
  └── develop     ← integration branch for all work
        ├── feat/...    ← feature branches
        ├── fix/...     ← bug fix branches
        └── chore/...   ← tooling, docs, CI branches
```

### Branch types

| Branch | Forks from | Merges to | Naming |
|--------|-----------|-----------|--------|
| Feature | `develop` | `develop` | `feat/short-desc` |
| Bug fix | `develop` | `develop` | `fix/short-desc` |
| Chore | `develop` | `develop` | `chore/short-desc` |
| Release | `develop` | `main` + `develop` | `release/x.y.z` |
| Hotfix | `main` | `main` + `develop` | `hotfix/short-desc` |

### Rules

- `main` always reflects the latest release — every commit on `main` is tagged
- `develop` is the integration branch — all feature/fix/chore PRs target it
- Direct pushes to `main` and `develop` are not allowed (use PRs)
- Release branches are short-lived: created when `develop` is ready, merged
  promptly after final validation

---

## Commit Convention

All commits must follow [Conventional Commits v1.0.0](https://www.conventionalcommits.org/en/v1.0.0/).
This is enforced by CI.

```text
<type>[optional scope]: <description>
```

**Types:** `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `ci`, `build`,
`perf`, `style`

**Scopes:** `engine`, `loader`, `output`, `context`, `cli`, `checks`, `release`

See [CONTRIBUTING.md](../CONTRIBUTING.md#commit-messages) for full details and
examples.

---

## Release Checklist

### 1. Ensure `develop` is ready

All features and fixes intended for this release must be merged to `develop`.
CI must be green.

```bash
git checkout develop
git pull origin develop
make test
```

### 2. Create a release branch

```bash
make release-branch VERSION=x.y.z
```

This checks out `develop`, pulls latest, and creates `release/x.y.z`.

### 3. Finalize the changelog

Add the release entry to `CHANGELOG.md` on the release branch:

```markdown
## [x.y.z] — YYYY-MM-DD

### Added
- (list new features)

### Fixed
- (list bug fixes)

### Changed
- (list other changes)
```

Commit the changelog update:

```bash
git add CHANGELOG.md
git commit -m "docs(release): add changelog entry for x.y.z"
```

### 4. Run the release

```bash
make release VERSION=x.y.z
```

The release script (`scripts/release.sh`) will:

1. Validate you're on the correct `release/x.y.z` branch
2. Check for uncommitted changes
3. Verify the tag doesn't already exist
4. Update version references in 4 files:
   - `VERSION`
   - `cmd/sesha/main.go` (`var version`)
   - `README.md` (badge)
   - `site/index.html` (badge)
5. Verify `CHANGELOG.md` has an entry for the version
6. Run `make test`
7. Commit: `chore(release): vx.y.z`
8. Merge release branch → `main` (no-ff)
9. Tag `vx.y.z` on `main`
10. Back-merge `main` → `develop`
11. Push `main`, `develop`, and the tag to `origin`
12. Delete the release branch (local + remote)

### 5. Verify the release

- GitHub Actions detects the `v*` tag and creates a GitHub Release
  with the binary and SLSA attestation
- Check the [Releases page](https://github.com/ancients-collective/sesha/releases)
  to confirm the release was created with the correct changelog extract

---

## Hotfix Process

For urgent fixes to production that can't wait for the normal release cycle:

### 1. Create a hotfix branch from `main`

```bash
git checkout main
git pull origin main
git checkout -b hotfix/short-desc
```

### 2. Make the fix

Implement the fix and add a regression test. Commit with conventional format:

```bash
git commit -m "fix(engine): prevent panic on nil context"
```

### 3. Update changelog and version

Add a changelog entry and bump the patch version:

```bash
# Edit CHANGELOG.md
git commit -m "docs(release): add changelog entry for x.y.z"
```

### 4. Merge, tag, and push

```bash
# Merge to main
git checkout main
git merge --no-ff hotfix/short-desc -m "fix(release): merge hotfix for vx.y.z"

# Update version references
# (manually update VERSION, cmd/sesha/main.go, README.md, site/index.html)
git commit -m "chore(release): vx.y.z"
git tag vx.y.z
git push origin main vx.y.z

# Back-merge to develop
git checkout develop
git merge --no-ff main -m "chore(release): back-merge vx.y.z hotfix to develop"
git push origin develop

# Cleanup
git branch -d hotfix/short-desc
```

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** (`x.0.0`): breaking changes to CLI flags, output format, or check
  behaviour that existing users depend on
- **MINOR** (`0.x.0`): new features (new checks, new functions, new CLI flags)
  that are backward-compatible
- **PATCH** (`0.0.x`): bug fixes, documentation, tooling changes

Use the corresponding Makefile target:

```bash
make release-patch    # 1.0.10 → 1.0.11
make release-minor    # 1.0.10 → 1.1.0
make release-major    # 1.0.10 → 2.0.0
```

---

## Changelog Format

Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/):

```markdown
## [x.y.z] — YYYY-MM-DD

### Added
- New features

### Changed
- Changes in existing functionality

### Fixed
- Bug fixes

### Removed
- Removed features
```

Each entry should be a short, human-readable sentence starting with a verb.
Link to relevant issues or PRs where applicable.

---

## One Concern Per Commit / Per PR

The cardinal rule: **each commit and each PR addresses exactly one concern**.

| Good | Bad |
|------|-----|
| `feat(engine): add sysctl_value function` | `add sysctl_value and fix loader bug` |
| `fix(loader): reject empty steps array` | `various fixes and improvements` |
| `chore(release): v1.0.11` | `v1.0.11: release + add new check` |
| `test(engine): add sysctl_value tests` | `update tests and docs` |

If a feature requires a prerequisite refactor, submit the refactor as a
separate PR first. This ensures each change can be reviewed, reverted, and
understood independently.

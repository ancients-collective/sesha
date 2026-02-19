#!/usr/bin/env bash
# scripts/release.sh — Repeatable release workflow for sesha.
#
# Usage:
#   ./scripts/release.sh <VERSION|patch|minor|major>
#
# Examples:
#   ./scripts/release.sh 1.0.10      # explicit version
#   ./scripts/release.sh patch        # auto-increment patch (1.0.9 → 1.0.10)
#   ./scripts/release.sh minor        # auto-increment minor (1.0.9 → 1.1.0)
#   ./scripts/release.sh major        # auto-increment major (1.0.9 → 2.0.0)
#
# This script:
#   1. Resolves the next version (explicit or auto-incremented)
#   2. Pre-flight checks (clean tree, on main branch)
#   3. Updates VERSION, cmd/sesha/main.go, README.md badge, site/index.html badge
#   4. Verifies CHANGELOG.md has an entry for the new version
#   5. Runs tests
#   6. Commits, tags, and pushes to origin
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BOLD='\033[1m'
NC='\033[0m' # No Color

info()  { echo -e "${GREEN}==>${NC} $*"; }
warn()  { echo -e "${YELLOW}==>${NC} $*"; }
error() { echo -e "${RED}==> ERROR:${NC} $*" >&2; }
die()   { error "$@"; exit 1; }

# ---------------------------------------------------------------------------
# Resolve version
# ---------------------------------------------------------------------------
CURRENT=$(cat VERSION | tr -d '[:space:]')
IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"

case "${1:-}" in
  patch)  NEW_VERSION="$MAJOR.$MINOR.$((PATCH + 1))" ;;
  minor)  NEW_VERSION="$MAJOR.$((MINOR + 1)).0" ;;
  major)  NEW_VERSION="$((MAJOR + 1)).0.0" ;;
  "")     die "Usage: $0 <VERSION|patch|minor|major>" ;;
  *)      NEW_VERSION="$1" ;;
esac

# Validate semver format
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  die "Invalid version format: '$NEW_VERSION' (expected MAJOR.MINOR.PATCH)"
fi

info "Release: v${CURRENT} → v${NEW_VERSION}"
echo ""

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
info "Pre-flight checks"

# Must be on main branch
BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [ "$BRANCH" != "main" ]; then
  die "Not on main branch (currently on '$BRANCH'). Switch to main first."
fi

# No uncommitted changes (allow staged changes for CHANGELOG edits)
if ! git diff --quiet; then
  warn "You have unstaged changes. They will be included in the release commit."
  echo ""
  git diff --stat
  echo ""
  read -p "Continue? [y/N] " -n 1 -r
  echo ""
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    die "Aborted."
  fi
fi

# Tag must not already exist
if git rev-parse "v${NEW_VERSION}" >/dev/null 2>&1; then
  die "Tag v${NEW_VERSION} already exists."
fi

echo ""

# ---------------------------------------------------------------------------
# Update version references
# ---------------------------------------------------------------------------
info "Updating version references"

echo "$NEW_VERSION" > VERSION
echo "  VERSION file"

sed -i "s/^var version = \".*\"/var version = \"${NEW_VERSION}\"/" cmd/sesha/main.go
echo "  cmd/sesha/main.go"

sed -i "s|release-v[0-9]*\.[0-9]*\.[0-9]*-|release-v${NEW_VERSION}-|g" README.md
echo "  README.md badge"

sed -i "s|release-v[0-9]*\.[0-9]*\.[0-9]*-|release-v${NEW_VERSION}-|g" site/index.html
echo "  site/index.html badge"

echo ""

# ---------------------------------------------------------------------------
# Verify CHANGELOG
# ---------------------------------------------------------------------------
info "Checking CHANGELOG.md"

if grep -q "## \[${NEW_VERSION}\]" CHANGELOG.md; then
  echo "  Found entry for [${NEW_VERSION}] ✓"
else
  warn "No CHANGELOG.md entry found for [${NEW_VERSION}]."
  echo ""
  echo "  Add an entry under this header before releasing:"
  echo ""
  echo "  ## [${NEW_VERSION}] — $(date +%Y-%m-%d)"
  echo ""
  echo "  ### Added"
  echo "  - (describe what was added)"
  echo ""
  echo "  ### Changed"
  echo "  - Bump version to ${NEW_VERSION}"
  echo ""
  die "Update CHANGELOG.md and re-run."
fi

echo ""

# ---------------------------------------------------------------------------
# Run tests
# ---------------------------------------------------------------------------
info "Running tests"
make test
echo ""

# ---------------------------------------------------------------------------
# Commit, tag, push
# ---------------------------------------------------------------------------
info "Committing and tagging"

git add -A
git commit -m "v${NEW_VERSION}: release"
git tag "v${NEW_VERSION}"

echo ""
info "Pushing to origin"

git push origin main
git push origin "v${NEW_VERSION}"

echo ""
echo -e "${BOLD}${GREEN}✓ v${NEW_VERSION} released successfully.${NC}"
echo "  GitHub Actions will create the Release from the tag."
echo ""

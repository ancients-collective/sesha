.PHONY: build test lint install release release-patch release-minor release-major clean

# Read version from VERSION file
VERSION := $(shell cat VERSION | tr -d '[:space:]')
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
BINARY  := sesha

## build: Compile the binary with version injection
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/sesha

## test: Run all tests and vet
test:
	go test ./... -count=1
	go vet ./...

## lint: Check formatting and cyclomatic complexity
lint:
	@echo "==> gofmt"
	@diff=$$(find . -name '*.go' | xargs gofmt -s -d); \
	if [ -n "$$diff" ]; then echo "$$diff"; exit 1; fi
	@echo "==> gocyclo (threshold 15)"
	@if command -v gocyclo >/dev/null 2>&1; then \
		gocyclo -over 15 .; \
	else \
		echo "gocyclo not installed — skipping (go install github.com/fzipp/gocyclo/cmd/gocyclo@latest)"; \
	fi

## install: Build and install to GOPATH/bin
install:
	go install $(LDFLAGS) ./cmd/sesha

## release: Bump version, update all version references, commit, tag, and push
##   Usage: make release VERSION=1.0.10
release:
	@if [ -z "$(VERSION)" ]; then echo "Usage: make release VERSION=x.y.z"; exit 1; fi
	@./scripts/release.sh "$(VERSION)"

## release-patch: Auto-increment patch version (e.g. 1.0.9 → 1.0.10)
release-patch:
	@./scripts/release.sh patch

## release-minor: Auto-increment minor version (e.g. 1.0.9 → 1.1.0)
release-minor:
	@./scripts/release.sh minor

## release-major: Auto-increment major version (e.g. 1.0.9 → 2.0.0)
release-major:
	@./scripts/release.sh major

## update-golden: Regenerate golden test files
update-golden:
	UPDATE_GOLDEN=1 go test ./internal/output/... -run TestJSON -count=1
	UPDATE_GOLDEN=1 go test ./internal/output/... -run TestJSONL -count=1

## clean: Remove build artifacts
clean:
	rm -f $(BINARY)

## help: Show this help
help:
	@grep -E '^##' Makefile | sed 's/## //'

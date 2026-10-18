# Standardized repository entrypoint for pwd-manager
set shell := ["sh", "-cu"]

default:
    @just --list

# Bootstrap dependencies and pre-commit hooks
setup:
    go mod download
    command -v lefthook >/dev/null 2>&1 && lefthook install || true

# Start local development mode
dev:
    go test ./...

# Run the automated test suite with race detector
test:
    go test -race ./...

# Run a single named Go test
test-one name:
    go test ./... -run "{{name}}" -v

# Run formatting, static analysis, and tests
check:
    test -z "$(gofmt -l .)"
    go vet ./...
    go test -race ./...

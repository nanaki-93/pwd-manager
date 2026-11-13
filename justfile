# Standardized repository entrypoint for pwd-manager
set shell := ["sh", "-cu"]

install_dir := env_var_or_default("INSTALL_DIR", env_var("HOME") / "DEV/programs/pwd-manager")

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

# Build pwd-manager and replace the installed binary (override dir with INSTALL_DIR)
install:
    mkdir -p "{{install_dir}}"
    go build -o "{{install_dir}}/.pwd-manager.tmp" .
    mv -f "{{install_dir}}/.pwd-manager.tmp" "{{install_dir}}/pwd-manager"

# pwd-manager Agent Contract

Keep this contract under 150 lines so human developers and coding agents share identical operational rules.

## 1. Quick Commands & Single-Test Execution

- Bootstrap & entrypoints (`justfile`): `just setup`, `just dev`, `just test`, `just check`.
- Run a single test: `just test-one TestName`.
- Always run `just check` before committing changes.

## 2. Architecture Boundaries

- Entrypoints and HTTP/UI handlers must never import database or storage packages directly; always go through service interfaces.
- Domain and indexing packages must remain pure and never import transport or presentation layers.
- Keep diffs surgical and scoped to the requested change, its callers, and its regression tests.

## 3. Error Handling & Concurrency Conventions

- Handle all errors explicitly with actionable context (e.g., `fmt.Errorf("action: %w", err)`). Never swallow errors or silently return fallback values.
- Propagate cancellation (`context.Context` / `AbortSignal`) across all I/O, child processes, and model calls.
- Guard shared state with explicit synchronization and ensure no background workers leak after a task or test finishes.


## Architecture boundaries & ownership

- `internal/api/` must never import `internal/storage/`.


- Max function complexity: 15
- Max function lines: 80
- Max file lines: 800


## Project overview and architecture

- Trace the entry point, owning package and callers before changing Go behavior. Keep transport, business rules and persistence in their existing packages; introduce interfaces at real consumer boundaries rather than for hypothetical reuse.
- Keep command names, flags, defaults and exit codes compatible unless the requested change explicitly alters them. Keep help text synchronized with behavior, validate arguments before side effects and define how non-interactive use behaves.
- Read the root AGENTS.md and applicable directory guides before editing. Keep local rules within their directory scope, resolve conflicts using the more specific applicable guide, and follow the user's explicit task instructions. Guidance does not grant permission for unrelated actions.


## Build and development

- Use the repository's documented setup, runtime versions and maintained build and test entry points. Run commands from their documented directory and report missing prerequisites clearly; do not invent commands or modify toolchain requirements merely to make a local check pass.


## Code style and conventions

- Format changed Go code with gofmt. Preserve wrapped errors and context cancellation; use deterministic tests for changed behavior and error paths. Run the project's documented Go checks and report their results.
- Return errors with useful operation context and preserve errors.Is/errors.As behavior when wrapping. Handle cleanup failures deliberately. Do not replace a failed operation with a zero value or log the same error at every layer.
- Give each goroutine an owner and a bounded lifetime. Pass context through blocking operations, avoid holding locks during network or subprocess work, and use deterministic synchronization in tests for cancellation and concurrent state changes.
- Keep machine-readable output on its documented stream and send progress or diagnostics to the appropriate separate stream. Preserve structured output formats, handle interrupted input and broken pipes deliberately, and avoid unsolicited prompts in non-interactive execution.
- Read nearby implementations before editing. Reuse existing patterns and avoid unnecessary dependencies.


## Testing and validation

- Exercise exported behavior with temporary directories and fake dependencies. Cover wrapped errors, cancellation and boundary inputs. Run focused package tests, then the owning module's documented tests and vet; use race detection for changes to shared state or background work.
- Cover changed behavior and meaningful error paths with deterministic tests. Report checks actually run.


## Security and data

- Keep credentials and source-bearing diagnostics out of logs and Git. Validate external input at its boundary.


## Documentation

- Update the existing documentation owner when behavior changes. Verify referenced paths and commands, distinguish current behavior from plans and keep examples consistent with the implementation.


## Review and handoff

- Keep changes limited to the requested behavior. Preserve unrelated work and public contracts.
- Prepare a diff and explain behavior and verification before explicitly approved source changes.

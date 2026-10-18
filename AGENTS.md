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

- Max function complexity: 15
- Max function lines: 80
- Max file lines: 800

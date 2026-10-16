# Project instructions

## Project overview and architecture

- Trace the entry point, owning package and callers before changing Go behavior. Keep transport, business rules and persistence in their existing packages; introduce interfaces at real consumer boundaries rather than for hypothetical reuse.
- Read the root AGENTS.md and applicable directory guides before editing. Keep local rules within their directory scope, resolve conflicts using the more specific applicable guide, and follow the user's explicit task instructions. Guidance does not grant permission for unrelated actions.
- Read the project overview and nearby implementations, then trace the affected entry point, state owner, callers and tests. Put the change in the layer that owns the behavior and preserve established module boundaries instead of duplicating domain rules in adapters.

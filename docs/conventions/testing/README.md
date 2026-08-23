# Conventions — testing
[INTENT: KONTEXT]

This area carries the testing conventions of the Go territory home: how tests
are constructed, proven, and kept portable across the fleet's supported
operating systems.

## Conventions

- `portable-test-construction.md` — every test and code path is constructed
  operating-system-agnostic; error branches are forced portably, never through
  a platform-specific input.

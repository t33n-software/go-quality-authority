# Testing — portable test construction
[INTENT: CONSTRAINT]

## Canonical source

This file is the canonical source of truth for the convention that every test
and every code path in the Go territory is constructed to be
operating-system-agnostic. A test or code path that relies on one platform's
semantics is a defect class, not a platform gap. The convention governs how
error branches, path handling, and platform-dependent behavior are forced and
asserted so that the proof holds on every supported operating system.

## The rule

A test or code path MUST NOT depend on a single platform's semantics to reach
or assert a branch. Platform-specific path forms (drive letters, separators),
line-ending assumptions, shell availability, and filesystem permission
semantics are never a valid basis for forcing or asserting behavior.

An error branch is forced portably or not at all: the forcing input MUST
produce the branch on every supported operating system. A value that is
absolute on one platform but not on another is a forbidden forcing input.

## The bound pattern: force error branches through runtime-derived inputs

When a test must force `filepath.Rel` (or any path-relation primitive) into
its error branch, the base MUST be absolute on every platform. Derive it from
the runtime — for example `t.TempDir()` — never from a hardcoded
platform-specific form.

## Why this is the foundation

- The fleet verifies on multiple operating systems; a local single-platform
  pass is not evidence of portability.
- A non-portable test passes on the development platform and fails only on
  another platform's lane, where it blocks a governed delivery fail-closed.
- Proven instance: `TestRelPathFallsBackOnError` forced the `filepath.Rel`
  error branch with the Windows drive-letter base `C:\gqa-root`. On Windows
  the base is absolute and the branch is taken; on Linux the same string is
  not absolute, the relation succeeds, and the assertion fails. The defect
  surfaced only in the Linux release-delivery lane and made the immutable
  `v1.0.0` tag undeliverable (GQA-10).

## Verification

The multi-operating-system lanes are the authority: a change that touches path
handling, error-branch forcing, line endings, shell execution, or filesystem
permissions is only proven portable when it passes on every targeted operating
system. A deviation is a fail-closed defect.

## Do / Don't

- Do derive absolute bases and platform behavior from the runtime
  (`t.TempDir()`, explicit `runtime.GOOS` seams, and the correct
  `filepath`/`path` choice).
- Don't hardcode a platform-specific path form, line ending, shell, or
  permission semantic to force or assert a branch.

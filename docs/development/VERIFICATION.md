# Verification

This document is the verification contract of the `go-quality-authority` home.
Every gate is fail-closed: a missing or failing check is never a pass.

## The canonical gate set

The quality lane is the `quality-gate` orchestrator. It reads the
schema-validated `git-governance.quality.json`, asserts the controlled
toolchain, executes the canonical gate set, and applies convention discovery.
The same invocation runs identically locally, in the Lefthook pre-push lane,
and in CI.

```bash
go run -mod=readonly ./cmd/quality-gate
```

The canonical gate set, in order:

1. **Controlled toolchain** — the running `go env GOVERSION` must equal the
   pinned `toolchain.goVersion` of the configuration seam.
2. **Module verification** — `go mod download`, `go mod verify`,
   `go mod tidy -diff` for the module and, when present, the `tools` module.
   The orchestrator never mutates `go.mod` or `go.sum`; the module graph is a
   versioned build input.
3. **Formatting** — `gofmt -l` over every Go source file must be empty.
4. **Lint** — `staticcheck ./...` via the pinned tool.
5. **Typecheck** — `go test -mod=readonly -run=^$ ./...`.
6. **Unit, contract, and integration tests** — `go test -mod=readonly ./...`.
7. **Race detector** — `go test -mod=readonly -race ./...`.
8. **Static analysis** — `go vet ./...`.
9. **Vulnerability analysis** — `govulncheck ./...` via the pinned tool;
   fail-closed.
10. **Boundary fuzzing** — every discovered or configured fuzz target runs
    with its execution budget (`-fuzztime`).
11. **Lefthook configuration** — `lefthook validate` via the pinned tool.
12. **Command binaries** — every `./cmd/*` binary is built with
    `-mod=readonly -trimpath` and smoke-tested.
13. **Coverage gate** — `check-coverage` runs in-process and enforces
    test-source presence plus exact 100.0-percent statement coverage for every
    executable Go package.

## Coverage gate

`check-coverage` owns the measurement and the threshold, never the project's
test layout:

```bash
go run -mod=readonly ./cmd/check-coverage
```

Every Go package must contain at least one `_test.go` file, and every
executable Go package must reach exactly 100.0 percent statement coverage.

## Configuration seam

The configuration seam is proven by the conformance vectors:
`conformance/positive/` documents decode successfully and
`conformance/negative/` are each rejected with a precise field error. The
contract test in `internal/packaging` binds the schema, the vectors, and the
tool catalog to the quality core.

## Whitebox testing

Every production path carries a direct same-package whitebox test for its
invariants, branches, state transitions, errors, and cleanup paths. The
configuration decoder carries the boundary fuzz lane (`FuzzDecodeConfig`).

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
   pinned `toolchain.version` of the configuration seam, and the seam's
   `toolchain.language` must be `go`; a declared capability pack (`extends`)
   is resolved against the pack registry union and fails closed when the
   reference is unknown.
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
seam definition (`quality-gate-config/v4`) is owned by the
supply-chain-governance shared kernel and referenced by identity; the
contract test in `internal/packaging` binds the canonical identity, the
vectors, and the tool catalog to the quality core.

## Self-pin currency

The tools module pins this home's own module so the lane-build proof exercises
the same pinned channel the tenants consume. The pin is a release-gate input:
the lifecycle publish lane invokes the pinned `quality-gate` against this
repository's configuration seam. Two fail-closed invariants keep the pin
current, proven by `TestSelfPinTracksTheMergedLineDecoder`:

1. The pin binds a commit on the merged develop line — never a
   pull-request-only commit.
2. The pin never predates the newest change to the configuration decoder
   surface (`internal/quality/config.go`) on that line.

A decoder change merges first and the repin follows on the merged line; every
pull request in between fails the guard.

## Capability pack machinery

The orchestrator owns the pack machinery (the pack model is owned by the
capability-pack contract in the shared kernel). Every surface is fail-closed
and covered by same-package whitebox tests:

1. **Descriptor decoding** — `internal/quality/pack.go` strictly decodes the
   `capability-pack/v1` descriptor (unknown fields, trailing documents,
   credential-like content, and every invariant violation are rejected with a
   precise field error); the boundary fuzz lane is `FuzzDecodePackDescriptor`.
2. **Registry resolution** — `internal/quality/packengine.go` resolves every
   `extends` reference against the union of the territory registry (this
   home's `capabilities/`) and the shared-kernel registry at the tenant's
   pinned tool stand. The registry modules are resolved through the tenant's
   integrity-pinned tooling channel (`tools/go.mod` + `tools/go.sum`), and the
   resolution never trusts a warm module cache: it downloads the module before
   querying its directory, so it runs identically on a cold CI runner. A home
   resolves its own registry from the working tree. The resolution has exactly
   three outcomes: declared and known is provisioned and executed, declared
   but unknown fails closed (naming the searched and unavailable registries),
   and not declared is skipped. A descriptor whose identity does not match its
   registry location, and a reference carried by more than one registry, fail
   closed.
3. **Provisioning** — the `provision` mode (`internal/quality/provision.go`)
   executes each declared pack's recipe: it downloads the bound artifact for
   the runner platform over HTTPS with a byte bound, verifies the bound
   `sha256` digest fail-closed, verifies the cosign signature where the
   descriptor binds one (the certificate is the cosign keyless `.sig`/`.pem`
   pair, and the certificate identity is the publisher's OIDC-bound
   release-workflow identity bound by the engine reference), and installs the
   tool into the pack tool cache with a bounded decompression read. The
   extraction never derives an output location from the archive, and only the
   regular file carrying the tool is extracted. A pack whose tool is not
   provisioned fails the gate closed with the remediation
   `quality-gate provision`.
4. **Composition** — the plan composes deterministically: the core gates,
   then the pack gates, then the project gates. A pack's assertions run before
   any of its gates, a repository gate runs once at the root, and a per-root
   gate runs once per discovered root (the parent directories of the
   discovery glob's matches, minus the excluded directory names). Every pack
   command references the provisioned tool, and the pack's enforced
   environment reaches the gate processes.

## Whitebox testing

Every production path carries a direct same-package whitebox test for its
invariants, branches, state transitions, errors, and cleanup paths. The
configuration decoder carries the boundary fuzz lane (`FuzzDecodeConfig`).

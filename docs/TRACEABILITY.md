# Product Acceptance Matrix

This matrix is the repository-local source of truth for delivery status. It
does not rely on any external governance repository or unpublished rule set.

## Status legend

- `IMPLEMENTED`: source code exists.
- `VERIFIED`: automated tests or an actual local execution succeeded.
- `IN_PROGRESS`: a confirmed gap is actively being remediated.
- `PENDING`: intentionally planned but not yet delivered.
- `BLOCKED`: cannot be verified because an external prerequisite is absent.

## Verified baseline

| Item | Status | Evidence |
|---|---|---|
| Local repository | VERIFIED | `main` is initialized; every audit and release gate begins by checking the current Git status |
| Go module | VERIFIED | `github.com/t33n-software/go-quality-authority`, language Go 1.26 and pinned toolchain Go 1.26.6 |

## Core capabilities

| Capability | Status | Verification |
|---|---|---|
| Quality-gate orchestrator | VERIFIED | `cmd/quality-gate` reads the schema-validated config seam, asserts the controlled toolchain, runs the canonical gate set, and applies convention discovery; same-package whitebox tests |
| Coverage gate | VERIFIED | `cmd/check-coverage` enforces test-source presence and exact 100.0-percent statement coverage; same-package whitebox tests |
| Configuration seam schema | VERIFIED | the seam definition (`quality-gate-config/v4`) is owned by the supply-chain-governance shared kernel and referenced by identity (`quality.SchemaID`); the v4 decoder strictly decodes the language-keyed toolchain and the `extends` declaration; conformance vectors prove every acceptance and rejection |
| Tool catalog | VERIFIED | `catalog/tools.json` carries the canonical admitted Go tools; contract test |
| Convention discovery | VERIFIED | every `./cmd/*` binary and convention-placed fuzz target is discovered without configuration; same-package whitebox tests |
| Boundary fuzzing | VERIFIED | `FuzzDecodeConfig` fuzzes the configuration decoder |
| Dogfooding | VERIFIED | `go run -mod=readonly ./cmd/quality-gate` runs the canonical gate set against this repository |
| Release lifecycle adoption | VERIFIED | the seven callers under `.github/workflows/` are byte-identical to the canonical masters of `t33n-software/git-governance` and hash-match `caller-hashes.json` (LF-normalized) |
| Governance CLI tool channel | VERIFIED | `tools/go.mod` pins `github.com/t33n-software/git-governance/cmd/git-governance` plus the self-pinned `quality-gate` and `check-coverage`; `go build -modfile tools/go.mod` proves the lane build |

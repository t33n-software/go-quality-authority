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
| License instance | VERIFIED | the tenant values `license.values.json` and the digest-pinned lock `license.lock.json` (template `license-hub/templates/custom/norepublish/NoRepublish-1.0.0.hbs`, version 1.0.0) render `LICENSE` and `LICENSES/LicenseRef-go-quality-authority-NoRepublish-1.0.txt`; the committed instance is proven byte-identical against the canonical render through the license-hub CLI (`verify` reports the instance matches the canonical render) |
| Code ownership contract | VERIFIED | `.github/CODEOWNERS` binds the default owner `@CyberT33N`; the materialization is byte-identical to the governed reference instance (SHA-256 proven) |

## Core capabilities

| Capability | Status | Verification |
|---|---|---|
| Quality-gate orchestrator | VERIFIED | `cmd/quality-gate` reads the schema-validated config seam, asserts the controlled toolchain, runs the canonical gate set, and applies convention discovery; the format gate is a fail-closed proof — the controlled toolchain's `gofmt -l` is evaluated through the output-capture seam and every listed file is a finding (the regression guard proves a drifted source fails the gate); the YAML wellformedness gate parses every convention-discovered `.yml`/`.yaml` document fail-closed with the admitted fleet-standard YAML library (the main module's single admitted dependency) — a malformed document fails with its parse error, and a repository without YAML documents is vacuously green; same-package whitebox tests |
| Coverage gate | VERIFIED | `cmd/check-coverage` enforces test-source presence and exact 100.0-percent statement coverage; same-package whitebox tests |
| Configuration seam schema | VERIFIED | the seam definition (`quality-gate-config/v4`) is owned by the supply-chain-governance shared kernel and referenced by identity (`quality.SchemaID`); the v4 decoder strictly decodes the language-keyed toolchain and the `extends` declaration; conformance vectors prove every acceptance and rejection |
| Tool catalog | VERIFIED | `catalog/tools.json` carries the canonical admitted Go tools, and its schema document `catalog/tools.schema.json` carries the exact canonical `$id` with the strict format description; the contract tests prove the catalog's conformity against the document fail-closed |
| Convention discovery | VERIFIED | every `./cmd/*` binary and convention-placed fuzz target is discovered without configuration; same-package whitebox tests |
| Boundary fuzzing | VERIFIED | `FuzzDecodeConfig` fuzzes the configuration decoder |
| Dogfooding | VERIFIED | `go run -mod=readonly ./cmd/quality-gate` runs the canonical gate set against this repository |
| Release lifecycle adoption | VERIFIED | the seven callers under `.github/workflows/` are byte-identical to the canonical masters of `t33n-software/git-governance` and hash-match `caller-hashes.json` (LF-normalized) |
| Governance CLI tool channel | VERIFIED | `tools/go.mod` pins `github.com/t33n-software/git-governance/cmd/git-governance` plus the self-pinned `quality-gate` and `check-coverage`; `go build -modfile tools/go.mod` proves the lane build |
|| Capability pack descriptor decoding | VERIFIED | `internal/quality/pack.go` strictly decodes the `capability-pack/v1` descriptor with the mirrored credential boundary; same-package whitebox tests prove every acceptance and rejection; the boundary fuzz lane is `FuzzDecodePackDescriptor` |
|| Capability pack registry resolution | VERIFIED | `internal/quality/packengine.go` resolves every `extends` reference against the territory and shared-kernel registry union through the tenant's integrity-pinned tooling channel (never trusting a warm cache), with the three-state outcome (known, unknown fail-closed, undeclared skipped), the identity cross-check, and the ambiguity finding; same-package whitebox tests |
|| Capability pack provisioning | VERIFIED | the `provision` mode (`internal/quality/provision.go`) executes the recipe: bounded HTTPS download, fail-closed sha256 proof, the cosign signature proof against the publisher's OIDC-bound release-workflow identity, and the bounded, traversal-safe tool-cache install; same-package whitebox tests with fake seams |
| Signature verifier bootstrap | VERIFIED | the engine binds the cosign verifier identity (the shared kernel's `security` area) as machinery configuration, resolves and provisions it digest-only before any signature-bound pack — the single documented exception — and runs its assertions as the install proof inside provisioning; the signature proof executes the provisioned verifier binary, never a lane PATH lookup; the raw-binary artifact form installs directly; a tenant declaration of the verifier and any second digest-only identity fail closed; same-package whitebox tests |
|| Capability pack gate composition | VERIFIED | the plan composes core gates, then pack gates, then project gates; a pack's assertions precede its gates, and a per-root gate expands over the discovered roots; same-package whitebox tests |
|| Provision mode | VERIFIED | `quality-gate provision` resolves and provisions the declared packs; same-package whitebox tests of the CLI wiring |

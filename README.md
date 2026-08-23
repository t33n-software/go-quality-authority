# go-quality-authority

`go-quality-authority` is the canonical Go territory home for the shared
quality tooling of the fleet. It owns the producer side of the quality
contract: the `quality-gate` orchestrator, the `check-coverage` 100-percent
statement-coverage gate, the canonical `git-governance.quality.json`
configuration schema, and the canonical Go tool catalog.

## Artifacts

| Artifact | Path | Role |
|---|---|---|
| Quality-gate orchestrator | `cmd/quality-gate/` | Reads the schema-validated config seam, asserts the controlled toolchain, executes the canonical gate set, and discovers command binaries and fuzz targets by convention |
| Coverage gate | `cmd/check-coverage/` | Enforces test-source presence and exact 100-percent statement coverage for every executable Go package |
| Config schema | `schemas/quality-gate-config/v1/quality-gate-config.schema.json` | The versioned, strictly decoded, named-owner configuration seam (schema version 3) |
| Tool catalog | `catalog/tools.json` | The canonical set of admitted Go tools consumed as `tool` directives |
| Conformance vectors | `conformance/{positive,negative}/` | The proof set for the configuration seam: every acceptance and every rejection |

## Consumption

Consumer repositories pin these tools as an exact, versioned dependency of
their tooling module (`tools/go.mod`, Go `tool` directive) and invoke them
identically locally, in hooks, and in CI:

```bash
go tool -modfile tools/go.mod quality-gate
go tool -modfile tools/go.mod check-coverage
```

Admitting or bumping a tool is the controlled update lane — one atomic,
reviewable change with admission evidence:

```bash
go get -tool github.com/t33n-software/go-quality-authority/cmd/quality-gate@v1.0.0
```

## The configuration seam

`git-governance.quality.json` is the typed seam between the fleet and the
tenant. The schema is versioned (`v<major>`), owned by this home, strictly
decoded, and proven by the conformance vectors. The canonical gate set is
fleet-identical; the `project` block is data and shrinks to named exceptions,
because the orchestrator discovers `./cmd/*` binaries and convention-placed
fuzz targets without configuration.

```json
{
  "schemaVersion": 3,
  "toolchain": { "goVersion": "1.26.6" },
  "defaults": { "includeFamilies": ["feature", "fix", "docs", "refactor", "chore", "test", "perf", "hotfix"] },
  "gates": [
    {
      "name": "full-local-build",
      "command": "go",
      "args": ["tool", "-modfile", "tools/go.mod", "quality-gate"],
      "timeout": "15m"
    }
  ],
  "project": {
    "binaries": [{ "package": "./cmd/<tenant-binary>", "smoke": ["--version"] }],
    "fuzz": [{ "package": "./internal/<boundary>", "target": "Fuzz<Name>", "time": "50000x" }]
  }
}
```

## Verification

The home verifies itself (dogfooding): `go run -mod=readonly ./cmd/quality-gate`
runs the canonical gate set against this repository — formatting, module and
tool verification, lint, typecheck, unit and contract tests, the race detector,
static analysis, vulnerability analysis, the boundary fuzz lane, the Lefthook
configuration validation, and the build-and-smoke of every command binary —
followed by the in-process 100-percent coverage gate. See
`docs/development/VERIFICATION.md` for the full contract.

## Release lifecycle

This home adopts the centralized release and hotfix lifecycle family owned by
`t33n-software/git-governance` as byte-identical, hash-pinned callers under
`.github/workflows/` — never by copy. The family contract lives at
`workflows/github/CONTRACT.md` in that home; the caller pins and hashes are
bound in `workflows/github/callers/release-lifecycle/caller-hashes.json`.

The bound delivery variant is `github-only` (repository variable
`GIT_GOVERNANCE_DELIVERY_VARIANT`): a signed immutable tag plus a GitHub
release with a provenance-attested source manifest. The broker-bound hotfix
lanes fail closed in this variant until their evidence path is migrated (the
named deferral of the family contract). The lanes build the governance CLI
from the pinned class-D tool in `tools/go.mod` — never from a source checkout.

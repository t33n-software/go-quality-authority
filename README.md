# go-quality-authority

`go-quality-authority` is the canonical Go territory home for the shared
quality tooling of the fleet: the quality-gate orchestrator
(`cmd/quality-gate`), the statement-coverage gate (`cmd/check-coverage`),
the canonical quality-gate configuration schema, and the canonical Go tool
catalog.

## Consumption

Consumer repositories pin these tools as an exact, versioned dependency of
their tooling module (`tools/go.mod`, Go `tool` directive) and invoke them
identically locally, in hooks, and in CI:

```bash
go tool -modfile tools/go.mod quality-gate
go tool -modfile tools/go.mod check-coverage
```

## Status

This repository is being established; the initial content lands through the
governed ticket workflow.

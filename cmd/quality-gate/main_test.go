package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/t33n-software/go-quality-authority/internal/quality"
)

func writeConfig(t *testing.T, dir string) {
	t.Helper()
	contents := `{
  "schemaVersion": 3,
  "toolchain": { "goVersion": "1.26.6" },
  "gates": [{"name":"full-local-build","command":"go","args":["version"]}]
}`
	if err := os.WriteFile(filepath.Join(dir, configFileName), []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRunVersion(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run --version = %d", code)
	}
	if !strings.Contains(stdout.String(), "quality-gate") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestRunUsageError(t *testing.T) {
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--bogus"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run --bogus = %d, want 2", code)
	}
}

func TestRunMissingConfig(t *testing.T) {
	var stdout, stderr strings.Builder
	code := run(context.Background(), []string{"--repo=" + t.TempDir()}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run without config = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "read quality configuration") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunInvalidConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, configFileName), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr strings.Builder
	code := run(context.Background(), []string{"--repo=" + dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run with invalid config = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "decode quality configuration") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunGateError(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir)
	defer func() { runGate = runQualityGate }()
	runGate = func(context.Context, quality.Config, string, io.Writer, io.Writer) error {
		return errors.New("boom")
	}
	var stdout, stderr strings.Builder
	code := run(context.Background(), []string{"--repo=" + dir}, &stdout, &stderr)
	if code != 1 {
		t.Fatalf("run with gate error = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "quality gate") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunSuccess(t *testing.T) {
	dir := t.TempDir()
	writeConfig(t, dir)
	defer func() { runGate = runQualityGate }()
	runGate = func(_ context.Context, _ quality.Config, root string, _, _ io.Writer) error {
		if root != dir {
			t.Fatalf("root = %q", root)
		}
		return nil
	}
	var stdout, stderr strings.Builder
	if code := run(context.Background(), []string{"--repo=" + dir}, &stdout, &stderr); code != 0 {
		t.Fatalf("run = %d, want 0", code)
	}
}

func TestRunQualityGateDelegation(t *testing.T) {
	// The delegation constructs the production orchestrator; an empty root fails
	// fast inside the plan, which exercises the seam without running real gates.
	if err := runQualityGate(context.Background(), testConfigForMain(), " ", io.Discard, io.Discard); err == nil {
		t.Fatal("expected the delegation to surface the plan error")
	}
}

func testConfigForMain() quality.Config {
	return quality.Config{
		SchemaVersion: quality.SchemaVersion,
		Toolchain:     quality.Toolchain{GoVersion: "1.26.6"},
		Gates:         []quality.Gate{{Name: "full-local-build", Command: "go"}},
	}
}

func TestMain(t *testing.T) {
	defer func() { exitProcess = os.Exit }()
	defer func() { commandArgs = os.Args }()
	var code int
	exitProcess = func(c int) { code = c }
	commandArgs = []string{"quality-gate", "--version"}
	main()
	if code != 0 {
		t.Fatalf("main exit = %d", code)
	}
}
